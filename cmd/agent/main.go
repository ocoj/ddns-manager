// node-agent — heartbeat agent for ddns-manager
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ocoj/ddns-manager/internal/crypto"
	"github.com/ocoj/ddns-manager/internal/model"
	"golang.org/x/text/encoding/simplifiedchinese"
	"gopkg.in/yaml.v3"
)

// v1.5.34 C1: 降级拒绝 sentinel error，与升级成功/失败区分
var errDowngradeBlocked = fmt.Errorf("downgrade blocked")
// v1.6.29 M5: 认证失败 sentinel, 心跳重试循环遇此错误跳过重试
var errAuthFailed = fmt.Errorf("auth failed")

// version is set at build time via -ldflags "-X main.version=x.y.z"
var version = "dev"
var lastConfigHash string

// configHashPath 返回配置 hash 持久化文件路径 (与 ddns_cache.yaml 并列)
// v1.6.36 C4: oneshot 模式下进程退出后 lastConfigHash 丢失,
// 持久化到此文件确保跨进程不重复推送配置
func configHashPath() string {
	return filepath.Join(agentBaseDir, "ddns_config_hash.txt")
}
var certHashMap = map[string]string{}
var certHashMapMu sync.Mutex // H6: protects certHashMap from concurrent access

// certHashMapRead v1.6.30 H1: 返回 certHashMap 的只读快照, 用于跟进心跳
func certHashMapRead() map[string]string {
	certHashMapMu.Lock()
	defer certHashMapMu.Unlock()
	out := make(map[string]string, len(certHashMap))
	for k, v := range certHashMap {
		out[k] = v
	}
	return out
}

// dnsUpdater is the global DNS updater instance (initialized once via sync.Once)
var (
	dnsUpdater       *DNSUpdater
	dnsUpdaterOnce   sync.Once
	dnsUpdateRunning atomic.Bool // v1.5.22 C4: 防止配置变更时 goroutine 堆积 (Load/Store 在 doHeartbeat)
)
var heartbeatFailed atomic.Bool // v1.5.22 H2: 标记心跳失败, 阻止 agentLogBuf.Clear() 丢弃操作日志
var agentLogBuf = newLogBuffer(100)
// v1.5.30 H2: 证书部署错误缓存, 下一心跳通过 Status.CertErrors 上报 Manager
var (
	lastCertErrors   []string
	lastCertErrorsMu sync.Mutex
)
// v1.5.34 H3: Agent 操作日志文件持久化 (10MB 轮转, 保留 3 个), 防止 crash 丢失
// v1.6.10 L1: 读写分离 — os.File.Write 是线程安全的, 锁仅保护文件句柄的获取/替换
var (
	agentEventsFile   *os.File
	agentEventsFileMu sync.Mutex
)
func agentLog(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	agentLogBuf.Write(msg)
	// v1.6.10 L1: 不加锁写文件 (os.File.Write 线程安全), 只持锁读文件句柄
	agentEventsFileMu.Lock()
	f := agentEventsFile
	agentEventsFileMu.Unlock()
	if f != nil {
		// v1.6.39: 使用显式 UTC 标记替代 RFC3339 Z, 更直观
		// v1.6.36 H1: 检查写入错误, 防止磁盘满/权限变更导致操作日志静默丢失
		n, writeErr := fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"), msg)
		if writeErr != nil {
			log.Printf("[agent] 操作日志写入失败: %v (wrote %d bytes)", writeErr, n)
		}
	}
}

// initAgentEventsLog 打开 Agent 操作事件日志文件 (agent_events.log), 10MB 轮转。
// v1.5.34 H3: 与 agent.log 平行, 独立于 go log 框架, 提供 crash-safe 的操作日志持久化。
func initAgentEventsLog() {
	path := filepath.Join(agentBaseDir, "agent_events.log")
	perm := os.FileMode(0600)
	if runtime.GOOS == "windows" {
		perm = 0644
	}
	// 轮转: >10MB 时重命名为 agent_events.N.log (保留 3 个)
	if fi, err := os.Stat(path); err == nil && fi.Size() > 10<<20 {
		for i := 3; i >= 1; i-- {
			old := filepath.Join(agentBaseDir, fmt.Sprintf("agent_events.%d.log", i))
			if i < 3 {
				next := filepath.Join(agentBaseDir, fmt.Sprintf("agent_events.%d.log", i+1))
				// v1.6.58: 检查 Rename 错误, 防止轮转失败静默
				if err := os.Rename(old, next); err != nil {
					log.Printf("[agent] 事件日志轮转 Rename 失败: %s→%s (%v)", old, next, err)
				}
			} else {
				// v1.6.42 L1: 检查删除错误, 防止轮转失败静默
				if err := os.Remove(old); err != nil && !os.IsNotExist(err) {
					log.Printf("[agent] 事件日志轮转删除失败: %s (%v)", old, err)
				}
			}
		}
		// v1.6.45 M2: 检查 Rename 错误, 防止轮转失败静默 (权限/磁盘问题导致文件持续增长)
		if err := os.Rename(path, filepath.Join(agentBaseDir, "agent_events.1.log")); err != nil {
			log.Printf("[agent] 事件日志轮转 Rename 失败: %s (%v)", path, err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, perm)
	if err != nil {
		return
	}
	agentEventsFileMu.Lock()
	agentEventsFile = f
	agentEventsFileMu.Unlock()
	log.Printf("[agent] 操作事件日志: %s", path)
}

// initAgentLog 将 Agent 日志输出到安装目录下的 agent.log。
// v1.5.31 H2: 增加 10MB 轮转 — 超限时重命名为 agent-YYYY-MM-DD.log, 保留最近 3 个。
// v1.5.33: Windows Service 避免写 os.Stderr（SCM 启动的进程无有效标准句柄, io.MultiWriter 会阻塞）。
// v1.5.33: 轮转逻辑移除 os.ReadDir/sort（避免潜在 Windows 兼容问题），改用简单顺序编号。
func initAgentLog() {
	perm := os.FileMode(0700)
	filePerm := os.FileMode(0600)
	if runtime.GOOS == "windows" {
		perm = 0755
		filePerm = 0644
	}
	// v1.6.42 H4: 检查目录创建错误, 失败时告警但不中断 (后续文件操作会再次失败)
	if err := os.MkdirAll(agentBaseDir, perm); err != nil {
		log.Printf("[agent] 创建安装目录失败: %v", err)
	}
	logPath := filepath.Join(agentBaseDir, "agent.log")

	// 文件超过 10MB 时轮转: 只保留 3 个, 简单编号 (1/2/3)
	if fi, err := os.Stat(logPath); err == nil && fi.Size() > 10<<20 {
		for i := 3; i >= 1; i-- {
			old := filepath.Join(agentBaseDir, fmt.Sprintf("agent.%d.log", i))
			if i < 3 {
				next := filepath.Join(agentBaseDir, fmt.Sprintf("agent.%d.log", i+1))
				// v1.6.58: 检查 Rename 错误, 防止轮转失败静默
				if err := os.Rename(old, next); err != nil {
					log.Printf("[agent] Agent日志轮转 Rename 失败: %s→%s (%v)", old, next, err)
				}
			} else {
				// v1.6.42 L1: 检查删除错误, 防止轮转失败静默
				if err := os.Remove(old); err != nil && !os.IsNotExist(err) {
					log.Printf("[agent] Agent日志轮转删除失败: %s (%v)", old, err)
				}
			}
		}
		os.Rename(logPath, filepath.Join(agentBaseDir, "agent.1.log"))
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, filePerm)
	if err != nil {
		return
	}
	// Windows Service 下 os.Stderr 无效, 写文件即可; Linux 同时写 stderr 便于调试
	if runtime.GOOS == "windows" {
		log.SetOutput(f)
	} else {
		log.SetOutput(io.MultiWriter(os.Stderr, f))
	}
	log.Printf("[agent] 日志文件: %s", logPath)
	// v1.5.34 H3: 同时打开操作事件日志持久化文件
	initAgentEventsLog()
}

// base paths — defaults, overridable via -dir flag or auto-detected from binary location.
var (
	agentBaseDir    string
	agentConfigPath string
)

func init() {
	if runtime.GOOS == "windows" {
		agentBaseDir = `C:\ddns-agent`
	} else {
		agentBaseDir = "/opt/ddns-agent"
	}
	agentConfigPath = filepath.Join(agentBaseDir, "agent.yaml")
}

// detectInstallDir 自适应寻找安装目录: 默认路径 → 二进制所在目录。
// v1.5.32: 兼容旧版本 /opt/ddns-manager → /opt/ddns-agent 路径迁移导致的配置不可达。
func detectInstallDir() {
	// 若默认路径已存在 agent.yaml, 直接使用
	if _, err := os.Stat(agentConfigPath); err == nil {
		return
	}
	// 回退: 从二进制所在目录定位 agent.yaml (兼容旧安装路径如 /opt/ddns-manager)
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		if fi, err2 := os.Stat(filepath.Join(dir, "agent.yaml")); err2 == nil && !fi.IsDir() {
			setBaseDir(dir)
			log.Printf("[agent] 从二进制路径自适应安装目录: %s", dir)
			return
		}
	}
}

// ensureSymlink v1.5.37: 启动时检测 node-agent 符号链接是否丢失, 自动从现有版本化二进制重建。
// 防止 replaceRunningBinary os.Remove→os.Symlink 窗口期导致的永久离线。
// 选择安装目录下版本号最高的 node-agent-v*-linux-amd64 文件作为链接目标。
func ensureSymlink() {
	if runtime.GOOS == "windows" {
		return // Windows 不使用符号链接, 由升级批处理管理
	}
	link := filepath.Join(agentBaseDir, "node-agent")
	if _, err := os.Lstat(link); err == nil {
		return // 符号链接存在, 正常
	}
	// 符号链接丢失 — 扫描安装目录寻找版本号最高的二进制
	entries, err := os.ReadDir(agentBaseDir)
	if err != nil {
		return
	}
	var bestVer string
	var bestName string
	for _, e := range entries {
		name := e.Name()
		// v1.6.29 M4+v1.6.30 C2: 排除 .new 临时升级文件和 .sha256 校验文件, 防止选中非可执行文件
		if !strings.HasPrefix(name, "node-agent-v") || e.IsDir() ||
			strings.HasSuffix(name, ".new") || strings.HasSuffix(name, ".sha256") ||
			strings.HasSuffix(name, ".tmp") || strings.HasSuffix(name, ".linktmp") {
			continue
		}
		// 提取版本号: node-agent-v1.5.34-linux-amd64 → 1.5.34
		if !strings.Contains(name, "-"+runtime.GOOS+"-") {
			continue
		}
		parts := strings.SplitN(name, "-v", 2)
		if len(parts) < 2 {
			continue
		}
		verPart := parts[1]
		if dash := strings.Index(verPart, "-"); dash != -1 {
			verPart = verPart[:dash]
		}
		if model.CompareSemVer(verPart, bestVer) > 0 {
			bestVer = verPart
			bestName = name
		}
	}
	if bestName == "" {
		log.Printf("[agent] 符号链接丢失且未找到版本化二进制, 请重新安装")
		agentLog("[heartbeat] 符号链接丢失且未找到版本化二进制")
		return
	}
	if err := os.Symlink(bestName, link); err != nil {
		log.Printf("[agent] 自动重建符号链接失败: %v", err)
		agentLog("[heartbeat] 符号链接重建失败: %v", err)
		return
	}
	log.Printf("[agent] 符号链接丢失,已自动重建: %s → %s (v%s)", link, bestName, bestVer)
	agentLog("[heartbeat] 符号链接已自动重建: %s → %s (v%s)", link, bestName, bestVer)
}

// setBaseDir overrides the default base directory (called after flag parsing).
func setBaseDir(dir string) {
	agentBaseDir = dir
	agentConfigPath = filepath.Join(agentBaseDir, "agent.yaml")
}


// configCachePath returns the path for caching the pushed ddns-go config.
// Always stores inside agentBaseDir — not derived from CertPath to avoid
// path traversal risk (e.g. CertPath = /var/../../../tmp).
func configCachePath() string {
	return filepath.Join(agentBaseDir, "ddns_cache.yaml")
}

// configCacheKey caches the AES key for config-cache encryption (derived once per agent lifetime).
var (
	configCacheKey     []byte
	configCacheKeyOnce sync.Once
)

// getConfigCacheKey returns the cached AES key for encrypting/decrypting the DNS config cache.
// M1: Key derivation is performed once (HKDF-SHA256) instead of per-heartbeat.
func getConfigCacheKey(password, fingerprint string) []byte {
	configCacheKeyOnce.Do(func() {
		configCacheKey = crypto.DeriveKey(password, fingerprint, "config-cache")
	})
	return configCacheKey
}

// runDNSUpdateWithTimeout executes dnsUpdater.Run() with a time limit.
// This prevents DNS API hangs (e.g. provider outage) from blocking the
// entire heartbeat cycle. The underlying ddns-go http.Client already has
// a 30s per-request timeout; this caps the total cycle time.
//
// If the timeout fires, the goroutine continues in the background (held
// by DNSUpdater's mutex), and the next heartbeat's Run() will block until
// it completes — ensuring no concurrent executions.
func runDNSUpdateWithTimeout(u *DNSUpdater, timeout time.Duration) DNSStatus {
	// v1.6.46: 启动 Run() 前保存快照 — 超时后返回真·旧状态, 不阻塞等 u.mu 锁
	// 旧实现 u.Status() 在 Run() 持锁时阻塞, 2分钟超时形同虚设
	prevStatus := u.Status()
	done := make(chan DNSStatus, 1)
	go func() {
		done <- u.Run()
	}()

	select {
	case status := <-done:
		return status
	case <-time.After(timeout):
		log.Printf("[dns] DNS更新超时 (%v), 使用本次运行前状态 (ipv4=%s ipv6=%s lastOK=%v)",
			timeout, prevStatus.IPv4, prevStatus.IPv6, prevStatus.LastOK)
		return prevStatus
	}
}

func loadConfig(path string) (*model.AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg model.AgentConfig
	// YAML is a superset of JSON — both old JSON and new YAML files parse fine
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	// v1.6.50: 默认启用 TLS 证书验证（所有 Agent 通过外网域名访问 Manager，
	// 使用 ACME 公网证书，无需跳过验证。用户显式设置 false 才关闭）
	var raw map[string]interface{}
	if yaml.Unmarshal(data, &raw) == nil {
		if _, exists := raw["verify_ssl"]; !exists {
			cfg.VerifySSL = true
		}
	}
	// v1.5.37: 确保 CertPath 有默认值, 否则心跳不携带此字段 → Manager 无法获取
	// → 证书绑定 deploy_path 无法从 Agent 获取 → WebUI 配置困难
	if cfg.CertPath == "" {
		cfg.CertPath = filepath.Join(agentBaseDir, "certs")
	}
	return &cfg, nil
}

func generatePassword() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("随机数生成失败: %v", err) // 不可恢复 — 安全关键路径
	}
	return hex.EncodeToString(b)
}

// collectHardware gathers system identity + network info for heartbeat reporting.
// v1.6.45 M3: 只采集身份信息(主机名/OS/网卡/IP) — 管理端仪表盘仅需展示管理端自身资源,
// Agent 端的 CPU/内存/磁盘资源数据不在采集范围内 (HardwareInfo 的 cpu_percent/
// memory_*/disk_* 字段为管理端专用, Agent 侧永不填充)。
func collectHardware() *model.HardwareInfo {
	hostname, _ := os.Hostname()
	hw := &model.HardwareInfo{
		Hostname: hostname,
		OS:       runtime.GOOS + "/" + runtime.GOARCH,
		Arch:     runtime.GOARCH,
	}
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				hw.OS = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}
	// v1.5.20 L2: Windows 上读注册表获取友好名称 (如 "Windows Server 2022 Standard")
	if runtime.GOOS == "windows" {
		if winName := osProductName(); winName != "" {
			hw.OS = winName
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("[hw] 获取网卡列表失败: %v", err)
		return hw
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		ni := model.NetInterface{
			Name: iface.Name,
			MAC:  iface.HardwareAddr.String(),
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.To4() != nil {
				ni.IPv4 = ipNet.IP.String()
			} else if ipNet.IP.To16() != nil {
				ni.IPv6 = ipNet.IP.String()
			}
		}
		hw.Interfaces = append(hw.Interfaces, ni)
	}
	return hw
}

func doHeartbeat(cfg *model.AgentConfig) error {
	// v1.6.36 C4: 加载持久化的配置 hash (oneshot 模式跨进程不丢失)
	// 仅首次心跳时加载一次, daemon 模式下 lastConfigHash 已在内存中
	if lastConfigHash == "" {
		if data, err := os.ReadFile(configHashPath()); err == nil {
			lastConfigHash = strings.TrimSpace(string(data))
		}
	}

	// v2: Use embedded DNSUpdater instead of separate ddns-go process
	dnsUpdaterOnce.Do(func() {
		dnsUpdater = NewDNSUpdater()
		// load cached config from previous successful push
		if data, err := os.ReadFile(configCachePath()); err == nil {
			// Try decrypt (v2.1+ encrypted format), fall back to plaintext (v2.0 compat)
			yamlData := data
			key := getConfigCacheKey(cfg.Password, cfg.Fingerprint)
			if plain, decErr := crypto.Decrypt(string(data), key); decErr == nil {
				yamlData = plain
			}
			dnsUpdater.ApplyConfig(yamlData)
		}
	})

	// 1. Run DNS update with timeout (2 min) — prevents DNS API hangs from blocking the heartbeat cycle.
	// ddns-go's http.Client already has 30s per-request timeout, this caps the total cycle.
	status := runDNSUpdateWithTimeout(dnsUpdater, 2*time.Minute)

	// 2. Collect deployed cert hashes for drift detection
	certHashes := collectCertHashesIfNeeded(cfg)

	// 3. Build heartbeat request
	// v1.5.30 H2: 从缓存读取证书部署错误, 填充到 Status.CertErrors 上报 Manager
	lastCertErrorsMu.Lock()
	reportCertErrors := lastCertErrors
	lastCertErrors = nil
	lastCertErrorsMu.Unlock()

	req := model.HeartbeatReq{
		NodeID:      cfg.NodeID,
		Fingerprint: cfg.Fingerprint,
		Status: model.NodeStatus{
			AgentVersion: version,
			CertPath:     cfg.CertPath,
			IPv4:         status.IPv4,
			IPv6:         status.IPv6,
			CertHashes:   certHashes,
			CertErrors:   reportCertErrors, // v1.5.30 H2: 证书部署错误上报
			// v1.6.15: IIS扫描仅在配置了证书绑定时执行, 无绑定则跳过
			IISBoundSites: scanIISBindingsIfNeeded(cfg),
			DDNSHealth: &model.DDNSHealthInfo{
				Running:         status.Running,
				LastOK:          status.LastOK,
				LastError:       status.LastError,
				LastErrorDetail: status.LastErrorDetail, // v1.5.33: ddns-go API 详细错误
				FailedDomains:   status.FailedDomains,
				LogLine:         status.LastLine(),
				// v1.6.11 B2: IP获取状态
				IPv4OK:          status.IPv4OK,
				IPv6OK:          status.IPv6OK,
				IPv4Msg:         status.IPv4Msg,
				IPv6Msg:         status.IPv6Msg,
				// v1.6.46: Manager 据此区分"主动关"和"意外失败"
				IPv4Enabled:     status.IPv4Enabled,
				IPv6Enabled:     status.IPv6Enabled,
			},
		},
		ConfigHash: lastConfigHash,  // v1.5.23+v1.6.36 C4: 回传Manager权威hash, 避免yaml往返不稳定导致每心跳重推
		Logs:       dnsUpdater.PeekRecentLogs(10),  // v1.6.46 H7: 增量上报, 心跳成功才 commit
		Hardware:   collectHardware(),
	}

	// v1.5.29 C1: 在 sendHeartbeat 之前填充 AgentLogs (修复 v1.5.22 H2 回归)
	// v1.6.10 M3: Drain 前快照 — 心跳失败时恢复, 避免重试循环中日志丢失
	// 注意: 重试循环中的 Write→Drain→Write→Drain 序列天然安全,
	// 因为恢复后的日志会在下次 Drain 时重新进入 req.AgentLogs
	var drainedAgentLogs []string
	if agentLogBuf.Len() > 0 {
		drainedAgentLogs = agentLogBuf.Drain()
		req.AgentLogs = drainedAgentLogs
	}

	// 3. Send heartbeat
	heartbeatFailed.Store(false)
	resp, hbErr := sendHeartbeat(cfg, req)
	if resp == nil {
		// v1.5.29 C1: 心跳失败时恢复 AgentLogs 到缓冲，防止丢失
		heartbeatFailed.Store(true)
		// v1.6.10 M3: 恢复已 drain 的日志, 确保重试时重新发送
		// v1.6.28 M5: 使用 WriteRaw 保留 Drain 时的原始时间戳
		for _, logLine := range drainedAgentLogs {
			agentLogBuf.WriteRaw(logLine)
		}
		// v1.6.46 H7: Peek 不消耗 buffer, 无需 dns-replay 恢复 — 失败时游标不动自动重传
		log.Printf("[heartbeat] 心跳失败: %v", hbErr)
		return fmt.Errorf("心跳失败: %w", hbErr)
	}

	// v1.6.46 H7: 心跳成功 → 确认 DNS 日志上报, 游标前移防止重复
	dnsUpdater.CommitRecentLogs()

	// 4. Config hot-reload + cache to disk for next heartbeat
	if resp.Config != nil && resp.Config.YAML != "" {
		if resp.Config.Hash != lastConfigHash {
			if err := dnsUpdater.ApplyConfig([]byte(resp.Config.YAML)); err != nil {
				log.Printf("配置应用失败: %v", err)
			} else {
			// v1.6.56 M2: 先持久化配置缓存，成功后写 hash — 缓存失败则 hash 不更新
			// 避免 hash=新但缓存=旧导致重启后配置不一致永久报错
			cacheWritten := false
			if encErr := os.MkdirAll(filepath.Dir(configCachePath()), 0700); encErr != nil {
				log.Printf("[config] 缓存目录创建失败 (磁盘满/权限?): %v", encErr)
				agentLog("配置缓存目录创建失败: %v", encErr)
			} else {
				cacheData, encErr := crypto.Encrypt([]byte(resp.Config.YAML),
					getConfigCacheKey(cfg.Password, cfg.Fingerprint))
				if encErr != nil {
					log.Printf("[config] 缓存加密失败，拒绝写入明文: %v", encErr)
					agentLog("缓存加密失败: %v", encErr)
				} else if writeErr := os.WriteFile(configCachePath(), []byte(cacheData), 0600); writeErr != nil {
					log.Printf("[config] 缓存写入失败 (磁盘满/权限?): %v", writeErr)
					agentLog("配置缓存写入失败: %v", writeErr)
				} else {
					cacheWritten = true
				}
			}
			if cacheWritten {
				if err := os.WriteFile(configHashPath(), []byte(resp.Config.Hash), 0600); err != nil {
					agentLog("[config] hash持久化失败 (磁盘满/权限?): %v", err)
					log.Printf("[config] hash持久化失败: %v (managerHash已丢弃, 下次心跳重推)", err)
				} else {
					lastConfigHash = resp.Config.Hash
				}
			}
				// v1.6.28 H1: 配置变更后同步执行 DNS 更新, 失败时立即发送跟进心跳上报
				// 修复 v1.5.29 C4 的 5 分钟延迟 — 异步 goroutine 导致失败静默到下一心跳
				if dnsUpdateRunning.CompareAndSwap(false, true) {
					cfgStatus := runDNSUpdateWithTimeout(dnsUpdater, 2*time.Minute)
					dnsUpdateRunning.Store(false)
					if !cfgStatus.LastOK {
						agentLog("配置变更后DNS更新失败: %s", cfgStatus.LastError)
						log.Printf("[dns] 配置变更后DNS更新失败: %s", cfgStatus.LastError)
						// 发送跟进心跳上报 DNS 失败状态 (含 Logs, 不等 5 分钟)
						go sendDDNSHealthHeartbeat(cfg, cfgStatus)
					} else {
						agentLog("配置变更后DNS更新完成 ipv4=%s ipv6=%s", cfgStatus.IPv4, cfgStatus.IPv6)
					}
				} else {
					log.Printf("[dns] DNS 更新已在运行, 跳过本次配置变更触发")
				}
			}
		}
	}

	// 5. v1.5.29 H5: 证书部署错误回报 Manager 便于诊断
	certErrors := applyCertUpdates(cfg, resp.CertUpdates)
	// 将本轮证书部署错误加入心跳请求 (下个心跳随 Status.CertErrors 上报)
	// 注意: 这里修改 req 是在 sendHeartbeat 成功返回之后, 本轮心跳已发送。
	// 证书错误将附加到 AgentLogs 中, 随下个心跳一起上报。
	if len(certErrors) > 0 {
		for _, ce := range certErrors {
			agentLog("证书部署错误: %s", ce)
		}
	}

	// 6. Config error — node config rendering failed on manager side
	if resp.ConfigError != "" {
		log.Printf("[config] 管理端配置渲染失败: %s", resp.ConfigError)
	}

	// 7. Self-upgrade (keep v1 logic)
	if resp.AgentUpdate != nil {
		// v1.5.20 Fix3: 升级前发送当前日志缓冲，升级后 os.Exit 会丢失
		agentLog("收到升级推送: v%s → v%s", version, resp.AgentUpdate.Version)
		if err := selfUpgrade(cfg, resp.AgentUpdate); err != nil {
			if err == errDowngradeBlocked {
				agentLog("升级已跳过: 拒绝降级至 v%s", resp.AgentUpdate.Version)
			} else {
				agentLog("自升级失败: %v", err)
				log.Printf("自升级失败: %v", err)
			}
		}
	}

	return nil
}

// sendHeartbeat sends a heartbeat request and returns the response.
// v1.5.34 H6+M5: 返回 error 区分失败原因 (网络/认证/解析), 非 200 时记录响应体
func sendHeartbeat(cfg *model.AgentConfig, req model.HeartbeatReq) (*model.HeartbeatResp, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("序列化失败: %w", err)
	}
	token := base64.StdEncoding.EncodeToString([]byte(cfg.NodeID + ":" + cfg.Password))

	client := newHTTPClient(cfg.VerifySSL, 30*time.Second)

	httpReq, err := http.NewRequest("POST", cfg.ManagerURL+"/api/heartbeat", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("网络错误: %w", err)
	}
	defer resp.Body.Close()

	// v1.6.29 M5: 检测认证失败 (401/403), 返回 sentinel error 阻止重试
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: HTTP %d", errAuthFailed, resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20)) // 50MB (多证书场景)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	var hr model.HeartbeatResp
	if err := json.Unmarshal(respBody, &hr); err != nil {
		// v1.5.34 M5: 解析失败时记录原始响应体前缀 (帮助诊断非 JSON 响应)
		preview := string(respBody)
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		return nil, fmt.Errorf("解析响应失败: %w (body=%s)", err, preview)
	}
	if !hr.OK {
		return nil, fmt.Errorf("服务端拒绝: %s", hr.Error)
	}
	return &hr, nil
}

// sendDDNSHealthHeartbeat v1.6.28 H1+v1.6.29 C3+v1.6.30 H1: 配置变更后 DNS 更新失败时发送跟进心跳
// 携带完整 DDNSHealth + IPv4/IPv6 + FailedDomains + LastErrorDetail + CertPath + CertHashes, 不等 5 分钟周期
func sendDDNSHealthHeartbeat(cfg *model.AgentConfig, status DNSStatus) {
	// v1.6.30 H1: 补全 CertPath/CertHashes/IPv4OK/IPv6OK, 与常规心跳字段对齐
	// v1.6.33 P5: 补全 CertErrors 字段, 确保证书部署错误也在跟进心跳中上报
	// v1.6.45 H1: 补全 Logs 字段, 确保 Manager 能关联 DNS 失败的具体域名和原因
	lastCertErrorsMu.Lock()
	followCertErrors := lastCertErrors
	lastCertErrorsMu.Unlock()

	dnsLogs := dnsUpdater.PeekRecentLogs(10)  // v1.6.46 H7: 增量上报
	req := model.HeartbeatReq{
		NodeID:      cfg.NodeID,
		Fingerprint: cfg.Fingerprint,
		ConfigHash:  lastConfigHash, // v1.6.36 C4: 补齐ConfigHash, 防止跟进心跳触发配置重推死循环
		Logs:        dnsLogs,
		Status: model.NodeStatus{
			AgentVersion: version,
			CertPath:     cfg.CertPath,
			CertHashes:   collectCertHashes(cfg), // v1.6.50 M2: 统一使用目录路径key, 对齐常规心跳和Manager精确匹配
			CertErrors:   followCertErrors,  // v1.6.33 P5: 补全证书部署错误上报
			IPv4:         status.IPv4,
			IPv6:         status.IPv6,
			DDNSHealth: &model.DDNSHealthInfo{
				Running:         status.Running,
				LastOK:          status.LastOK,
				LastError:       status.LastError,
				LastErrorDetail: status.LastErrorDetail,
				FailedDomains:   status.FailedDomains,
				IPv4OK:          status.IPv4OK,
				IPv6OK:          status.IPv6OK,
				IPv4Msg:         buildIPMsg(status.IPv4, status.IPv4Enabled),
				IPv6Msg:         buildIPMsg(status.IPv6, status.IPv6Enabled),
				IPv4Enabled:     status.IPv4Enabled,
				IPv6Enabled:     status.IPv6Enabled,
				Status:          "ERR",
				StatusMsg:       fmt.Sprintf("配置变更后DNS更新失败: %s", status.LastError),
			},
		},
	}
	if _, err := sendHeartbeat(cfg, req); err != nil {
		log.Printf("[dns] 跟进心跳发送失败: %v", err)
		agentLog("跟进心跳发送失败: %v", err)
	} else {
		log.Printf("[dns] 跟进心跳已发送 (配置变更后DNS失败已上报) %d失败域名", len(status.FailedDomains))
	}
}

// applyCertUpdates processes certificate updates from heartbeat response.
// Deploys cert files → updates IIS bindings (Windows) → reloads services → recycles app pools.
// v1.5.29 H5: 返回证书部署错误列表，供心跳上报 Manager 诊断
func applyCertUpdates(cfg *model.AgentConfig, updates []*model.CertUpdate) (certErrors []string) {
	if len(updates) == 0 {
		return
	}
	agentLog("证书部署: 收到 %d 个证书更新", len(updates))
	key := crypto.DeriveKey(cfg.Password, cfg.Fingerprint, "cert-transport")
	for _, cu := range updates {
		agentLog("证书部署: 开始处理 bundle=%s hash=%s...", cu.BundleName, cu.CertHash[:14])
		// v1.5.41: 每个证书部署到 CertPath/{BundleName}/ 子目录, 避免多站点证书覆盖
		// 对齐 win-acme: 不同证书存不同位置, IIS 绑定按 CN/SAN 自动匹配
		path := cu.TargetPath
		if path == "" {
			path = filepath.Join(cfg.CertPath, model.SanitizeCertDirName(cu.BundleName))
		}
		if path == "" {
			// M7: mark bundle as processed to prevent repeated push
			certHashMapMu.Lock()
			certHashMap[cu.BundleName] = cu.CertHash
			certHashMapMu.Unlock()
			continue
		}
		// v1.6.28 H6: Agent 端二次校验部署路径, 拒绝路径穿越 (Manager TLS 被绕过时的纵深防御)
		// v1.5.xx: 宽鬆處理絕對路徑 — 若在 agentBaseDir 子樹內則接受, 解決 Manager 下發
		// Agent 自身 CertPath (如 C:\ddns-agent\certs) 被 IsAbs 誤判為非法的問題。
		if strings.Contains(path, "..") {
			errMsg := fmt.Sprintf("%s: 拒绝非法部署路径(含..) %q", cu.BundleName, path)
			log.Printf("[cert] %s", errMsg)
			agentLog("证书部署: %s", errMsg)
			certErrors = append(certErrors, errMsg)
			continue
		}
		if filepath.IsAbs(path) {
			absBase, _ := filepath.Abs(agentBaseDir)
			cleaned := filepath.Clean(path)
			rel, err := filepath.Rel(absBase, cleaned)
			if err != nil || strings.HasPrefix(rel, "..") {
				errMsg := fmt.Sprintf("%s: 拒绝非法部署路径(越界) %q", cu.BundleName, path)
				log.Printf("[cert] %s", errMsg)
				agentLog("证书部署: %s", errMsg)
				certErrors = append(certErrors, errMsg)
				continue
			}
			path = cleaned
		} else {
			// 相对路径基于 agentBaseDir 解析, 避免 Windows Service cwd 不确定
			path = filepath.Join(agentBaseDir, path)
		}
		// v1.6.37: 755 允许非root服务(nginx worker等)读取公钥证书
		// v1.6.45 H3: 检查目录创建错误, 失败时告警但不中断 (后续文件写操作会再次失败)
		if err := os.MkdirAll(path, 0o755); err != nil {
			log.Printf("[cert] 创建证书目录失败 %s: %v", path, err)
			agentLog("证书部署: 创建目录失败 %s: %v", path, err)
		}
		hasModernPFX := false
		hasLegacyPFX := false
		legacyPFXFile := "" // cert.pfx path (LegacyDES, 全版本兼容)
		modernPFXFile := "" // cert-modern.pfx path (PBES2+AES-256, Win10+)
		for name, ct := range cu.Files {
			plain, err := crypto.Decrypt(ct, key)
			if err != nil {
				log.Printf("[cert] 解密失败 %s/%s: %v", cu.BundleName, name, err)
				certErrors = append(certErrors, fmt.Sprintf("%s: 解密失败 %s", cu.BundleName, name))
				continue
			}
			tmp := filepath.Join(path, name+".new")
			dst := filepath.Join(path, name)
			// v1.6.37: 私钥 600, 公钥证书 644 — 允许非root服务读取证书
			filePerm := os.FileMode(0o644)
			if isPrivateKeyFile(name) {
				filePerm = 0o600
			}
			if we := os.WriteFile(tmp, plain, filePerm); we != nil {
				log.Printf("[cert] 写入失败 %s/%s: %v", cu.BundleName, name, we)
				agentLog("证书部署: 写入失败 %s/%s: %v", cu.BundleName, name, we)
				certErrors = append(certErrors, fmt.Sprintf("%s: 写入失败 %s (%v)", cu.BundleName, name, we))
				continue
			}
			if re := os.Rename(tmp, dst); re != nil {
				log.Printf("[cert] 重命名失败 %s/%s: %v", cu.BundleName, name, re)
				agentLog("证书部署: 重命名失败 %s/%s: %v", cu.BundleName, name, re)
				certErrors = append(certErrors, fmt.Sprintf("%s: 重命名失败 %s (%v)", cu.BundleName, name, re))
				continue
			}
			agentLog("证书部署: 写入文件 %s/%s (%d bytes)", cu.BundleName, name, len(plain))
			lower := strings.ToLower(name)
			if strings.HasSuffix(lower, ".pfx") {
				if strings.Contains(lower, "modern") {
					hasModernPFX = true
					modernPFXFile = dst
					agentLog("证书部署: 检测到 Modern PFX %s", name)
				} else {
					hasLegacyPFX = true
					legacyPFXFile = dst
					agentLog("证书部署: 检测到 Legacy PFX %s", name)
				}
			}
		}
		// H5: 先写证书文件，IIS 绑定失败则不写 .cert_hash，下次心跳重试

		// On Windows, auto-import cert to IIS after deployment
		// 双PFX: Modern优先(AES-256) → 失败降级Legacy(3DES) → 无PFX走openssl
		iisOK := true
		if runtime.GOOS == "windows" {
			// v1.5.20: 证书级 PFX 密码 → 配置级 → 默认 "ddns"
		// v1.5.39: 增加密码来源诊断日志, 便于从 Manager 侧定位密码不匹配问题
		pfxPwd := cu.PFXPassword
		pwdSource := "证书级(cert)"
		if pfxPwd == "" {
			pfxPwd = cfg.PFXPassword
			pwdSource = "配置级(agent.yaml)"
		}
		if pfxPwd == "" {
			pfxPwd = crypto.DefaultPFXPassword
			pwdSource = "默认"
			agentLog("证书部署: 使用默认PFX密码, 建议在管理端为 %s 设置密码", cu.BundleName)
			log.Printf("[cert] %s: 未设置PFX密码, 使用默认值 %s", cu.BundleName, crypto.DefaultPFXPassword)
		}
		agentLog("证书部署: PFX密码来源=%s bundle=%s", pwdSource, cu.BundleName)
		log.Printf("[cert] %s: PFX密码来源=%s", cu.BundleName, pwdSource)
			pfxImported := false
			// 1. 优先尝试 Modern PFX (Win10 1809+, 更强加密)
			if hasModernPFX && modernPFXFile != "" {
				if _, err := os.Stat(modernPFXFile); err == nil {
					iisOK = importPFXToIIS(modernPFXFile, cu.BundleName, pfxPwd, cfg.IISCertBindings)
					if iisOK {
						pfxImported = true
						recycleIISAppPools()
						agentLog("证书部署: IIS Modern PFX 绑定成功 %s", cu.BundleName)
						log.Printf("[cert] IIS绑定: Modern PFX → %s", cu.BundleName)
					} else {
						agentLog("证书部署: Modern PFX 失败, 降级Legacy %s", cu.BundleName)
						log.Printf("[cert] Modern PFX导入失败, 降级尝试Legacy...")
					}
				}
			}
			// 2. Modern失败或不存在 → 降级到 Legacy PFX (Win7/Win2016 兼容)
			if !pfxImported && hasLegacyPFX && legacyPFXFile != "" {
				if _, err := os.Stat(legacyPFXFile); err == nil {
					iisOK = importPFXToIIS(legacyPFXFile, cu.BundleName, pfxPwd, cfg.IISCertBindings)
					if iisOK {
						pfxImported = true
						recycleIISAppPools()
						agentLog("证书部署: IIS Legacy PFX 绑定成功 %s", cu.BundleName)
						log.Printf("[cert] IIS绑定: Legacy PFX → %s", cu.BundleName)
					} else {
						agentLog("证书部署: Legacy PFX 失败, 降级openssl %s", cu.BundleName)
						log.Printf("[cert] Legacy PFX导入失败, 降级尝试openssl...")
					}
				}
			}
			// 3. 两个PFX都失败 → 走 openssl 兼容路径
			if !pfxImported {
				iisOK = importToIIS(path, cu.BundleName, cfg.IISCertBindings, pfxPwd)
				recycleIISAppPools()
				agentLog("证书部署: openssl路径 IIS绑定 %s (成功=%v)", cu.BundleName, iisOK)
			}
		}

		// Process service reload hints from Manager
		// M4: collect failed service reloads for logging
		var failedServices []string
		for _, svc := range cu.ReloadServices {
			if !reloadService(svc) {
				agentLog("证书部署: 服务重载失败 %s (bundle=%s)", svc, cu.BundleName)
				failedServices = append(failedServices, svc)
			}
		}
		if len(failedServices) > 0 {
			certErrors = append(certErrors, fmt.Sprintf("%s: 服务重载失败 %v", cu.BundleName, failedServices))
			agentLog("证书部署: 服务重载失败: %v (bundle=%s)", failedServices, cu.BundleName)
		} else if len(cu.ReloadServices) > 0 {
			agentLog("证书部署: 服务重载完成 (%d个服务) bundle=%s", len(cu.ReloadServices), cu.BundleName)
		}

		// H5: 仅在 IIS 绑定成功(或非Windows)后才写入 .cert_hash
		// 如果 IIS 绑定失败，保留旧 hash，下次心跳 Manager 会重新推送
		if iisOK {
			hashFile := filepath.Join(path, ".cert_hash")
			// v1.6.58: 原子写入 — tmp+Rename 防止崩溃残留半截文件
			tmpHashFile := hashFile + ".tmp"
			os.WriteFile(tmpHashFile, []byte(cu.CertHash), 0o644)
			os.Rename(tmpHashFile, hashFile)
			// v1.5.22 M1: 正常路径也更新 certHashMap，使清理逻辑生效
			certHashMapMu.Lock()
			certHashMap[cu.BundleName] = cu.CertHash
			certHashMapMu.Unlock()
			agentLog("证书部署: 完成 %s -> %s (hash=%s...)", cu.BundleName, path, cu.CertHash[:14])
			log.Printf("[cert] 已部署: %s -> %s", cu.BundleName, path)
		} else {
			certErrors = append(certErrors, fmt.Sprintf("%s: IIS绑定失败, 下次心跳重试", cu.BundleName))
			agentLog("证书部署: 文件已写入但IIS绑定失败 %s, 下次心跳重试", cu.BundleName)
			log.Printf("[cert] 证书文件已写入但 IIS 绑定失败: %s, 下次心跳重试", cu.BundleName)
			// v1.6.65 修复: 写哨兵 .cert_hash — 否则 collectCertHashes 走
			// Phase 3 磁盘扫描, 上报的磁盘 hash 与 Manager meta hash 一致后
			// Manager 判定"已部署"停止推送 → IIS 绑定永不重试 (死锁, sp 事故)。
			// 哨兵值非 sha256: 格式, 上报后与 meta hash 不匹配 → 强制下个心跳重推。
			sentinelPath := filepath.Join(path, ".cert_hash")
			tmpSentinel := sentinelPath + ".tmp"
			if werr := os.WriteFile(tmpSentinel, []byte("pending"), 0o644); werr != nil {
				log.Printf("[cert] 哨兵 .cert_hash 写入失败 %s: %v", sentinelPath, werr)
			} else if rerr := os.Rename(tmpSentinel, sentinelPath); rerr != nil {
				log.Printf("[cert] 哨兵 .cert_hash 重命名失败 %s: %v", sentinelPath, rerr)
			}
		}
	}
	// H6: Clean stale certHashMap entries (bundles no longer pushed by Manager)
	// v1.5.22 M1: 正常路径(iisOK=true)已写入 certHashMap, 清理逻辑现在生效
	certHashMapMu.Lock()
	for bundle := range certHashMap {
		found := false
		for _, cu := range updates {
			if cu.BundleName == bundle {
				found = true
				break
			}
		}
		if !found {
			delete(certHashMap, bundle)
		}
	}
	certHashMapMu.Unlock()
	// v1.5.30 H2: 将本轮证书部署错误缓存, 下个心跳通过 Status.CertErrors 上报 Manager
	if len(certErrors) > 0 {
		lastCertErrorsMu.Lock()
		// 限制最多 20 条防止洪泛; 取最新的
		lastCertErrors = append(lastCertErrors, certErrors...)
		if len(lastCertErrors) > 20 {
			lastCertErrors = lastCertErrors[len(lastCertErrors)-20:]
		}
		lastCertErrorsMu.Unlock()
	}
	return certErrors
}

// reloadService reloads or restarts a system service after cert deployment.
// Supports systemd service names (Linux) and Windows service names.
// v1.6.58: 服务名限定白名单 — 防止管理员误配导致关键系统服务被误操作。
func reloadService(svc string) bool {
	// v1.6.58: 服务名白名单校验
	if !isAllowedService(svc) {
		log.Printf("[cert] 服务名 %q 不在白名单中, 已跳过", svc)
		return false
	}
	if runtime.GOOS == "windows" {
		// Windows: try appcmd recycle first (IIS), then net stop/start
		if strings.Contains(strings.ToLower(svc), "iis") || strings.Contains(strings.ToLower(svc), "w3svc") {
			recycleIISAppPools()
			return true
		}
		// Generic Windows service restart
		// v1.5.22 C5: 检查 sc stop 结果，stop 失败时不执行 start
		if outStop, errStop := exec.Command("sc", "stop", svc).CombinedOutput(); errStop != nil {
			log.Printf("[cert] 服务停止失败 %s: %v: %s", svc, errStop, string(outStop))
			// 继续尝试 start — 服务可能已经停止或 stop 超时
		} else {
			time.Sleep(2 * time.Second)
		}
		out, err := exec.Command("sc", "start", svc).CombinedOutput()
		if err != nil {
			log.Printf("[cert] 服务启动失败 %s: %v: %s", svc, err, string(out))
		} else {
			log.Printf("[cert] 服务已重启: %s", svc)
			return true
		}
		return false
	}
	// Linux: try reload first (nginx -s reload, systemctl reload), then restart
	// v1.6.29 H7: restart 后等待服务激活, 确保证书已被新进程读取
	_, err := exec.Command("systemctl", "reload", svc).CombinedOutput()
	if err != nil {
		// reload not supported, try restart
		out2, err2 := exec.Command("systemctl", "restart", svc).CombinedOutput()
		if err2 != nil {
			log.Printf("[cert] 服务重载失败 %s: %v: %s", svc, err2, string(out2))
			return false
		}
		// 等待服务进入 active 状态 (最多 5s), 确保证书文件已被新进程读取
		for i := 0; i < 5; i++ {
			time.Sleep(1 * time.Second)
			if outChk, errChk := exec.Command("systemctl", "is-active", "--quiet", svc).CombinedOutput(); errChk == nil {
				log.Printf("[cert] 服务已重启并激活: %s", svc)
				return true
			} else {
				_ = outChk
			}
		}
		log.Printf("[cert] 服务已重启(激活验证超时): %s", svc)
		return true // 重启命令成功, 即使激活验证超时也认为成功
	}
	log.Printf("[cert] 服务已重载: %s", svc)
	return true
}

// isAllowedService v1.6.58: 服务名白名单 — 仅允许常见 Web/反向代理服务。
// 防止管理员在 WebUI 误配导致关键系统服务被 sc stop/systemctl restart。
func isAllowedService(svc string) bool {
	allowed := map[string]bool{
		"nginx": true, "apache2": true, "httpd": true, "caddy": true,
		"haproxy": true, "traefik": true, "lighttpd": true, "openresty": true,
		"iisadmin": true, "w3svc": true, "w3logsvc": true, "ftpsvc": true,
		"apphostsvc": true, "was": true,
	}
	lower := strings.ToLower(svc)
	if allowed[lower] {
		return true
	}
	// 允许以已知前缀开头的自定义服务 (如 nginx@custom, apache2@site1)
	for prefix := range allowed {
		if strings.HasPrefix(lower, prefix+"@") || strings.HasPrefix(lower, prefix+"-") {
			return true
		}
	}
	return false
}

// recycleIISAppPools recycles all IIS application pools so the new certificate
// takes effect immediately. Uses appcmd (IIS 7+) with fallback to iisreset.
// v1.6.42 H5: 增加 agentLog, 使 Manager 端可追踪 IIS 回收结果
func recycleIISAppPools() {
	// Preferred: recycle individual app pools (less disruptive than iisreset)
	appcmd := filepath.Join(os.Getenv("SystemRoot"), "System32", "inetsrv", "appcmd.exe")
	if _, err := os.Stat(appcmd); err == nil {
		out, err := exec.Command(appcmd, "list", "apppool", "/xml").Output()
		if err == nil {
			// Parse app pool names and recycle each
			var recycled []string
			for _, line := range strings.Split(string(out), "\n") {
				if idx := strings.Index(line, "APPPOOL.NAME="); idx != -1 {
					start := idx + len("APPPOOL.NAME=") + 1
					end := strings.IndexByte(line[start:], '"')
					if end > 0 {
						poolName := line[start : start+end]
						exec.Command(appcmd, "recycle", "apppool", poolName).Run()
						log.Printf("[cert] IIS 应用池已回收: %s", poolName)
						recycled = append(recycled, poolName)
					}
				}
			}
			agentLog("[cert] IIS应用池已回收: %v", recycled)
			return
		}
	}
	// Fallback: full IIS reset (disruptive but guaranteed)
	out, err := exec.Command("iisreset", "/noforce").CombinedOutput()
	if err != nil {
		log.Printf("[cert] IIS 重置失败: %v: %s", err, string(out))
		agentLog("[cert] IIS重置失败: %v", err)
	} else {
		log.Printf("[cert] IIS 已重置 (iisreset)")
		agentLog("[cert] IIS已重置(iisreset)")
	}
}
func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil { return -1 }
	return fi.Size()
}

// isCertFile 判断文件名是否为证书相关文件 (PEM/PFX/KEY/CRT)。
// v1.5.41: 用于磁盘证书文件扫描, 排除 .cert_hash / meta.json 等非证书文件。
// isCertFile v1.6.42 M2: 用 strings.EqualFold 替代 ToLower, 避免每次调用分配新字符串
func isCertFile(name string) bool {
	return strings.EqualFold(filepath.Ext(name), ".pem") ||
		strings.EqualFold(filepath.Ext(name), ".crt") ||
		strings.EqualFold(filepath.Ext(name), ".cer") ||
		strings.EqualFold(filepath.Ext(name), ".key") ||
		strings.EqualFold(filepath.Ext(name), ".pfx")
}

// isPrivateKeyFile v1.6.37: 判断是否为私钥文件，私钥应保持 600 权限
func isPrivateKeyFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".key") ||
		strings.Contains(lower, "privkey") ||
		strings.Contains(lower, "key.")
}

func fileSHA256(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[hash] 无法读取文件 %s: %v", path, err)
		return ""
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

// collectCertHashes v1.6.15: 仅在配置了证书绑定时扫描证书目录
// collectCertHashesIfNeeded v1.6.16: 仅在证书已部署时扫描
func collectCertHashesIfNeeded(cfg *model.AgentConfig) map[string]string {
	entries, _ := os.ReadDir(cfg.CertPath)
	if len(entries) == 0 {
		return nil
	}
	return collectCertHashes(cfg)
}

// collectCertHashes scans the cert directory for .cert_hash files deployed by Manager.
// Returns map[deploy_path]hash for heartbeat reporting.
//
// v1.5.41: 对齐 win-acme 设计 — 除 .cert_hash 文件外, 也扫描磁盘上的证书文件
// 计算 SHA256 hash 上报。用于覆盖管理员手动部署证书(无 .cert_hash 文件)的场景。
func collectCertHashes(cfg *model.AgentConfig) map[string]string {
	if cfg.CertPath == "" {
		return map[string]string{}
	}
	// v1.5.22 M4: 用 mu 保护 result map 的并发访问
	// WalkDir 回调在独立 goroutine 中执行，超时后 goroutine 可能仍在写 result
	var mu sync.Mutex
	result := map[string]string{}
	maxDepth := 5
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan struct{}, 1)
	go func() {
		defer func() { done <- struct{}{} }()
		// Phase 1: WalkDir 扫描 .cert_hash 文件
		filepath.WalkDir(cfg.CertPath, func(p string, d os.DirEntry, err error) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if err != nil {
				log.Printf("[cert] 遍历目录错误 %s: %v", p, err)
				return nil
			}
			if d.IsDir() {
				rel, _ := filepath.Rel(cfg.CertPath, p)
				if rel != "." && strings.Count(rel, string(os.PathSeparator)) >= maxDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Name() == ".cert_hash" {
				data, err := os.ReadFile(p)
				if err == nil {
					mu.Lock()
					result[filepath.Dir(p)] = strings.TrimSpace(string(data))
					mu.Unlock()
				}
			}
			return nil
		})
		if ctx.Err() != nil { return }
		// Phase 2+3: 磁盘证书扫描 (v1.6.29 H2: 并入 goroutine, 受 30s 超时保护)
		// v1.6.42 M3: 合并为单次遍历 entries, 同时收集根级证书文件 + 检测子目录
		entries, _ := os.ReadDir(cfg.CertPath)
		var rootFiles []string
		for _, e := range entries {
			if ctx.Err() != nil { return }
			if e.IsDir() { continue }
			if isCertFile(e.Name()) {
				rootFiles = append(rootFiles, e.Name())
			}
		}
		if len(rootFiles) > 0 {
			sort.Strings(rootFiles)
			h := sha256.New()
			for _, fn := range rootFiles {
				if data, err := os.ReadFile(filepath.Join(cfg.CertPath, fn)); err == nil { h.Write(data) }
			}
			rootHash := fmt.Sprintf("sha256:%x", h.Sum(nil))
			mu.Lock()
			if _, exists := result[cfg.CertPath]; !exists { result[cfg.CertPath] = rootHash }
			mu.Unlock()
		}
		for _, e := range entries {
			if ctx.Err() != nil { return }
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") { continue }
			subDir := filepath.Join(cfg.CertPath, e.Name())
			if _, err := os.Stat(filepath.Join(subDir, ".cert_hash")); err == nil { continue }
			certFiles, _ := os.ReadDir(subDir)
			var files []string
			for _, cf := range certFiles {
				if cf.IsDir() || cf.Name() == "meta.json" { continue }
				files = append(files, cf.Name())
			}
			if len(files) == 0 { continue }
			sort.Strings(files)
			h := sha256.New()
			for _, fn := range files {
				if data, err := os.ReadFile(filepath.Join(subDir, fn)); err == nil { h.Write(data) }
			}
			diskHash := fmt.Sprintf("sha256:%x", h.Sum(nil))
			mu.Lock()
			// v1.6.30 H2: 同时注册相对名和完整路径, 兼容 Manager deploy_path 两套键名
			if _, exists := result[e.Name()]; !exists { result[e.Name()] = diskHash }
			fullPath := filepath.Join(cfg.CertPath, e.Name())
			if _, exists := result[fullPath]; !exists { result[fullPath] = diskHash }
			mu.Unlock()
		}
	}()
	// v1.6.42 C4 + v1.6.45 H2: 超时后等待 goroutine 退出再返回 result
	// 35s 总超时后 goroutine 可能仍在写 result map (NFS深层目录卡住) → data race
	// 此时返回空 map 而非半成品: Manager 检测到空 CertHashes 会全量重推证书 (一次冗余但安全)
	select {
	case <-done:
		// 正常完成
	case <-time.After(30 * time.Second):
		log.Printf("[cert] 证书目录遍历超时 (30s): %s (可能是NFS挂载卡住)", cfg.CertPath)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			log.Printf("[cert] 遍历goroutine未能在35s内退出, 返回空hash (防data race)")
			return map[string]string{}
		}
	}
	return result
}

// ── newHTTPClient ──

// newHTTPClient returns an http.Client that clones http.DefaultTransport
// (preserving HTTP/2, connection pooling) with optional TLS verification skip.
func newHTTPClient(verifySSL bool, timeout time.Duration) *http.Client {
	// 防御: timeout=0 表示无限等待，一个挂起的 TCP 连接会永久阻塞心跳
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if verifySSL {
		return &http.Client{Timeout: timeout}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// validateAgentBinary checks the downloaded file is a valid executable for this platform.
func validateAgentBinary(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read: %w", err)
	}
	if len(data) < 64 {
		return fmt.Errorf("file too small (%d bytes)", len(data))
	}

	if runtime.GOOS == "windows" {
		// PE magic: MZ
		if len(data) < 2 || data[0] != 'M' || data[1] != 'Z' {
			return fmt.Errorf("not a Windows PE binary")
		}
		// PE signature at offset in e_lfanew (offset 60)
		peOffset := binary.LittleEndian.Uint32(data[60:64])
		if int(peOffset)+4 > len(data) {
			return fmt.Errorf("PE offset out of range")
		}
		if data[peOffset] != 'P' || data[peOffset+1] != 'E' || data[peOffset+2] != 0 || data[peOffset+3] != 0 {
			return fmt.Errorf("not a valid PE binary")
		}
		// Machine type at peOffset+4
		machine := binary.LittleEndian.Uint16(data[peOffset+4 : peOffset+6])
		switch machine {
		case 0x8664: // AMD64
			if runtime.GOARCH != "amd64" {
				return fmt.Errorf("AMD64 binary on %s host", runtime.GOARCH)
			}
		case 0xAA64: // ARM64
			if runtime.GOARCH != "arm64" {
				return fmt.Errorf("ARM64 binary on %s host", runtime.GOARCH)
			}
		default:
			return fmt.Errorf("unsupported machine type 0x%x", machine)
		}
		return nil
	}

	// Linux ELF validation
	if len(data) < 4 || data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return fmt.Errorf("not an ELF binary")
	}
	if data[4] != 2 {
		return fmt.Errorf("not a 64-bit binary")
	}
	if data[5] != 1 {
		return fmt.Errorf("not little-endian")
	}
	// OS/ABI: 0=System V (generic), 3=GNU/Linux, 0x10=Linux (Clang/LLVM)
	// 某些交叉编译器输出 ABI=0，也是合法 Linux 二进制
	osabi := data[7]
	if osabi != 0 && osabi != 3 && osabi != 0x10 {
		return fmt.Errorf("not a Linux binary (OS/ABI=%d)", osabi)
	}
	elfType := binary.LittleEndian.Uint16(data[16:18])
	if elfType != 2 && elfType != 3 {
		return fmt.Errorf("not an executable (type %d)", elfType)
	}
	machine := binary.LittleEndian.Uint16(data[18:20])
	switch machine {
	case 0x3E:
		if runtime.GOARCH != "amd64" {
			return fmt.Errorf("x86-64 binary on %s host", runtime.GOARCH)
		}
	case 0xB7:
		if runtime.GOARCH != "arm64" {
			return fmt.Errorf("ARM64 binary on %s host", runtime.GOARCH)
		}
	default:
		return fmt.Errorf("unsupported architecture (0x%x)", machine)
	}
	return nil
}
// upgradeLogger writes upgrade step logs to install_dir/ddns_upgrade.log
// (v1.5.30 M1: 与批处理脚本统一日志文件, 方便排查)
// v1.6.36 M7: 缓存文件句柄 — 升级流程中 write→close→open 重复 20+ 次,
// 现改为 Open 一次缓存, 避免每行日志都 Open/Close 的开销
var (
	upgradeLogFile   *os.File
	upgradeLogFileMu sync.Mutex
)
func upgradeLogger(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	upgradeLogFileMu.Lock()
	if upgradeLogFile == nil {
		f, err := os.OpenFile(filepath.Join(agentBaseDir, "ddns_upgrade.log"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			upgradeLogFileMu.Unlock()
			return
		}
		upgradeLogFile = f
	}
	n, writeErr := fmt.Fprintf(upgradeLogFile, "[%s] %s\n", time.Now().UTC().Format("15:04:05 UTC"), msg)
	upgradeLogFileMu.Unlock()
	if writeErr != nil {
		log.Printf("[upgrade] 升级日志写入失败: %v (wrote %d bytes)", writeErr, n)
	}
}

func selfUpgrade(cfg *model.AgentConfig, update *model.AgentUpdate) error {
	// v1.6.45 L2: defer 关闭升级日志文件句柄 (进程 os.Exit 前确保刷盘)
	defer func() {
		upgradeLogFileMu.Lock()
		if upgradeLogFile != nil {
			upgradeLogFile.Close()
			upgradeLogFile = nil
		}
		upgradeLogFileMu.Unlock()
	}()

	exePath, _ := os.Executable()
	if exePath == "" {
		return fmt.Errorf("cannot find self")
	}

	// Resolve symlink to real path (Linux: /usr/local/bin/node-agent → /opt/ddns-manager/node-agent-v1.5.2-linux-amd64)
	if realPath, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = realPath
	}

	url := update.URL
	if !strings.HasPrefix(url, "http") {
		url = strings.TrimRight(cfg.ManagerURL, "/") + "/" + strings.TrimLeft(url, "/")
	}

	upgradeLogger("======== 自升级开始 v1.5.26+ ========")
	upgradeLogger("版本=%s exe=%s url=%s", update.Version, exePath, url)

	// v1.5.33: 防止降级 — 推送版本号 ≤ 当前版本时跳过
	if update.Version != "" && version != "" && version != "dev" {
		if cmp := model.CompareSemVer(update.Version, version); cmp <= 0 {
			upgradeLogger("跳过升级: 推送版本 v%s ≤ 当前版本 v%s (拒绝降级)", update.Version, version)
			log.Printf("[upgrade] 拒绝降级 v%s→v%s", version, update.Version)
			return errDowngradeBlocked
		}
	}
	tmpFile := exePath + ".new"

	// 带重试的下载（3 次，递增退避：2s, 4s, 6s），防止网络抖动导致升级失败后等待 5 分钟。
	// 每次迭代用独立闭包确保 defer 在迭代结束时立即执行（HTTP body / 文件句柄零泄漏）。
	// BUGFIX(C1): HTTP 非 200 不应 return — return 杀死整个重试循环，3 次重试形同虚设。
	// 改为 continue 继续下一轮，只在所有迭代耗尽后才返回最终错误。
	// v1.5.20 Fix1: 使用普通循环替代闭包，手控资源释放，避免 defer 在重试间泄漏
	var downloadErr error
	var contentLen int64
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
			upgradeLogger("下载重试 %d/3", attempt+1)
		}
		// v1.6.36 M2: 检查删除错误, 防止杀毒软件锁定文件导致 os.Create 失败
		if rmErr := os.Remove(tmpFile); rmErr != nil && !os.IsNotExist(rmErr) {
			upgradeLogger("清理临时文件失败(可能被锁定): %v", rmErr)
		}
		hc := newHTTPClient(cfg.VerifySSL, 2*time.Minute)
		resp, err := hc.Get(url)
		if err != nil {
			downloadErr = fmt.Errorf("attempt %d: %w", attempt+1, err)
			upgradeLogger("下载失败: %v", downloadErr)
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			downloadErr = fmt.Errorf("attempt %d: HTTP %d", attempt+1, resp.StatusCode)
			upgradeLogger("下载失败: %v", downloadErr)
			continue
		}
		contentLen = resp.ContentLength
		f2, err := os.Create(tmpFile)
		if err != nil {
			resp.Body.Close()
			downloadErr = fmt.Errorf("attempt %d: create tmp: %w", attempt+1, err)
			upgradeLogger("下载失败: %v", downloadErr)
			continue
		}
		n, copyErr := io.Copy(f2, io.LimitReader(resp.Body, 100<<20))
		f2.Close()
		resp.Body.Close()
		if copyErr != nil {
			downloadErr = fmt.Errorf("attempt %d: write: %w", attempt+1, copyErr)
			upgradeLogger("下载失败: %v", downloadErr)
			continue
		}
		downloadErr = nil
		upgradeLogger("下载成功 (%d 字节, Content-Length=%d)", n, contentLen)
		break
	}
	// v1.5.22 M2: 验证下载大小 >= Content-Length * 95% (原80%过于宽松, 15MB→12MB也会通过)
	if downloadErr == nil && contentLen > 0 {
		fs := fileSize(tmpFile)
		if fs > 0 && float64(fs) < float64(contentLen)*0.95 {
			upgradeLogger("下载不完整: 实际=%d Content-Length=%d", fs, contentLen)
			downloadErr = fmt.Errorf("downloaded %d bytes (expected ~%d)", fs, contentLen)
		}
	}
	if downloadErr != nil {
		upgradeLogger("下载彻底失败(3次重试用尽): %v", downloadErr)
		os.Remove(tmpFile)
		return fmt.Errorf("自升级下载: %w", downloadErr)
	}

	upgradeLogger("验证二进制...") // write before validate in case it hangs
	if err := validateAgentBinary(tmpFile); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("binary validation: %w", err)
	}

	if update.Checksum != "" {
		if actual := fileSHA256(tmpFile); actual != update.Checksum {
			os.Remove(tmpFile)
			return fmt.Errorf("checksum mismatch: want %s, got %s", update.Checksum, actual)
		}
	}

	// v1.6.30: Windows 上同时下载 upgrade_helper.exe, 防止上次升级自删除后下次缺失
	// 非关键操作 — 下载失败不阻塞升级 (replaceRunningBinary 内会降级到批处理)
	if runtime.GOOS == "windows" {
		downloadUpgradeHelper(cfg, update.Version)
	}

	upgradeLogger("开始替换二进制: %s → v%s", exePath, update.Version)
	if err := replaceRunningBinary(exePath, tmpFile, update.Version); err != nil {
		upgradeLogger("替换失败: %v", err)
		return fmt.Errorf("replace: %w", err)
	}

	// v1.6.12 C6: Windows 升级不再使用批处理
	// replaceRunningBinary 内部: sc config disabled → 启动助手 → 触发SCM标准退出
	if runtime.GOOS == "windows" {
		upgradeLogger("升级助手已调度, 触发SCM标准退出...")
		return nil
	}

	// Linux oneshot 模式: 升级后触发即时心跳，避免 DNS 更新中断 5 分钟
	restartAgentAfterUpgrade()
	upgradeLogger("替换成功! 即将退出进程...")
	os.Exit(0)
	return nil
}

func importPFXToIIS(pfxFile, bundleName, pfxPassword string, bindings []model.CertToIISBinding) bool {
	// 1. 用 certutil -importpfx 导入到 LocalMachine 证书存储 (v1.5.32: 替代不可靠的 PowerShell Import)
	// certutil 是 Windows 内置工具, 无执行策略/.NET 版本依赖, 全版本一致
	// v1.5.37: 先尝试删除旧证书(防止重复导入报错), 再导入新证书
	oldThumb, _ := extractPFXInfo(pfxFile, pfxPassword)
	if oldThumb != "" {
		exec.Command("certutil", "-delstore", "My", oldThumb).Run()
	}
	// v1.6.57: certutil 不支持环境变量传密码，仅能通过 -p 参数。openssl 路径已改用 env。
	importArgs := []string{"-importpfx", "-p", pfxPassword, "-enterprise", pfxFile}
	out, err := exec.Command("certutil", importArgs...).CombinedOutput()
	if err != nil {
		// v1.5.40: 如果密码错误(0x80070056), 尝试默认 ddns 密码兜底
		// 已知问题: 部分 Windows 节点 PFX 传输后 certutil 报告密码不匹配
		errMsg := string(out)
		if strings.Contains(errMsg, "0x80070056") || strings.Contains(errMsg, "ERROR_INVALID_PASSWORD") {
			log.Printf("[cert] certutil 密码错误(0x80070056), 尝试默认密码兜底: %s", bundleName)
			retryArgs := []string{"-importpfx", "-p", crypto.DefaultPFXPassword, "-enterprise", pfxFile}
			retryOut, retryErr := exec.Command("certutil", retryArgs...).CombinedOutput()
			if retryErr == nil {
				log.Printf("[cert] certutil ddns兜底导入成功: %s", bundleName)
				agentLog("证书部署: certutil初审密码失败, ddns兜底成功 %s", bundleName)
				// 继续执行指纹提取(用 ddns 密码)
				out = retryOut
				err = nil
			} else {
				log.Printf("[cert] certutil ddns兜底也失败 %s: %s", bundleName, strings.TrimSpace(string(retryOut)))
			}
		}
		if err != nil {
			// v1.6.17: certutil 在中文Windows输出GBK编码, 直接取hex错误码避免乱码
			ec := certutilErrorCode(errMsg)
			log.Printf("[cert] certutil -importpfx 失败 %s: %v, code=%s", bundleName, err, ec)
			agentLog("证书部署: certutil导入失败 %s: %s", bundleName, ec)
			return false
		}
	}
	log.Printf("[cert] certutil -importpfx 成功: %s", bundleName)

	// 2. 用 certutil -dump 提取指纹（格式固定，不受 PowerShell 版本/语言影响）
	// v1.5.20 L1: 合并一次 certutil -dump 同时提取指纹和 CN
	thumb, certCN := extractPFXInfo(pfxFile, pfxPassword)
	if thumb == "" {
		log.Printf("PFX 证书指纹提取失败: %s", bundleName)
		return false
	}
	log.Printf("PFX已导入: %s (指纹=%s CN=%s)", bundleName, thumb[:8]+"...", certCN)

	// 2. bind to IIS
	if len(bindings) > 0 {
		bindExplicit(thumb, bundleName, certCN, bindings)
	} else {
		autoBindExisting(thumb, certCN)
	}
	return true
}

// importToIIS converts PEM cert files to PFX, imports, and binds to IIS.
// Legacy path — used when manager sends PEM files (Linux style).
// v1.5.37: 接受 pfxPassword 参数替代硬编码 "ddns"
func importToIIS(certDir, bundleName string, bindings []model.CertToIISBinding, pfxPassword string) bool {
	certFile := filepath.Join(certDir, "fullchain.pem")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		certFile = filepath.Join(certDir, "cert.pem")
	}
	keyFile := filepath.Join(certDir, "privkey.pem")

	// 1. get SHA1 thumbprint + subject CN from cert
	openssl := filepath.Join(agentBaseDir, "openssl.exe")
	if _, err := os.Stat(openssl); os.IsNotExist(err) {
		openssl = "openssl"
	}
	fpOut, err := exec.Command(openssl, "x509", "-in", certFile, "-fingerprint", "-sha1", "-noout").Output()
	if err != nil {
		log.Printf("openssl 提取指纹失败: %v", err)
		return false
	}
	thumb := strings.TrimPrefix(strings.TrimSpace(string(fpOut)), "sha1 Fingerprint=")
	thumb = strings.TrimPrefix(thumb, "SHA1 Fingerprint=")
	thumb = strings.ReplaceAll(thumb, ":", "")
	thumb = strings.TrimSpace(thumb)
	if thumb == "" {
		log.Printf("证书指纹为空: %s", bundleName)
		return false
	}

	// also get subject CN for auto-matching
	subjOut, _ := exec.Command(openssl, "x509", "-in", certFile, "-subject", "-noout").Output()
	subject := strings.TrimSpace(string(subjOut))
	// "subject= /CN=app.example.com" → "app.example.com"
	certCN := ""
	if idx := strings.Index(subject, "CN="); idx != -1 {
		cn := subject[idx+3:]
		if space := strings.IndexAny(cn, " /,"); space != -1 {
			cn = cn[:space]
		}
		certCN = strings.ToLower(strings.TrimSpace(cn))
	}

	// 2. import to Windows cert store (LocalMachine\My) via certutil (v1.5.32: 替代 PowerShell)
	// v1.5.37: 使用 pfxPassword 替代硬编码 "ddns", 支持用户自定义密码
	pfxFile := filepath.Join(certDir, bundleName+".pfx")
	// v1.6.57 L1: 密码通过环境变量传递，不出现在进程命令行
	cmd := exec.Command(openssl, "pkcs12", "-export",
		"-in", certFile, "-inkey", keyFile, "-out", pfxFile,
		"-passout", "env:PFX_PWD")
	cmd.Env = append(os.Environ(), "PFX_PWD="+pfxPassword)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[cert] openssl PFX导出失败: %v: %s", err, string(out))
		agentLog("证书部署: openssl PFX导出失败 %s: %s", bundleName, strings.TrimSpace(string(out)))
		return false
	}
	importOut, importErr := exec.Command("certutil", "-importpfx", "-p", pfxPassword, "-enterprise", pfxFile).CombinedOutput()
	if importErr != nil {
		// v1.6.17: 仅取hex错误码, 避免中文乱码
		ec := certutilErrorCode(string(importOut))
		log.Printf("[cert] certutil -importpfx 失败 (openssl路径): %v code=%s", importErr, ec)
		agentLog("证书部署: certutil导入失败(openssl) %s: %s", bundleName, ec)
		return false
	}
	log.Printf("证书已导入: %s (指纹=%s CN=%s)", bundleName, thumb[:8]+"...", certCN)

	// 3. bind cert to IIS — explicit config or auto-discover
	if len(bindings) > 0 {
		bindExplicit(thumb, bundleName, certCN, bindings)
	} else {
		autoBindExisting(thumb, certCN)
	}
	return true
}

// ── IIS certificate binding helpers ──

// bindExplicit uses iis_cert_bindings from agent.yaml for precise multi-site control.
func bindExplicit(thumb, bundleName, certCN string, bindings []model.CertToIISBinding) {
	var matched int
	for _, b := range bindings {
		if b.BundleName != bundleName {
			continue
		}
		ip := b.IP
		if ip == "" {
			ip = "0.0.0.0"
		}
		port := b.Port
		if port == 0 {
			port = 443
		}
		appID := "{4dc3e181-e14b-4a21-b022-59fc669b0914}"
		if b.Hostname != "" {
			key := fmt.Sprintf("%s:%d", b.Hostname, port)
			exec.Command("netsh", "http", "delete", "sslcert", "hostnameport="+key).Run()
			out, err := exec.Command("netsh", "http", "add", "sslcert",
				"hostnameport="+key, "certhash="+thumb, "appid="+appID, "certstorename=MY").CombinedOutput()
			if err != nil {
				log.Printf("IIS SNI 绑定 %s 失败: %v: %s", key, err, string(out))
			} else {
				log.Printf("IIS SNI 已绑定: %s -> %s", key, bundleName)
			}
		} else {
			key := fmt.Sprintf("%s:%d", ip, port)
			exec.Command("netsh", "http", "delete", "sslcert", "ipport="+key).Run()
			out, err := exec.Command("netsh", "http", "add", "sslcert",
				"ipport="+key, "certhash="+thumb, "appid="+appID).CombinedOutput()
			if err != nil {
				log.Printf("IIS IP 绑定 %s 失败: %v: %s", key, err, string(out))
			} else {
				log.Printf("IIS IP 已绑定: %s -> %s", key, bundleName)
			}
		}
		matched++
	}
	if matched == 0 {
		log.Printf("IIS 绑定: 未找到匹配证书集 %s 的 iis_cert_bindings, 回退到自动模式", bundleName)
		autoBindExisting(thumb, certCN)
	}
}

// autoBindExisting scans existing IIS SSL bindings via netsh and updates them
// to use the new cert. Matches by cert CN → binding hostname for multi-site.
func autoBindExisting(thumb, certCN string) {
	out, err := exec.Command("netsh", "http", "show", "sslcert").Output()
	if err != nil {
		log.Printf("IIS 自动绑定: netsh 查询失败: %v", err)
		return
	}
	type sslBinding struct {
		key   string // "0.0.0.0:443" or "app.example.com:443"
		isSNI bool
		appID string
	}
	var bindings []sslBinding
	lines := strings.Split(string(out), "\n")
	var cur sslBinding
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// detect binding key
		if after, found := strings.CutPrefix(trimmed, "Hostname:port"); found {
			cur = sslBinding{isSNI: true}
			if idx := strings.Index(after, ":"); idx != -1 {
				cur.key = strings.TrimSpace(after[idx+1:])
			}
			// hostname from the key
			if idx := strings.LastIndex(cur.key, ":"); idx != -1 {
				cur.key = strings.TrimSpace(cur.key)
			}
			continue
		}
		if after, found := strings.CutPrefix(trimmed, "IP:port"); found {
			cur = sslBinding{}
			if idx := strings.Index(after, ":"); idx != -1 {
				cur.key = strings.TrimSpace(after[idx+1:])
			}
			continue
		}
		// detect appid — signals end of a binding block
		if after, found := strings.CutPrefix(trimmed, "Application ID"); found {
			cur.appID = strings.TrimSpace(strings.TrimPrefix(after, ":"))
			cur.appID = strings.TrimSpace(cur.appID)
			if cur.key != "" {
				bindings = append(bindings, cur)
			}
			cur = sslBinding{}
		}
	}

	if len(bindings) == 0 {
		log.Printf("IIS 自动绑定: 未找到现有 SSL 绑定 — 无需更新")
		return
	}

	// For IP-only bindings (no SNI): only auto-update if there are no SNI bindings
	// (suggesting a simple single-site server). Otherwise skip them.
	hasSNI := false
	for _, b := range bindings {
		if b.isSNI {
			hasSNI = true
			break
		}
	}

	var updated int
	for _, b := range bindings {
		// v1.6.0: win-acme Fits() 三级匹配: 精确(100) > 泛域名(50) > 默认(10)
		matchScore := 0
		matchReason := ""
		if b.isSNI && certCN != "" {
			host := strings.ToLower(b.key)
			if idx := strings.LastIndex(host, ":"); idx != -1 {
				host = host[:idx]
			}
			matchScore, matchReason = fitsBinding(host, certCN)
		} else if !b.isSNI && !hasSNI {
			// v1.6.9: IP绑定只在单站(仅1个IP绑定)时自动更新, 多IP绑定时跳过防误覆盖
			ipCount := 0
			for _, bb := range bindings {
				if !bb.isSNI { ipCount++ }
			}
			if ipCount > 1 {
				agentLog("证书部署: 跳过IP绑定 %s (%d个IP绑定, 防止多站点误覆盖, 请手动绑定)", b.key, ipCount)
				continue
			}
			matchScore = 10
			matchReason = "默认IP绑定(单站点)"
		}
		if matchScore == 0 {
			continue
		}
		agentLog("证书部署: IIS绑定 %s CN=%s 匹配度=%d(%s)", b.key, certCN, matchScore, matchReason)

		appID := b.appID
		if appID == "" {
			appID = "{4dc3e181-e14b-4a21-b022-59fc669b0914}"
		}
		if b.isSNI {
			exec.Command("netsh", "http", "delete", "sslcert", "hostnameport="+b.key).Run()
			out, err := exec.Command("netsh", "http", "add", "sslcert",
				"hostnameport="+b.key, "certhash="+thumb, "appid="+appID, "certstorename=MY").CombinedOutput()
			if err != nil {
				log.Printf("IIS 自动绑定 SNI %s 失败: %v: %s", b.key, err, string(out))
			} else {
				log.Printf("IIS 自动绑定 SNI: %s 已更新", b.key)
				updated++
			}
		} else {
			exec.Command("netsh", "http", "delete", "sslcert", "ipport="+b.key).Run()
			out, err := exec.Command("netsh", "http", "add", "sslcert",
				"ipport="+b.key, "certhash="+thumb, "appid="+appID).CombinedOutput()
			if err != nil {
				log.Printf("IIS 自动绑定 IP %s 失败: %v: %s", b.key, err, string(out))
			} else {
				log.Printf("IIS 自动绑定 IP: %s 已更新", b.key)
				updated++
			}
		}
	}
	log.Printf("IIS 自动绑定: %d/%d 绑定已更新 (CN=%s)", updated, len(bindings), certCN)
	if updated == 0 && len(bindings) > 0 {
		agentLog("证书部署: IIS未匹配 CN=%s 已有%d个SSL绑定但无一匹配 → 请手动绑定", certCN, len(bindings))
	}
}

// cutAnyPrefix v1.6.5: 尝试多个前缀匹配, 返回第一个匹配的 after 部分。
func cutAnyPrefix(s string, prefixes ...string) (after string, ok bool) {
	for _, p := range prefixes {
		if after, ok = strings.CutPrefix(s, p); ok {
			return
		}
	}
	return "", false
}

// fitsBinding 对齐 win-acme Fits() 三级 hostname 匹配 (v1.6.0)。
// 返回 (分数, 原因描述): 精确匹配=100, 泛域名匹配=50, 无匹配=0。
func fitsBinding(iisHost, certCN string) (int, string) {
	// 精确匹配: sub.example.com == sub.example.com
	if strings.EqualFold(iisHost, certCN) {
		return 100, "精确匹配"
	}
	// IIS泛域名绑定 *.example.com vs 证书 sub.example.com
	if strings.HasPrefix(iisHost, "*.") && !strings.HasPrefix(certCN, "*.") {
		suffix := "." + iisHost[2:]
		if strings.HasSuffix(strings.ToLower(certCN), strings.ToLower(suffix)) {
			return 50, "IIS泛域名→证书子域名"
		}
		return 0, ""
	}
	// 证书泛域名 *.example.com vs IIS绑定 sub.example.com
	if !strings.HasPrefix(iisHost, "*.") && strings.HasPrefix(certCN, "*.") {
		suffix := "." + certCN[2:]
		if strings.HasSuffix(strings.ToLower(iisHost), strings.ToLower(suffix)) {
			iisLevel := len(strings.Split(iisHost, "."))
			certLevel := len(strings.Split(certCN[2:], ".")) + 1
			if iisLevel == certLevel {
				return 90, "证书泛域名→IIS子域名(同层级)"
			}
		}
		return 0, ""
	}
	return 0, ""
}

// scanIISBindingsIfNeeded v1.6.16: 仅在证书已部署时扫描
// 判断逻辑: 证书目录有内容 → Manager已推送证书 → 需要IIS扫描
func scanIISBindingsIfNeeded(cfg *model.AgentConfig) []model.IISBoundSite {
	entries, _ := os.ReadDir(cfg.CertPath)
	if len(entries) == 0 {
		return nil
	}
	return scanIISBindings(cfg)
}

// scanIISBindings v1.6.15 C7: WebAdministration API (结构化JSON, 不受locale影响)
// netsh http show sslcert 在所有Windows版本(含Win10/Server)均可执行, 无版本兼容问题
func scanIISBindings(cfg *model.AgentConfig) []model.IISBoundSite {
	if runtime.GOOS != "windows" {
		return nil
	}

	// 1. appcmd list sites → 建立 site_id 映射
	siteMap := mapIISSites()

	// 2. WebAdministration API (v1.6.15 C7: 恢复, netsh文本解析因SYSTEM locale失败)
	// 历史教训 (见 CHANGELOG v1.6.1→v1.6.7, docs/windows-dev-notes.md):
	//   netsh http show sslcert 在SYSTEM账户下输出中文标签(IP:端口/证书哈希),
	//   英文正则解析彻底失效, chcp 437 前缀也无法可靠工作。
	//   WebAdministration API 返回结构化JSON, 不受locale/PS版本影响。
	// 非IIS服务器: 模块不存在 → Write-Host 'NO_MODULE' → 优雅降级, 不报错。
	psCmd := "Import-Module WebAdministration -ErrorAction SilentlyContinue; if (Get-Module WebAdministration) { Get-ChildItem IIS:\\SSLBindings | Where-Object { $_.Sites } | ForEach-Object { [PSCustomObject]@{ Site = if ($_.Sites.Value) { $_.Sites.Value -join ',' } else { '' }; IP = [string]$_.IPAddress; Port = $_.Port; Thumbprint = $_.Thumbprint } } | ConvertTo-Json } else { Write-Host 'NO_MODULE' }"
	out, err := exec.Command("powershell", "-Command", psCmd).CombinedOutput()
	if err != nil || len(out) == 0 {
		agentLog("IIS扫描: 不可用 (非IIS服务器或PowerShell受限)")
		return nil
	}
	if strings.Contains(string(out), "NO_MODULE") {
		agentLog("IIS扫描: WebAdministration模块未安装 (非IIS服务器, 正常)")
		return nil
	}
	type psSSLBinding struct {
		Site       string `json:"Site"`
		IP         string `json:"IP"`
		Port       int    `json:"Port"`
		Thumbprint string `json:"Thumbprint"`
	}
	var psBindings []psSSLBinding
	jsonText := strings.TrimSpace(string(out))
	if strings.HasPrefix(jsonText, "[") {
		if err := json.Unmarshal(out, &psBindings); err != nil {
			agentLog("IIS扫描: JSON解析失败: %v", err)
			return nil
		}
	} else {
		var single psSSLBinding
		if err := json.Unmarshal(out, &single); err != nil {
			agentLog("IIS扫描: JSON解析失败: %v", err)
			return nil
		}
		psBindings = append(psBindings, single)
	}
	var sites []model.IISBoundSite
	for _, pb := range psBindings {
		cur := model.IISBoundSite{
			Hostname:   pb.IP,
			Port:       pb.Port,
			Thumbprint: strings.ToLower(pb.Thumbprint),
		}
		if info, ok := siteMap[pb.Site]; ok {
			cur.SiteID = info.id
			cur.SiteName = info.name
		}
		sites = append(sites, cur)
	}

	saveIISBindingsFile(cfg, sites)
	agentLog("IIS扫描: %d个SSL绑定 (siteMap=%d个站点)", len(sites), len(siteMap))
	return sites
}

// iisSiteInfo holds parsed IIS site metadata from appcmd.
type iisSiteInfo struct {
	id   int
	name string
}

// mapIISSites v1.6.15 C7: PowerShell 包装 appcmd (SYSTEM账户必须通过PS调用)
// 非IIS服务器: appcmd.exe 不存在 → PowerShell返回空 → 空map
func mapIISSites() map[string]iisSiteInfo {
	result := map[string]iisSiteInfo{}
	psCmd := "if (Test-Path $env:SystemRoot\\System32\\inetsrv\\appcmd.exe) { & $env:SystemRoot\\System32\\inetsrv\\appcmd list sites }"
	out, err := exec.Command("powershell", "-Command", psCmd).CombinedOutput()
	if err != nil {
		return result
	}
	re := regexp.MustCompile(`SITE "([^"]+)" \(id:(\d+),bindings:([^)]+)\)`)
	for _, match := range re.FindAllStringSubmatch(string(out), -1) {
		siteName := match[1]
		siteID, _ := strconv.Atoi(match[2])
		result[siteName] = iisSiteInfo{id: siteID, name: siteName}
	}
	return result
}

// saveIISBindingsFile v1.6.1: 写入 iis_bindings.json 供本地/管理端查看绑定状态。
func saveIISBindingsFile(cfg *model.AgentConfig, sites []model.IISBoundSite) {
	path := filepath.Join(cfg.CertPath, "iis_bindings.json")
	data, _ := json.MarshalIndent(sites, "", "  ")
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Printf("[cert] 写入 iis_bindings.json 失败: %v", err)
	}
}

// extractPFXInfo 合并一次 certutil -dump 同时提取指纹和 CN。
// v1.5.20 L1: 原 extractThumbprintCertutil + extractCNFromPFX 各执行一次 certutil,
// 现合并为一次调用减少进程开销。
// v1.5.38: 增加 pfxPassword 参数 — certutil -dump 密码保护的 PFX 文件需要 -p 密码。
// Win2022 上 certutil -dump 无 -p 返回 0x80070056 (ERROR_INVALID_PASSWORD) 导致指纹提取失败。
// certutilErrRe v1.6.42 C5: 包级编译一次 + 匹配任意长度 hex (覆盖 0x2/0x5/0x80070056)
var certutilErrRe = regexp.MustCompile(`0x[0-9a-fA-F]+`)
// v1.6.50 L2: 二次匹配 Windows 符号错误名 (如 ERROR_FILE_NOT_FOUND, ERROR_ACCESS_DENIED)
var certutilWinErrRe = regexp.MustCompile(`ERROR_[A-Z_]+`)

// certutilErrorCode v1.6.17: 从certutil输出提取hex错误码, 避免中文乱码
// certutil在中文Windows输出GBK, 直接log会出现"ָ 벻 ȷ"等乱码
// v1.6.42 C5: 改用包级 regex + 匹配任意长度 hex 错误码 (不再限制恰好8位)
// v1.6.50 L2: hex错误码未命中时尝试Windows符号错误名, 提高中文乱码环境诊断能力
func certutilErrorCode(output string) string {
	if m := certutilErrRe.FindString(output); m != "" {
		return fmt.Sprintf("错误码=%s", m)
	}
	if m := certutilWinErrRe.FindString(output); m != "" {
		return fmt.Sprintf("错误=%s", m)
	}
	// 回退: 取第一行非空文本的前100字符(ASCII safe)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 100 {
			line = line[:100] + "..."
		}
		return fmt.Sprintf("输出=%s", line)
	}
	return "未知错误"
}

func extractPFXInfo(pfxFile, pfxPassword string) (thumb string, cn string) {
	out, err := exec.Command("certutil", "-dump", "-p", pfxPassword, pfxFile).CombinedOutput()
	if err != nil {
		log.Printf("[cert] certutil -dump 失败: %v", err)
		return "", ""
	}
	// v1.6.67 修复: 中文 Windows 的 certutil 输出 GBK 编码(非 UTF-8)。
	// 直接按 UTF-8 解析中文标签会因字节序列不匹配而失败
	// (sp/Win2022 实测: certutil -importpfx 成功但指纹提取失败)。
	// 先自动检测编码(GBK/GB18030/UTF-8)转为 UTF-8 再解析。
	return parsePFXInfoDump(decodeCertutilOutput(out))
}

// decodeCertutilOutput 将 certutil 输出转为 UTF-8 (自动检测 GBK/GB18030/UTF-8)。
// v1.6.67: 不用 html/charset 嗅探 — 它对无 BOM 的纯 GBK 文本检测失败(实测返回
// 空指纹)。改用: 合法 UTF-8 直接用, 否则按 GBK 解码 (中文 Windows ANSI 代码页)。
func decodeCertutilOutput(out []byte) string {
	// 1) 合法 UTF-8 (英文 Windows 或已是 UTF-8) → 原样
	if utf8.Valid(out) {
		return string(out)
	}
	// 2) 否则按 GBK/GB18030 解码 (GB18030 是 GBK 超集, 兼容全部字节)
	if b, err := simplifiedchinese.GB18030.NewDecoder().Bytes(out); err == nil {
		return string(b)
	}
	// 3) 回退: 原样返回
	return string(out)
}

// parsePFXInfoDump 解析 certutil -dump 输出，提取叶子证书(带私钥)的指纹和 CN。
// v1.6.65 修复 — 与 netsh 中文 locale 问题同源(参考 v1.6.6 cutAnyPrefix 方案):
//  1) 中文 Windows 输出中文标签 (证书哈希(sha1):/使用者:)，同时匹配中英文
//  2) certutil -dump 按"证书 N"分块，根证书在前(无私钥)。必须提取含
//     Provider/提供程序 行的叶子证书块，否则 delstore/IIS 绑定会用根证书
//     指纹导致绑定失败 (生产 sp.lanxun.pro / Win2022 实测)
func parsePFXInfoDump(output string) (thumb string, cn string) {
	lines := strings.Split(output, "\n")
	isBlockStart := func(l string) bool {
		return strings.HasPrefix(l, "================ 证书") ||
			strings.HasPrefix(l, "================ Cert")
	}
	var curThumb, curCN string
	hasKey := false
	flush := func() {
		// 仅取第一个带私钥(叶子)证书块
		if hasKey && curThumb != "" && thumb == "" {
			thumb = curThumb
			cn = curCN
		}
	}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if isBlockStart(line) {
			flush()
			curThumb, curCN, hasKey = "", "", false
			continue
		}
		if after, ok := cutAnyPrefix(line, "Cert Hash(sha1):", "证书哈希(sha1):"); ok {
			// 去除空格: 英文版可能按字节空格分隔 (3c 34 e3), 中文版为连续 hex
			curThumb = strings.ReplaceAll(strings.TrimSpace(after), " ", "")
		} else if after, ok := cutAnyPrefix(line, "Subject:", "使用者:"); ok {
			subject := strings.TrimSpace(after)
			if idx := strings.Index(subject, "CN="); idx != -1 {
				c := subject[idx+3:]
				if comma := strings.IndexByte(c, ','); comma != -1 {
					c = c[:comma]
				}
				curCN = strings.ToLower(strings.TrimSpace(c))
			}
		} else if strings.Contains(line, "提供程序 =") || strings.Contains(line, "Provider =") ||
			strings.Contains(line, "密钥容器 =") || strings.Contains(line, "Key Container =") {
			// 叶子证书(带私钥)标志
			hasKey = true
		}
	}
	flush()
	// 兜底: 输出异常(无 Provider 标志)时回退第一个指纹，兼容旧行为
	if thumb == "" {
		for _, raw := range lines {
			line := strings.TrimSpace(raw)
			if after, ok := cutAnyPrefix(line, "Cert Hash(sha1):", "证书哈希(sha1):"); ok {
				thumb = strings.ReplaceAll(strings.TrimSpace(after), " ", "")
				break
			}
		}
	}
	return
}

// ── Windows Trust (MotW removal) ──
func main() {
	// v1.5.31 M3: 所有日志带时间戳+文件名行号，便于排查
	// v1.6.45 L3: 加 log.LUTC 统一 UTC+0 时区 — Agent 上报/Manager 存储均使用 UTC,
	// Web UI 按设置页时区转换显示。Agent 上报内容中附加的 "UTC" 标记用于区分原始时间与展示时间
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.LUTC)
	heartbeat := flag.Bool("heartbeat", false, "send single heartbeat (for systemd timer)")
	daemon := flag.Bool("daemon", false, "run as daemon (for Windows Service)")
	showVersion := flag.Bool("version", false, "show version")
	installDir := flag.String("dir", "", "installation directory (default: /opt/ddns-manager or C:\\ddns-manager)")
	flag.Parse()

	if *installDir != "" {
		setBaseDir(*installDir)
	}
	// v1.5.33: Windows Service 时跳过, 延迟到 SCM handler goroutine 中初始化
	// 确保 main() 对 SCM 绝对零阻塞
	// v1.6.10 M6: ensureSymlink 在 Windows 下是 no-op (Windows 不使用符号链接),
	// Windows daemon 的 detectInstallDir+initAgentLog 在 svc_windows.go 中补执行
	if !(*daemon && runtime.GOOS == "windows") {
		detectInstallDir() // v1.5.32: 自适应寻找安装目录 (兼容旧路径)
		initAgentLog()
		ensureSymlink()   // v1.5.37: 启动时符号链接自愈, 防止离线
	}

	if *showVersion {
		fmt.Printf("node-agent v%s\nPublisher: Lanxun CO.,Ltd.\n", version)
		return
	}

	if *heartbeat {
		cfg, err := loadConfig(agentConfigPath)
		if err != nil {
			log.Fatalf("加载配置失败: %v — 请先运行安装器", err)
		}
		if err := doHeartbeat(cfg); err != nil {
			log.Printf("心跳失败: %v", err)
			os.Exit(1)
		}
		return
	}

	if *daemon {
		cfg, err := loadConfig(agentConfigPath)
		if err != nil {
			log.Fatalf("加载配置失败: %v", err)
		}
		if runtime.GOOS == "windows" {
			runWindowsService(cfg)
		} else {
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, os.Interrupt)
			log.Printf("[daemon] %s 已启动, 版本=%s", runtime.GOOS, version)
			// v1.5.20 H1+v1.6.29 M5: 心跳失败后 30s×3 快速重试 (认证失败不重试)
			doHeartbeatWithRetry := func() {
				if err := doHeartbeat(cfg); err != nil {
					log.Printf("[daemon] 心跳失败: %v", err)
					// v1.6.29 M5: 认证失败 (401/403) 不重试 — 凭证无效, 重试无意义
					if errors.Is(err, errAuthFailed) {
						log.Printf("[daemon] 认证失败, 跳过重试 (请检查节点凭证或审批状态)")
						return
					}
					for i := 0; i < 3; i++ {
						select {
						case <-time.After(30 * time.Second):
							log.Printf("[daemon] 第%d次重试...", i+1)
							if err := doHeartbeat(cfg); err != nil {
								log.Printf("[daemon] 重试%d失败: %v", i+1, err)
								// 重试中发现认证失败时立即停止
								if errors.Is(err, errAuthFailed) {
									log.Printf("[daemon] 认证失败(重试中), 停止重试")
									return
								}
							} else {
								log.Printf("[daemon] 重试%d成功", i+1)
								return
							}
						case <-ch:
							return
						}
					}
					log.Printf("[daemon] 3次重试均失败, 等待下一轮心跳周期")
				}
			}
			// 启动时立即执行一次心跳 + DNS 更新，不等 5 分钟
			go func() {
				log.Println("[daemon] 执行首次心跳...")
				doHeartbeatWithRetry()
			}()
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					doHeartbeatWithRetry()
				case <-ch:
				log.Println("[daemon] 正在关闭...")
				// v1.5.29 M2: 等待正在运行的 DNS 更新完成，防止 goroutine 泄漏
				waitStart := time.Now()
				for dnsUpdateRunning.Load() && time.Since(waitStart) < 30*time.Second {
					time.Sleep(200 * time.Millisecond)
				}
				if dnsUpdateRunning.Load() {
					log.Println("[daemon] DNS 更新超时未完成，强制退出")
				}
				return
				}
			}
		}
		return
	}

	fmt.Println("ddns-manager Node Agent")
	fmt.Printf("Version: %s  |  Publisher: Lanxun CO.,Ltd.\n\n", version)
	fmt.Println("Usage:")
	fmt.Println("  node-agent -heartbeat              (single heartbeat, for systemd timer)")
	fmt.Println("  node-agent -daemon                 (daemon mode, 5min internal timer)")
	fmt.Println("  node-agent -daemon -dir /custom    (daemon from custom install path)")
	fmt.Println("  node-agent -version                (show version)")
	fmt.Println()
	fmt.Println("  Install: use the separate ddns-installer binary")
	fmt.Println("    curl -fsSL MANAGER/bin/install.sh | sh")
}


