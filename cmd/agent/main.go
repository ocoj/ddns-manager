// node-agent — heartbeat agent for ddns-manager
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/kk/ddns-manager/internal/crypto"
	"github.com/kk/ddns-manager/internal/model"
	"gopkg.in/yaml.v3"
)

// version is set at build time via -ldflags "-X main.version=x.y.z"
var version = "dev"

// dnsUpdater is the global DNS updater instance (initialized once via sync.Once)
var (
	dnsUpdater     *DNSUpdater
	dnsUpdaterOnce sync.Once
)

// base paths — defaults, overridable via -dir flag
var (
	agentBaseDir    string
	agentConfigPath string
)

func init() {
	if runtime.GOOS == "windows" {
		agentBaseDir = `C:\ddns-manager`
	} else {
		agentBaseDir = "/opt/ddns-manager"
	}
	agentConfigPath = filepath.Join(agentBaseDir, "agent.yaml")
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
	done := make(chan DNSStatus, 1)
	go func() {
		done <- u.Run()
	}()

	select {
	case status := <-done:
		return status
	case <-time.After(timeout):
		log.Printf("[dns] DNS更新超时 (%v), 使用上次已知状态", timeout)
		return u.Status()
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
	return &cfg, nil
}

func generatePassword() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("随机数生成失败: %v", err) // 不可恢复 — 安全关键路径
	}
	return hex.EncodeToString(b)
}

// collectHardware gathers system info for heartbeat reporting.
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
	certHashes := collectCertHashes(cfg)

	// 3. Build heartbeat request
	req := model.HeartbeatReq{
		NodeID:      cfg.NodeID,
		Fingerprint: cfg.Fingerprint,
		Status: model.NodeStatus{
			AgentVersion: version,
			IPv4:         status.IPv4,
			IPv6:         status.IPv6,
			CertHashes:   certHashes,
			DDNSHealth: &model.DDNSHealthInfo{
				Running:   status.Running,
				LastOK:    status.LastOK,
				LastError: status.LastError,
				LogLine:   status.LastLine(),
			},
		},
		ConfigHash: dnsUpdater.ConfigHash(),
		Logs:       dnsUpdater.RecentLogs(10),
		Hardware:   collectHardware(),
	}

	// 3. Send heartbeat
	resp := sendHeartbeat(cfg, req)
	if resp == nil {
		return fmt.Errorf("心跳失败")
	}

	// 4. Config hot-reload + cache to disk for next heartbeat
	if resp.Config != nil && resp.Config.YAML != "" {
		if resp.Config.Hash != req.ConfigHash {
			if err := dnsUpdater.ApplyConfig([]byte(resp.Config.YAML)); err != nil {
				log.Printf("配置应用失败: %v", err)
			} else {
				// Cache encrypted config for next oneshot run (AES-256-GCM)
				// 加密失败时拒绝写入，绝不以明文存储 DNS 凭据
				os.MkdirAll(filepath.Dir(configCachePath()), 0700)
				cacheData, encErr := crypto.Encrypt([]byte(resp.Config.YAML),
					getConfigCacheKey(cfg.Password, cfg.Fingerprint))
				if encErr != nil {
					log.Printf("[config] 缓存加密失败，拒绝写入明文: %v", encErr)
					// 不写入 disk — 明文 DNS 凭据泄露风险不可接受
					// 下次心跳会重新尝试加密并缓存
				} else {
					os.WriteFile(configCachePath(), []byte(cacheData), 0600)
				}
				// re-run DNS update with new config (with timeout, don't block heartbeat)
				go func() { runDNSUpdateWithTimeout(dnsUpdater, 2*time.Minute) }()
			}
		}
	}

	// 5. Cert deploy (keep v1 logic)
	applyCertUpdates(cfg, resp.CertUpdates)

	// 6. Config error — node config rendering failed on manager side
	if resp.ConfigError != "" {
		log.Printf("[config] 管理端配置渲染失败: %s", resp.ConfigError)
	}

	// 7. Self-upgrade (keep v1 logic)
	if resp.AgentUpdate != nil {
		if err := selfUpgrade(cfg, resp.AgentUpdate); err != nil {
			log.Printf("自升级失败: %v", err)
		}
	}

	return nil
}

// sendHeartbeat sends a heartbeat request and returns the response.
func sendHeartbeat(cfg *model.AgentConfig, req model.HeartbeatReq) *model.HeartbeatResp {
	body, err := json.Marshal(req)
	if err != nil {
		log.Printf("心跳 序列化失败: %v", err)
		return nil
	}
	token := base64.StdEncoding.EncodeToString([]byte(cfg.NodeID + ":" + cfg.Password))

	client := newHTTPClient(cfg.VerifySSL, 30*time.Second)

	httpReq, err := http.NewRequest("POST", cfg.ManagerURL+"/api/heartbeat", bytes.NewReader(body))
	if err != nil {
		log.Printf("心跳 创建请求失败: %v", err)
		return nil
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("心跳 发送请求失败: %v", err)
		return nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20)) // 50MB (多证书场景)
	if err != nil {
		log.Printf("心跳 读取响应失败: %v", err)
		return nil
	}
	var hr model.HeartbeatResp
	if err := json.Unmarshal(respBody, &hr); err != nil {
		log.Printf("心跳 解析响应失败: %v", err)
		return nil
	}
	if !hr.OK {
		log.Printf("心跳 被服务端拒绝: %s", hr.Error)
		return nil
	}
	return &hr
}

// applyCertUpdates processes certificate updates from heartbeat response.
// Deploys cert files → updates IIS bindings (Windows) → reloads services → recycles app pools.
func applyCertUpdates(cfg *model.AgentConfig, updates []*model.CertUpdate) {
	if len(updates) == 0 {
		return
	}
	key := crypto.DeriveKey(cfg.Password, cfg.Fingerprint, "cert-transport")
	for _, cu := range updates {
		path := cu.TargetPath
		if path == "" {
			path = cfg.CertPath
		}
		if path == "" {
			continue
		}
		os.MkdirAll(path, 0o700)
		hasModernPFX := false
		hasLegacyPFX := false
		legacyPFXFile := "" // cert.pfx path (LegacyDES, 全版本兼容)
		modernPFXFile := "" // cert-modern.pfx path (PBES2+AES-256, Win10+)
		for name, ct := range cu.Files {
			plain, err := crypto.Decrypt(ct, key)
			if err != nil {
				log.Printf("[cert] 解密失败 %s/%s: %v", cu.BundleName, name, err)
				continue
			}
			tmp := filepath.Join(path, name+".new")
			dst := filepath.Join(path, name)
			os.WriteFile(tmp, plain, 0o600)
			os.Rename(tmp, dst)
			lower := strings.ToLower(name)
			if strings.HasSuffix(lower, ".pfx") {
				if strings.Contains(lower, "modern") {
					hasModernPFX = true
					modernPFXFile = dst
				} else {
					hasLegacyPFX = true
					legacyPFXFile = dst
				}
			}
		}
		// H5: 先写证书文件，IIS 绑定失败则不写 .cert_hash，下次心跳重试

		// On Windows, auto-import cert to IIS after deployment
		// 双PFX: 优先 Modern (AES-256) → 降级 Legacy (3DES)
		iisOK := true
		if runtime.GOOS == "windows" {
			// 优先尝试 Modern PFX (Win10 1809+, 更强加密)
			if hasModernPFX && modernPFXFile != "" {
				if _, err := os.Stat(modernPFXFile); err == nil {
					iisOK = importPFXToIIS(modernPFXFile, cu.BundleName, cfg.IISCertBindings)
					recycleIISAppPools()
				}
			} else if hasLegacyPFX && legacyPFXFile != "" {
				// 降级到 Legacy PFX (Win7/Win2016 兼容)
				if _, err := os.Stat(legacyPFXFile); err == nil {
					iisOK = importPFXToIIS(legacyPFXFile, cu.BundleName, cfg.IISCertBindings)
					recycleIISAppPools()
				}
			} else {
				// 无 PFX → 走 openssl 兼容路径
				iisOK = importToIIS(path, cu.BundleName, cfg.IISCertBindings)
				recycleIISAppPools()
			}
		}

		// Process service reload hints from Manager
		for _, svc := range cu.ReloadServices {
			reloadService(svc)
		}

		// H5: 仅在 IIS 绑定成功(或非Windows)后才写入 .cert_hash
		// 如果 IIS 绑定失败，保留旧 hash，下次心跳 Manager 会重新推送
		if iisOK {
			hashFile := filepath.Join(path, ".cert_hash")
			os.WriteFile(hashFile, []byte(cu.CertHash), 0o600)
			log.Printf("[cert] 已部署: %s -> %s", cu.BundleName, path)
		} else {
			log.Printf("[cert] 证书文件已写入但 IIS 绑定失败: %s, 下次心跳重试", cu.BundleName)
		}
	}
}

// reloadService reloads or restarts a system service after cert deployment.
// Supports systemd service names (Linux) and Windows service names.
func reloadService(svc string) {
	if runtime.GOOS == "windows" {
		// Windows: try appcmd recycle first (IIS), then net stop/start
		if strings.Contains(strings.ToLower(svc), "iis") || strings.Contains(strings.ToLower(svc), "w3svc") {
			recycleIISAppPools()
			return
		}
		// Generic Windows service restart
		exec.Command("sc", "stop", svc).Run()
		time.Sleep(2 * time.Second)
		out, err := exec.Command("sc", "start", svc).CombinedOutput()
		if err != nil {
			log.Printf("[cert] 服务重启失败 %s: %v: %s", svc, err, string(out))
		} else {
			log.Printf("[cert] 服务已重启: %s", svc)
		}
		return
	}
	// Linux: try reload first (nginx -s reload, systemctl reload), then restart
	out, err := exec.Command("systemctl", "reload", svc).CombinedOutput()
	if err != nil {
		// reload not supported, try restart
		out2, err2 := exec.Command("systemctl", "restart", svc).CombinedOutput()
		if err2 != nil {
			log.Printf("[cert] 服务重载失败 %s: %v: %s", svc, err2, string(out2))
		} else {
			log.Printf("[cert] 服务已重启: %s", svc)
		}
	} else {
		log.Printf("[cert] 服务已重载: %s", svc)
		_ = out
	}
}

// recycleIISAppPools recycles all IIS application pools so the new certificate
// takes effect immediately. Uses appcmd (IIS 7+) with fallback to iisreset.
func recycleIISAppPools() {
	// Preferred: recycle individual app pools (less disruptive than iisreset)
	appcmd := filepath.Join(os.Getenv("SystemRoot"), "System32", "inetsrv", "appcmd.exe")
	if _, err := os.Stat(appcmd); err == nil {
		out, err := exec.Command(appcmd, "list", "apppool", "/xml").Output()
		if err == nil {
			// Parse app pool names and recycle each
			for _, line := range strings.Split(string(out), "\n") {
				if idx := strings.Index(line, "APPPOOL.NAME="); idx != -1 {
					start := idx + len("APPPOOL.NAME=") + 1
					end := strings.IndexByte(line[start:], '"')
					if end > 0 {
						poolName := line[start : start+end]
						exec.Command(appcmd, "recycle", "apppool", poolName).Run()
						log.Printf("[cert] IIS 应用池已回收: %s", poolName)
					}
				}
			}
			return
		}
	}
	// Fallback: full IIS reset (disruptive but guaranteed)
	out, err := exec.Command("iisreset", "/noforce").CombinedOutput()
	if err != nil {
		log.Printf("[cert] IIS 重置失败: %v: %s", err, string(out))
	} else {
		log.Printf("[cert] IIS 已重置 (iisreset)")
	}
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

// collectCertHashes scans the cert directory for .cert_hash files deployed by Manager.
// Returns map[deploy_path]hash for heartbeat reporting.
func collectCertHashes(cfg *model.AgentConfig) map[string]string {
	result := map[string]string{}
	if cfg.CertPath == "" {
		return result
	}
	// walk the cert directory for .cert_hash marker files
	// 限制深度: 证书目录通常 ≤3 层，超过 5 层停止 (防止 CertPath 误配为 /)
	// 超时保护: NFS 卡住时 30s 后取消 Walk（filepath.Walk 不支持 context，
	// 通过 goroutine + channel 实现超时控制）
	maxDepth := 5
	done := make(chan struct{}, 1)
	go func() {
		filepath.Walk(cfg.CertPath, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				log.Printf("[cert] 遍历目录错误 %s: %v", p, err)
				return nil
			}
			if info.IsDir() {
				rel, _ := filepath.Rel(cfg.CertPath, p)
				if rel != "." && strings.Count(rel, string(os.PathSeparator)) >= maxDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if info.Name() == ".cert_hash" {
				data, err := os.ReadFile(p)
				if err == nil {
					result[filepath.Dir(p)] = strings.TrimSpace(string(data))
				}
			}
			return nil
		})
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		log.Printf("[cert] 证书目录遍历超时 (30s): %s (可能是NFS挂载卡住)", cfg.CertPath)
	}
	return result
}

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

func selfUpgrade(cfg *model.AgentConfig, update *model.AgentUpdate) error {
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

	log.Printf("自升级: 正在下载 %s 从 %s", update.Version, url)
	tmpFile := exePath + ".new"

	// 带重试的下载（3 次，递增退避：2s, 4s, 6s），防止网络抖动导致升级失败后等待 5 分钟。
	// 每次迭代用独立闭包确保 defer 在迭代结束时立即执行（HTTP body / 文件句柄零泄漏）。
	// BUGFIX(C1): HTTP 非 200 不应 return — return 杀死整个重试循环，3 次重试形同虚设。
	// 改为 continue 继续下一轮，只在所有迭代耗尽后才返回最终错误。
	var downloadErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
			log.Printf("自升级: 重试 %d/3 ...", attempt+1)
		}
		downloadErr = func() error {
			hc := newHTTPClient(cfg.VerifySSL, 2*time.Minute)
			resp, err := hc.Get(url)
			if err != nil {
				return fmt.Errorf("attempt %d: %w", attempt+1, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("attempt %d: HTTP %d", attempt+1, resp.StatusCode)
			}
			f2, err := os.Create(tmpFile)
			if err != nil {
				return fmt.Errorf("attempt %d: create tmp: %w", attempt+1, err)
			}
			defer f2.Close()
			if _, err := io.Copy(f2, io.LimitReader(resp.Body, 100<<20)); err != nil {
				return fmt.Errorf("attempt %d: write: %w", attempt+1, err)
			}
			return nil
		}()
		if downloadErr == nil {
			break // 成功
		}
		log.Printf("自升级: %v", downloadErr)
	}
	if downloadErr != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("自升级下载: %w", downloadErr)
	}

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

	log.Printf("自升级: 正在替换 %s → v%s", exePath, update.Version)
	if err := replaceRunningBinary(exePath, tmpFile, update.Version); err != nil {
		return fmt.Errorf("replace: %w", err)
	}

	// Linux oneshot 模式: 升级后触发即时心跳，避免 DNS 更新中断 5 分钟
	if runtime.GOOS != "windows" {
		restartAgentAfterUpgrade()
	}

	// replaceRunningBinary handles platform-specific replacement.
	// This line should never be reached on Windows (CreateProcess detaches).
	log.Printf("自升级: 即将退出")
	os.Exit(0)
	return nil
}

func importPFXToIIS(pfxFile, bundleName string, bindings []model.CertToIISBinding) bool {
	// 1. import PFX to Windows cert store
	escapedPath := strings.ReplaceAll(pfxFile, "'", "''")
	ps := fmt.Sprintf(
		`$pfx = Get-Content '%s' -AsByteStream -Raw;`+
			`$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2;`+
			`$cert.Import($pfx, 'ddns', 'DefaultKeySet');`+
			`$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine');`+
			`$store.Open('ReadWrite'); $store.Add($cert); $store.Close();`,
		escapedPath)
	out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).CombinedOutput()
	if err != nil {
		log.Printf("PFX导入到证书存储失败: %v: %s", err, string(out))
		return false
	}

	// 2. 用 certutil -dump 提取指纹（格式固定，不受 PowerShell 版本/语言影响）
	thumb := extractThumbprintCertutil(pfxFile)
	certCN := extractCNFromPFX(pfxFile)
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
func importToIIS(certDir, bundleName string, bindings []model.CertToIISBinding) bool {
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

	// 2. import to Windows cert store (LocalMachine\My)
	pfxFile := filepath.Join(certDir, bundleName+".pfx")
	cmd := exec.Command(openssl, "pkcs12", "-export",
		"-in", certFile, "-inkey", keyFile, "-out", pfxFile,
		"-passout", "pass:ddns")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("openssl PFX导出失败: %v: %s", err, string(out))
		return false
	}
	escapedPFX := strings.ReplaceAll(pfxFile, "'", "''")
	ps := `$pfx = Get-Content '` + escapedPFX + `' -AsByteStream -Raw;` +
		`$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2;` +
		`$cert.Import($pfx, 'ddns', 'DefaultKeySet');` +
		`$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine');` +
		`$store.Open('ReadWrite'); $store.Add($cert); $store.Close()`
	if out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).CombinedOutput(); err != nil {
		log.Printf("证书导入到存储失败: %v: %s", err, string(out))
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
		// match: cert CN matches binding hostname
		// IP-only bindings only matched when no SNI bindings exist (simple server)
		match := false
		if b.isSNI && certCN != "" {
			host := strings.ToLower(b.key)
			if idx := strings.LastIndex(host, ":"); idx != -1 {
				host = host[:idx]
			}
			match = host == certCN || strings.HasSuffix(host, "."+certCN) || strings.HasSuffix(certCN, "."+host)
		} else if !b.isSNI && !hasSNI {
			match = true
		}
		if !match {
			continue
		}

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
}

// extractThumbprintCertutil 使用 certutil 提取 PFX 证书指纹。
// certutil -dump 输出格式固定（不受语言/版本影响），比 PowerShell Write-Host 解析更可靠:
//   Cert Hash(sha1): a1b2c3d4e5f6789012345678901234567890abcd
func extractThumbprintCertutil(pfxFile string) string {
	out, err := exec.Command("certutil", "-dump", pfxFile).CombinedOutput()
	if err != nil {
		log.Printf("[cert] certutil -dump 失败: %v", err)
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Cert Hash(sha1):") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Cert Hash(sha1):"))
		}
	}
	return ""
}

// extractCNFromPFX 通过 certutil 解析 PFX 文件获取 CN（通用名称）。
// certutil 输出中 Issuer/Subject 行格式固定:
//   Subject: CN=app.example.com, O=Org, ...
func extractCNFromPFX(pfxFile string) string {
	out, err := exec.Command("certutil", "-dump", pfxFile).CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Subject:") {
			subject := strings.TrimPrefix(line, "Subject:")
			subject = strings.TrimSpace(subject)
			if idx := strings.Index(subject, "CN="); idx != -1 {
				cn := subject[idx+3:]
				if comma := strings.IndexByte(cn, ','); comma != -1 {
					cn = cn[:comma]
				}
				return strings.ToLower(strings.TrimSpace(cn))
			}
		}
	}
	return ""
}

// ── Windows Trust (MotW removal) ──
func main() {
	log.SetFlags(log.LstdFlags) // 所有日志带时间戳 (2009/01/23 01:23:45)
	heartbeat := flag.Bool("heartbeat", false, "send single heartbeat (for systemd timer)")
	daemon := flag.Bool("daemon", false, "run as daemon (for Windows Service)")
	showVersion := flag.Bool("version", false, "show version")
	installDir := flag.String("dir", "", "installation directory (default: /opt/ddns-manager or C:\\ddns-manager)")
	flag.Parse()

	if *installDir != "" {
		setBaseDir(*installDir)
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
			// 启动时立即执行一次心跳 + DNS 更新，不等 5 分钟
			// （daemon 重启后若等首个 tick，DNS 会中断 5 分钟）
			go func() {
				log.Println("[daemon] 执行首次心跳...")
				if err := doHeartbeat(cfg); err != nil {
					log.Printf("首次心跳失败: %v", err)
				}
			}()
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if err := doHeartbeat(cfg); err != nil {
						log.Printf("心跳失败: %v", err)
					}
				case <-ch:
					log.Println("[daemon] 正在关闭")
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


