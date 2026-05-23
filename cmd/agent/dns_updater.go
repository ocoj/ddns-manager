// dns_updater.go — embedded DDNS updater using ddns-go DNS providers.
// Uses ddns-go's provider registry to make real DNS API calls.
// IP detection is delegated to ddns-go's built-in methods (url/netInterface/cmd).

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	ddnsconfig "github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
	"github.com/kk/ddns-manager/internal/provider"
	"gopkg.in/yaml.v3"
)

// DNSStatus holds the result of the last DNS update run.
type DNSStatus struct {
	Running         bool      // DNSUpdater is running
	LastOK          bool      // last update succeeded
	LastError       string    // last error message (if any)
	LastErrorDetail string    // v1.5.33: 最近一条详细错误 (ddns-go API 响应原文, 最多500字)
	FailedDomains   []string  // v1.5.29 H1: 具体失败域名列表
	IPv4            string    // current public IPv4
	IPv6            string    // current public IPv6
	IPv4Enabled     bool      // v1.6.11 B2: DNS配置中IPv4是否启用
	IPv6Enabled     bool      // v1.6.11 B2: DNS配置中IPv6是否启用
	IPv4OK          bool      // v1.6.11 B2: IPv4 IP获取是否成功
	IPv6OK          bool      // v1.6.11 B2: IPv6 IP获取是否成功
	IPv4Msg         string    // v1.6.11 B2: IPv4状态说明
	IPv6Msg         string    // v1.6.11 B2: IPv6状态说明
	LastRun         time.Time // timestamp of last run
}

// LastLine returns error line for health reporting.
func (s DNSStatus) LastLine() string {
	if s.LastError != "" {
		return s.LastError
	}
	return ""
}

// DNSUpdater wraps ddns-go DNS providers for DNS record management.
type DNSUpdater struct {
	mu     sync.Mutex
	cfg    *ddnsconfig.Config // current ddns-go config from Manager
	status DNSStatus
	logBuf *LogBuffer // memory ring buffer (50 entries)
}

// NewDNSUpdater creates a DNSUpdater with default (empty) config.
func NewDNSUpdater() *DNSUpdater {
	u := &DNSUpdater{
		cfg:    &ddnsconfig.Config{},
		logBuf: newLogBuffer(50),
	}
	u.status.Running = true
	return u
}

// Run executes one DNS update cycle. Called before each heartbeat.
// Uses ddns-go's DNS provider infrastructure to make real API calls.
func (u *DNSUpdater) Run() DNSStatus {
	u.mu.Lock()
	defer u.mu.Unlock()

	// v1.6.46: 所有 IPv4/IPv6 状态字段在函数入口统一重置, 避免 DnsConf 空时
	// 早期返回携带上次运行残留值 (如 IPv4Enabled=true 但实际已无配置)
	u.status.IPv4OK = false
	u.status.IPv6OK = false
	u.status.IPv4Msg = ""
	u.status.IPv6Msg = ""
	u.status.IPv4Enabled = false
	u.status.IPv6Enabled = false

	if u.cfg == nil || len(u.cfg.DnsConf) == 0 {
		u.status.LastRun = time.Now()
		u.status.LastOK = false
		u.status.LastError = "等待管理端下发DNS配置（节点可能未审批）"
		// v1.6.46: IPv4/IPv6 字段已在入口重置, 早期返回携带零值而非过期数据
		return u.status
	}

	u.status.LastOK = true
	u.status.LastError = ""
	u.status.FailedDomains = nil

	// v1.6.11 B2: 在循环前检测配置中是否启用了IPv4/IPv6
	for _, dc := range u.cfg.DnsConf {
		if dc.Ipv4.Enable { u.status.IPv4Enabled = true }
		if dc.Ipv6.Enable { u.status.IPv6Enabled = true }
	}

	// v1.5.30 H4 + v1.6.10 C1: allOK + allFailedDomains 在循环内累积, 循环外统一赋值 status。
	// segErrors 记录每段DnsConf的独立错误 (供 LastErrorDetail 使用)
	allOK := true
	var allFailedDomains []string
	type segErr struct {
		provider string
		domains  []string
		detail   string
	}
	var segErrors []segErr
	var lastAPIErr string // v1.6.44 C1: DNS API 实际错误，用于域名级失败日志

	for _, dc := range u.cfg.DnsConf {
		// Create the appropriate DNS provider (v1.6.28 M1: 统一注册表)
		provider := provider.NewProvider(dc.DNS.Name)
		if provider == nil {
			allOK = false
			msg := fmt.Sprintf("unsupported DNS provider: %s", dc.DNS.Name)
			u.logBuf.Write(fmt.Sprintf("不支持的DNS提供商: %s", dc.DNS.Name))
			log.Printf("[dns] 不支持的DNS提供商: %s", dc.DNS.Name)
			segErrors = append(segErrors, segErr{provider: dc.DNS.Name, detail: msg})
			continue
		}

		// Init provider — this detects IPs and prepares domains
		ipv4cache := &util.IpCache{}
		ipv6cache := &util.IpCache{}

		// v1.5.33: 临时截获 log 输出, 捕获 ddns-go API 详细错误
		var detailBuf bytes.Buffer
		origWriter := log.Writer()
		log.SetOutput(io.MultiWriter(origWriter, &detailBuf))
		// v1.6.28 H8: 闭包内 defer 确保 provider.Init() 内部 panic+recover 后 log 输出也能恢复
		// 外层 defer 只在 Run() 返回时执行, 闭包内 defer 在 Init 调用后立即执行
		func() {
			defer log.SetOutput(origWriter)
			provider.Init(&dc, ipv4cache, ipv6cache)
		}()

		// Execute DNS updates — provider handles query + create/update
		domains := provider.AddUpdateDomainRecords()

		// 解析截获的 log 输出 (Init 时 log 已由闭包恢复)
		// v1.5.34 H1: 精确匹配 ddns-go API 错误 — 优先 JSON 错误码/结构化日志，其次已知错误模式
		var errLines []string
		for _, line := range strings.Split(detailBuf.String(), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// 精确匹配: ddns-go 结构化错误 (level=error) 或 JSON API 错误响应
			isError := strings.Contains(line, "level=error") ||
				(strings.Contains(line, `"Code"`) && !strings.Contains(line, `"Success"`)) ||
				strings.Contains(line, "InvalidAccessKeyId") ||
				strings.Contains(line, "AccessDenied") ||
				strings.Contains(line, "SignatureDoesNotMatch") ||
				strings.Contains(line, "RequestLimitExceeded") ||
				strings.Contains(line, "DomainRecordDuplicate")
			if isError {
				errLines = append(errLines, line)
			}
		}
		if len(errLines) > 0 {
			// 截断到 500 字符, 防止超长错误消息
			detail := strings.Join(errLines, " | ")
			if len(detail) > 500 {
				detail = detail[:500] + "..."
			}
			// v1.6.44 C1: 保存API错误详情供后续域名级失败日志使用
			lastAPIErr = detail
			// v1.6.33 P2: 每段错误独立记录 — 移除有缺陷的 len(segErrors) < len(DnsConf) 条件
			// 原条件在"不支持的provider"提前占位时可能导致后续段的错误被静默丢弃
			segErrors = append(segErrors, segErr{provider: dc.DNS.Name, detail: detail})
			u.logBuf.Write(fmt.Sprintf("API错误详情(%s): %s", dc.DNS.Name, detail))
		}

		// Extract detected IPs for heartbeat reporting
		// v1.5.29 M1: 多DNS配置段时取第一个非空IP，不覆盖
		if domains.Ipv4Addr != "" && u.status.IPv4 == "" {
			u.status.IPv4 = domains.Ipv4Addr
		}
		if domains.Ipv6Addr != "" && u.status.IPv6 == "" {
			u.status.IPv6 = domains.Ipv6Addr
		}

		// Check results — any failure marks the whole run as failed
		// v1.5.29 H1: 收集失败域名详情，后续上报到 Manager
		// v1.5.30 H4: 失败域名追加到外层累积列表，不覆盖
		var segFailed []string
		var segFailedDetail []string
		for _, d := range domains.Ipv4Domains {
			if d.UpdateStatus == ddnsconfig.UpdatedFailed {
				allOK = false
				domainStr := d.String()
				// v1.6.44 C1: DNS失败时附带 ddns-go API 实际错误详情
				if lastAPIErr != "" {
					u.logBuf.Write(fmt.Sprintf("IPv4更新失败: %s — %s", domainStr, lastAPIErr))
					segFailedDetail = append(segFailedDetail, domainStr+": "+lastAPIErr)
				} else {
					u.logBuf.Write(fmt.Sprintf("IPv4更新失败: %s", domainStr))
					segFailedDetail = append(segFailedDetail, domainStr)
				}
				segFailed = append(segFailed, domainStr)
			}
		}
		for _, d := range domains.Ipv6Domains {
			if d.UpdateStatus == ddnsconfig.UpdatedFailed {
				allOK = false
				domainStr := d.String()
				if lastAPIErr != "" {
					u.logBuf.Write(fmt.Sprintf("IPv6更新失败: %s — %s", domainStr, lastAPIErr))
					segFailedDetail = append(segFailedDetail, domainStr+": "+lastAPIErr)
				} else {
					u.logBuf.Write(fmt.Sprintf("IPv6更新失败: %s", domainStr))
					segFailedDetail = append(segFailedDetail, domainStr)
				}
				segFailed = append(segFailed, domainStr)
			}
		}
		allFailedDomains = append(allFailedDomains, segFailed...)

		if len(segFailed) > 0 {
			// v1.6.10 C1: 仅记录日志, 状态在循环外统一赋值
			// v1.6.44 C1: DNS失败时附带 ddns-go API 实际错误原因
			segErrors = append(segErrors, segErr{provider: dc.DNS.Name, domains: segFailed,
				detail: strings.Join(segFailedDetail, "; ")})
			log.Printf("[dns] DNS更新失败 (提供商 %s): %s", dc.DNS.Name, strings.Join(segFailedDetail, ", "))
		}
	}

	// v1.6.10 C1+H1: 循环外统一赋值 status, 防止多段配置时中间状态覆盖
	u.status.LastOK = allOK
	if allOK {
		u.status.LastError = ""
		u.status.LastErrorDetail = ""
		u.status.FailedDomains = nil
		if len(u.cfg.DnsConf) > 0 {
			u.logBuf.Write("DNS更新完成")
		}
	} else {
		u.status.LastError = fmt.Sprintf("DNS更新失败(%d段): %s", len(u.cfg.DnsConf), strings.Join(allFailedDomains, ", "))
		u.status.FailedDomains = allFailedDomains
		// 拼接所有段的独立错误详情
		var detailParts []string
		for _, se := range segErrors {
			if se.detail != "" {
				detailParts = append(detailParts, fmt.Sprintf("[%s] %s", se.provider, se.detail))
			} else if len(se.domains) > 0 {
				detailParts = append(detailParts, fmt.Sprintf("[%s] failed=%s", se.provider, strings.Join(se.domains, ",")))
			}
		}
		u.status.LastErrorDetail = strings.Join(detailParts, " | ")
		if len(u.status.LastErrorDetail) > 500 {
			u.status.LastErrorDetail = u.status.LastErrorDetail[:500] + "..."
		}
	}

// v1.6.30 H6: 无论 DNS 更新成功与否, IP 已获取就设置 IPv4OK/IPv6OK
	// DNS 记录更新失败不等于 IP 获取失败 (原逻辑误标 IP 状态)
	u.status.IPv4Msg = buildIPMsg(u.status.IPv4, u.status.IPv4Enabled)
	u.status.IPv6Msg = buildIPMsg(u.status.IPv6, u.status.IPv6Enabled)
	if u.status.IPv4 != "" { u.status.IPv4OK = true }
	if u.status.IPv6 != "" { u.status.IPv6OK = true }

	// v1.6.10 M1 + v1.6.11 B2: DNS 更新结果持久化, 区分IP状态
	if allOK {
		agentLog("[dns] 更新完成: ipv4=%s(%s) ipv6=%s(%s)",
			u.status.IPv4, u.status.IPv4Msg, u.status.IPv6, u.status.IPv6Msg)
	} else {
		agentLog("[dns] 更新失败: %s", u.status.LastError)
	}

	// v1.5.31 H3: 失败域名持久化到 ddns_errors.log, 防止 Agent 崩溃丢失内存日志
	// v1.5.34 M1: 增加 10MB 轮转, 保留 3 个历史文件
	// v1.6.10 H4: 关键错误详情也写入, 不再依赖心跳上报
	if len(allFailedDomains) > 0 {
		path := filepath.Join(agentBaseDir, "ddns_errors.log")
		// 轮转: >10MB 时重命名为 ddns_errors.N.log (保留 3 个)
		if fi, statErr := os.Stat(path); statErr == nil && fi.Size() > 10<<20 {
			for i := 3; i >= 1; i-- {
				old := filepath.Join(agentBaseDir, fmt.Sprintf("ddns_errors.%d.log", i))
				if i < 3 {
					next := filepath.Join(agentBaseDir, fmt.Sprintf("ddns_errors.%d.log", i+1))
					os.Rename(old, next)
				} else {
					os.Remove(old)
				}
			}
			os.Rename(path, filepath.Join(agentBaseDir, "ddns_errors.1.log"))
		}
		if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			fmt.Fprintf(f, "%s DNS更新失败: %s\n", time.Now().Format(time.RFC3339), strings.Join(allFailedDomains, ", "))
			f.Close()
		}
	}

	u.status.LastRun = time.Now()
	return u.status
}

// buildIPMsg v1.6.11 B2: 构建IP获取状态描述信息
func buildIPMsg(ip string, enabled bool) string {
	if !enabled {
		return "未开启"
	}
	if ip == "" {
		return "获取失败"
	}
	return "已获取"
}

// ============== Config management ==============

// ApplyConfig hot-reloads the ddns-go config from Manager-pushed YAML.
func (u *DNSUpdater) ApplyConfig(yamlData []byte) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	var cfg ddnsconfig.Config
	if err := yaml.Unmarshal(yamlData, &cfg); err != nil {
		return fmt.Errorf("config parse: %w", err)
	}
	u.cfg = &cfg
	u.logBuf.Write("DNS配置已更新")
	log.Printf("[config] 配置已热加载 (%d 条DNS配置)", len(cfg.DnsConf))
	return nil
}

// ConfigHash returns the SHA256 hash of the current config.
func (u *DNSUpdater) ConfigHash() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cfg == nil {
		return ""
	}
	data, err := yaml.Marshal(u.cfg)
	if err != nil {
		log.Printf("[dns] ConfigHash 序列化失败: %v", err)
		return ""
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Status returns a copy of the current DNS status.
func (u *DNSUpdater) Status() DNSStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.status
}

// RecentLogs returns N recent log entries.
func (u *DNSUpdater) RecentLogs(n int) []string {
	return u.logBuf.Recent(n)
}

// PeekRecentLogs v1.6.46 H7: 只返回上次确认上报之后的新日志条目, 不消耗 buffer。
// 心跳失败时条目保留, 下次 Peek 重发。心跳成功后调用 CommitRecentLogs 前移游标。
func (u *DNSUpdater) PeekRecentLogs(n int) []string {
	return u.logBuf.Peek(n)
}

// CommitRecentLogs 确认 Peek 返回的日志已成功上报, 前移游标防止重复。
func (u *DNSUpdater) CommitRecentLogs() {
	u.logBuf.Commit()
}

// LastLogLine returns the most recent log line.
func (u *DNSUpdater) LastLogLine() string {
	lines := u.logBuf.Recent(1)
	if len(lines) > 0 {
		return lines[0]
	}
	return ""
}

// ============== Log Buffer ==============

// LogBuffer is a thread-safe ring buffer for log lines.
type LogBuffer struct {
	mu      sync.Mutex
	buf     []string
	pos     int
	size    int
	peekPos int // v1.6.46 H7: 已确认上报位置 (Commit 前移)
}

func newLogBuffer(size int) *LogBuffer {
	return &LogBuffer{buf: make([]string, size), size: size}
}

func (lb *LogBuffer) Write(msg string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	// v1.6.30 H3+v1.6.39: 使用显式 UTC 标记替代 "Z", 对非技术用户更直观
	lb.buf[lb.pos%lb.size] = time.Now().UTC().Format("2006-01-02 15:04:05 UTC") + " " + msg
	lb.pos++
}

// WriteRaw v1.6.28 M5: 追加原始消息 (不含新时间戳), 用于 Drain 后恢复保留原时间戳
func (lb *LogBuffer) WriteRaw(msg string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.buf[lb.pos%lb.size] = msg
	lb.pos++
}

// Clear empties the log buffer.
func (lb *LogBuffer) Clear() {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.buf = make([]string, lb.size)
	lb.pos = 0
}

// Len returns the number of entries currently in the buffer.
func (lb *LogBuffer) Len() int {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	total := lb.pos
	if total > lb.size {
		total = lb.size
	}
	return total
}

// Drain returns all buffered entries and clears the buffer atomically.
// v1.5.22 H2: 心跳成功时一次性取出 + 清空，避免丢日志。
func (lb *LogBuffer) Drain() []string {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	total := lb.pos
	if total > lb.size {
		total = lb.size
	}
	result := make([]string, 0, total)
	start := lb.pos - total
	if start < 0 {
		start = 0
	}
	for i := start; i < lb.pos; i++ {
		result = append(result, lb.buf[i%lb.size])
	}
	lb.buf = make([]string, lb.size)
	lb.pos = 0
	return result
}

func (lb *LogBuffer) Recent(n int) []string {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	total := lb.pos
	if total > lb.size {
		total = lb.size
	}
	if n > total {
		n = total
	}
	result := make([]string, 0, n)
	start := lb.pos - n
	if start < 0 {
		start = 0
	}
	for i := start; i < lb.pos; i++ {
		result = append(result, lb.buf[i%lb.size])
	}
	return result
}

// Peek v1.6.46 H7: 返回 peekPos 之后的新日志最多 n 条, 不动游标不消耗 buffer。
// Commit 成功后游标前移, 心跳失败则 Peek 下次返回相同的条目 (自动重传)。
// 若 ring buffer 已覆盖 peekPos, 退到最早有效位置。
func (lb *LogBuffer) Peek(n int) []string {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	total := lb.pos
	if total > lb.size {
		total = lb.size
	}
	oldest := lb.pos - total
	if oldest < 0 {
		oldest = 0
	}
	start := lb.peekPos
	if start < oldest {
		start = oldest // peekPos 被环形覆盖, 退到最早有效位置
	}
	if start >= lb.pos {
		return nil // 无新条目
	}
	count := lb.pos - start
	if count > n {
		count = n
	}
	result := make([]string, 0, count)
	for i := start; i < start+count; i++ {
		result = append(result, lb.buf[i%lb.size])
	}
	return result
}

// Commit 确认 Peek 返回的日志已成功上报, peekPos 前移到当前位置。
// 心跳成功后调用; 失败时跳过 → 下次 Peek 自动重传相同条目。
func (lb *LogBuffer) Commit() {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.peekPos = lb.pos
}
