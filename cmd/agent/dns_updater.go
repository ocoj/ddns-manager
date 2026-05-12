// dns_updater.go — embedded DDNS updater using ddns-go DNS providers.
// Uses ddns-go's provider registry to make real DNS API calls.
// IP detection is delegated to ddns-go's built-in methods (url/netInterface/cmd).

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	ddnsconfig "github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/dns"
	"github.com/jeessy2/ddns-go/v6/util"
	"gopkg.in/yaml.v3"
)

// DNSStatus holds the result of the last DNS update run.
type DNSStatus struct {
	Running   bool      // DNSUpdater is running
	LastOK    bool      // last update succeeded
	LastError string    // last error message (if any)
	IPv4      string    // current public IPv4
	IPv6      string    // current public IPv6
	LastRun   time.Time // timestamp of last run
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

	if u.cfg == nil || len(u.cfg.DnsConf) == 0 {
		u.status.LastRun = time.Now()
		u.status.LastOK = false
		u.status.LastError = "等待管理端下发DNS配置（节点可能未审批）"
		return u.status
	}

	u.status.LastOK = true
	u.status.LastError = ""

	for _, dc := range u.cfg.DnsConf {
		// Create the appropriate DNS provider
		provider := newProvider(dc.DNS.Name)
		if provider == nil {
			u.status.LastOK = false
			u.status.LastError = fmt.Sprintf("unsupported DNS provider: %s", dc.DNS.Name)
			u.logBuf.Write(fmt.Sprintf("不支持的DNS提供商: %s", dc.DNS.Name))
			log.Printf("[dns] 不支持的DNS提供商: %s", dc.DNS.Name)
			continue
		}

		// Init provider — this detects IPs and prepares domains
		ipv4cache := &util.IpCache{}
		ipv6cache := &util.IpCache{}
		provider.Init(&dc, ipv4cache, ipv6cache)

		// Execute DNS updates — provider handles query + create/update
		domains := provider.AddUpdateDomainRecords()

		// Extract detected IPs for heartbeat reporting
		if domains.Ipv4Addr != "" {
			u.status.IPv4 = domains.Ipv4Addr
		}
		if domains.Ipv6Addr != "" {
			u.status.IPv6 = domains.Ipv6Addr
		}

		// Check results — any failure marks the whole run as failed
		allOK := true
		for _, d := range domains.Ipv4Domains {
			if d.UpdateStatus == ddnsconfig.UpdatedFailed {
				allOK = false
				u.logBuf.Write(fmt.Sprintf("IPv4更新失败: %s", d.String()))
			}
		}
		for _, d := range domains.Ipv6Domains {
			if d.UpdateStatus == ddnsconfig.UpdatedFailed {
				allOK = false
				u.logBuf.Write(fmt.Sprintf("IPv6更新失败: %s", d.String()))
			}
		}

		if !allOK {
			u.status.LastOK = false
			u.status.LastError = "部分域名更新失败"
			log.Printf("[dns] DNS更新失败 (提供商 %s)", dc.DNS.Name)
		} else if len(domains.Ipv4Domains) > 0 || len(domains.Ipv6Domains) > 0 {
			u.logBuf.Write("DNS更新完成")
		}
	}

	u.status.LastRun = time.Now()
	return u.status
}

// providerRegistry maps ddns-go DNS provider names to factory functions.
// Must be kept in sync with ddns-go's dns/index.go:RunOnce() switch.
// TestProviderRegistryCompleteness validates this automatically.
var providerRegistry = map[string]func() dns.DNS{
	"alidns":       func() dns.DNS { return &dns.Alidns{} },
	"aliesa":       func() dns.DNS { return &dns.Aliesa{} },
	"tencentcloud": func() dns.DNS { return &dns.TencentCloud{} },
	"trafficroute": func() dns.DNS { return &dns.TrafficRoute{} },
	"dnspod":       func() dns.DNS { return &dns.Dnspod{} },
	"dnsla":        func() dns.DNS { return &dns.Dnsla{} },
	"cloudflare":   func() dns.DNS { return &dns.Cloudflare{} },
	"huaweicloud":  func() dns.DNS { return &dns.Huaweicloud{} },
	"callback":     func() dns.DNS { return &dns.Callback{} },
	"baiducloud":   func() dns.DNS { return &dns.BaiduCloud{} },
	"porkbun":      func() dns.DNS { return &dns.Porkbun{} },
	"godaddy":      func() dns.DNS { return &dns.GoDaddyDNS{} },
	"namecheap":    func() dns.DNS { return &dns.NameCheap{} },
	"namesilo":     func() dns.DNS { return &dns.NameSilo{} },
	"vercel":       func() dns.DNS { return &dns.Vercel{} },
	"dynadot":      func() dns.DNS { return &dns.Dynadot{} },
	"dynv6":        func() dns.DNS { return &dns.Dynv6{} },
	"spaceship":    func() dns.DNS { return &dns.Spaceship{} },
	"nowcn":        func() dns.DNS { return &dns.Nowcn{} },
	"eranet":       func() dns.DNS { return &dns.Eranet{} },
	"tnethk":       func() dns.DNS { return &dns.Tnethk{} },
	"gcore":        func() dns.DNS { return &dns.Gcore{} },
	"edgeone":      func() dns.DNS { return &dns.EdgeOne{} },
	"nsone":        func() dns.DNS { return &dns.NSOne{} },
	"name_com":     func() dns.DNS { return &dns.NameCom{} },
	"rainyun":      func() dns.DNS { return &dns.Rainyun{} },
	"hipmdnsmgr":   func() dns.DNS { return &dns.HiPMDnsMgr{} },
	"cloudns":      func() dns.DNS { return &dns.ClouDNS{} },
}

// newProvider creates a DNS provider by name.
func newProvider(name string) dns.DNS {
	if fn, ok := providerRegistry[name]; ok {
		return fn()
	}
	return nil
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
	mu   sync.Mutex
	buf  []string
	pos  int
	size int
}

func newLogBuffer(size int) *LogBuffer {
	return &LogBuffer{buf: make([]string, size), size: size}
}

func (lb *LogBuffer) Write(msg string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.buf[lb.pos%lb.size] = time.Now().Format("15:04:05") + " " + msg
	lb.pos++
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
	// lb.pos grows without bound (wraps at 2^63 ~ 10^19 writes at 5min/heartbeat).
	// The subtraction lb.pos-n is safe: the loop is bounded to n iterations.
	start := lb.pos - n
	if start < 0 {
		start = 0
	}
	for i := start; i < lb.pos; i++ {
		result = append(result, lb.buf[i%lb.size])
	}
	return result
}
