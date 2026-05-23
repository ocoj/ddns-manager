package model

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/kk/ddns-manager/internal/provider"
)

type DDNSHealthInfo struct {
	Running         bool     `json:"running"`
	LastOK          bool     `json:"last_ok"`
	LastError       string   `json:"last_error,omitempty"`
	LastErrorDetail string   `json:"last_error_detail,omitempty"` // v1.5.33: ddns-go API 详细错误
	FailedDomains   []string `json:"failed_domains,omitempty"` // v1.5.29 H1: 具体失败域名列表
	LogLine         string   `json:"log_line,omitempty"`
	Status          string   `json:"status,omitempty"`
	StatusMsg       string   `json:"status_msg,omitempty"`
	// v1.6.11 B2: IP获取状态
	IPv4OK      bool   `json:"ipv4_ok,omitempty"`
	IPv6OK      bool   `json:"ipv6_ok,omitempty"`
	IPv4Msg     string `json:"ipv4_msg,omitempty"`
	IPv6Msg     string `json:"ipv6_msg,omitempty"`
	// v1.6.46: IPv4/IPv6 启用标志 — Manager 据此区分"主动关"和"意外失败"
	IPv4Enabled bool   `json:"ipv4_enabled,omitempty"`
	IPv6Enabled bool   `json:"ipv6_enabled,omitempty"`
}

type HeartbeatReq struct {
	NodeID      string        `json:"node_id"`
	Fingerprint string        `json:"fingerprint"`
	Status      NodeStatus    `json:"status"`
	ConfigHash  string        `json:"config_hash,omitempty"`
	Logs        []string      `json:"logs,omitempty"`           // DNS 更新日志
	AgentLogs   []string      `json:"agent_logs,omitempty"`     // Agent 操作日志（升级/证书/配置/心跳）
	Hardware    *HardwareInfo `json:"hardware,omitempty"`
}

type NodeStatus struct {
	AgentVersion  string            `json:"agent_version"`
	CertPath      string            `json:"cert_path,omitempty"`     // 客户端实际证书目录
	CertHashes    map[string]string `json:"cert_hashes,omitempty"`
	IPv4          string            `json:"ipv4"`
	IPv6          string            `json:"ipv6"`
	DDNSHealth    *DDNSHealthInfo   `json:"ddns_health,omitempty"`
	CertErrors    []string          `json:"cert_errors,omitempty"`   // v1.5.29 H5: 证书部署失败详情
	IISBoundSites []IISBoundSite    `json:"iis_bound_sites,omitempty"` // v1.6.0: IIS 绑定快照
}

// IISBoundSite v1.6.0: Agent 上报的 IIS SSL 绑定快照, 用于多站点证书识别。
type IISBoundSite struct {
	Hostname   string `json:"hostname"`               // SNI hostname 或 IP
	Port       int    `json:"port"`                   // 端口号
	Thumbprint string `json:"thumbprint"`             // SHA1 指纹 (IIS 证书哈希)
	SiteID     int    `json:"site_id,omitempty"`      // v1.6.0: IIS 站点 ID
	SiteName   string `json:"site_name,omitempty"`    // IIS 站点名称
	BundleName string `json:"bundle_name,omitempty"`   // 匹配到的 bundle 名称
}

type HeartbeatResp struct {
	OK          bool          `json:"ok"`
	Timestamp   string        `json:"timestamp"`
	CertUpdates []*CertUpdate `json:"cert_updates,omitempty"`
	AgentUpdate *AgentUpdate  `json:"agent_update,omitempty"`
	Config      *ConfigPush   `json:"config,omitempty"`
	ConfigError string        `json:"config_error,omitempty"` // 配置渲染失败原因
	Error       string        `json:"error,omitempty"`
}

type ConfigPush struct {
	YAML string `json:"yaml"`
	Hash string `json:"hash"`
}

type NodeRecord struct {
	Fingerprint  string        `json:"fingerprint"`
	PasswordHash string        `json:"password_hash"`
	CreatedAt    time.Time     `json:"created_at"`
	LastSeen     time.Time     `json:"last_seen"`
	Approved     bool          `json:"approved"`            // 审批状态: 注册后需管理员审批才能接收配置/证书推送
	CertBindings []CertBinding `json:"cert_bindings"`
	ConfigYAML   string        `json:"config_yaml,omitempty"`
	ConfigHash   string        `json:"config_hash,omitempty"`
	ConfigSentAt time.Time     `json:"config_sent_at,omitempty"`
	Tags         []string      `json:"tags,omitempty"`
	Notes        string        `json:"notes,omitempty"`
	Status       NodeStatus    `json:"status,omitempty"`
	Hardware     *HardwareInfo `json:"hardware,omitempty"`
	// v1.6.46: DNS 连续失败计数器 — 防 DNS API 瞬态故障误标 ERR
	// 心跳中 LastOK=false 时 +1, LastOK=true 时清零
	// 连续 ≥2 次失败才标记 ERR, 单次失败标记 WARN
	DNSConsecutiveFailures int `json:"dns_consecutive_failures,omitempty"`
}

type DNSKeyRecord struct {
	Name            string   `json:"name"`              // 用户自定义名称 (e.g. "阿里云-生产")
	Provider        string   `json:"provider"`          // ddns-go 提供商 (e.g. "alidns")
	AccessKeyID     string   `json:"access_key_id"`
	AccessKeySecret string   `json:"access_key_secret"`
	UpdatedAt       string   `json:"updated_at"`
	UsedByNodes     []string `json:"used_by_nodes"`
}

type DomainConfig struct {
	Domain     string `json:"domain"`
	DNSKeyName string `json:"dns_key_name,omitempty"` // 空=继承顶层默认
}

// UnmarshalJSON 兼容旧格式（字符串数组）和新格式（对象数组）。
func (d *DomainConfig) UnmarshalJSON(data []byte) error {
	// 旧格式: "example.com" → {domain:"example.com"}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		d.Domain = s
		return nil
	}
	// 新格式: {"domain":"example.com","dns_key_name":"阿里云-生产"}
	type alias DomainConfig
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*d = DomainConfig(a)
	return nil
}

type CertBinding struct {
	BundleName     string   `json:"bundle_name"`
	DeployPath     string   `json:"deploy_path"`
	ReloadServices []string `json:"reload_services,omitempty"` // 证书部署后需重载的服务 (systemd/windows service names)
}

type CertUpdate struct {
	CertHash            string            `json:"cert_hash"`
	BundleName          string            `json:"bundle_name"`
	Files               map[string]string `json:"files"`
	TargetPath          string            `json:"target_path"`
	ReloadServices      []string          `json:"reload_services,omitempty"`
	PFXPassword         string            `json:"pfx_password,omitempty"`     // PFX 证书密码（用户自设，非硬编码）
}

type AgentUpdate struct {
	Version  string `json:"version"`
	URL      string `json:"url"`
	Checksum string `json:"checksum"`
}

// HardwareInfo v1.6.45 C1/M3: 结构体定义包含身份信息(主机名/OS/网卡)和资源指标。
// Agent 侧 collectHardware() 仅填充身份信息+网卡 — CPU/内存/磁盘字段为管理端专用,
// 由 internal/server/access_stats.go 通过 sysinfo 包采集 (仅 Linux 管理端部署)。
// Agent 心跳上报的 hardware 对象中这些资源字段保持零值。
type HardwareInfo struct {
	Hostname    string         `json:"hostname"`
	OS          string         `json:"os"`
	Arch        string         `json:"arch"`
	Interfaces  []NetInterface `json:"interfaces"`
	CPUPercent  float64        `json:"cpu_percent,omitempty"`
	MemoryUsed  uint64         `json:"memory_used,omitempty"`
	MemoryTotal uint64         `json:"memory_total,omitempty"`
	DiskUsed    uint64         `json:"disk_used,omitempty"`
	DiskTotal   uint64         `json:"disk_total,omitempty"`
}

type NetInterface struct {
	Name string `json:"name"`
	MAC  string `json:"mac"`
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

type NodeConfigRequest struct {
	DNSKeyName   string        `json:"dns_key_name"`
	DnsProvider  string        `json:"dns_provider"`
	TTL          string        `json:"ttl"`
	IPv4         IPv4Config    `json:"ipv4"`
	IPv6         IPv6Config    `json:"ipv6"`
	CertBindings []CertBinding `json:"cert_bindings"`
	// v1.6.48: 多 DNS 配置卡片 (替代顶层 ipv4/ipv6/dns_key_name)
	DnsConfs []DnsConfItem `json:"dns_confs,omitempty"`
}

// DnsConfItem 单张 DNS 配置卡片 — 独立 DNS Key、IPv4/IPv6 获取方式、域名、TTL
type DnsConfItem struct {
	Name   string     `json:"name"`             // 卡片名称 (e.g. "阿里云-主")
	DnsKey string     `json:"dns_key"`          // 引用的 DNS Key 名称
	IPv4   IPv4Config `json:"ipv4"`
	IPv6   IPv6Config `json:"ipv6"`
	TTL    string     `json:"ttl"`
}

type IPv4Config struct {
	Enable       bool           `json:"enable"`
	GetType      string         `json:"gettype"`
	URL          string         `json:"url"`
	NetInterface string         `json:"netinterface"`
	Cmd          string         `json:"cmd"`
	Domains      []DomainConfig `json:"domains"`
}

type IPv6Config struct {
	Enable       bool           `json:"enable"`
	GetType      string         `json:"gettype"`
	URL          string         `json:"url"`
	NetInterface string         `json:"netinterface"`
	Cmd          string         `json:"cmd"`
	IPv6Reg      string         `json:"ipv6reg"`
	Domains      []DomainConfig `json:"domains"`
}

// CertToIISBinding maps a cert bundle to an IIS HTTPS binding (Windows only).
type CertToIISBinding struct {
	BundleName string `json:"bundle_name" yaml:"bundle_name"` // matches cert bundle name from manager
	Hostname   string `json:"hostname" yaml:"hostname"`       // SNI hostname (empty = IP-only binding)
	IP         string `json:"ip" yaml:"ip"`                   // default "0.0.0.0"
	Port       int    `json:"port" yaml:"port"`               // default 443
}

// AgentConfig is the shared node agent configuration.
// Used by both installer and agent; IISCertBindings is Windows-only (empty on Linux).
type AgentConfig struct {
	ManagerURL      string             `json:"manager_url" yaml:"manager_url"`
	NodeID          string             `json:"node_id" yaml:"node_id"`
	Fingerprint     string             `json:"fingerprint" yaml:"fingerprint"`
	Password        string             `json:"password" yaml:"password"`
	CertPath        string             `json:"cert_path" yaml:"cert_path"`
	PFXPassword     string             `json:"pfx_password" yaml:"pfx_password"` // 默认 PFX 密码（可被证书级覆盖）
	VerifySSL       bool               `json:"verify_ssl" yaml:"verify_ssl"`
	IISCertBindings []CertToIISBinding `json:"iis_cert_bindings,omitempty" yaml:"iis_cert_bindings,omitempty"`
}

// CompareSemVer 比较两个语义化版本号 a vs b。
// 返回 -1 (a<b), 0 (a==b), 1 (a>b)。
// 自动去除 v 前缀，支持 pre-release 后缀 (如 1.5.10-beta1 → 1.5.10)。
// v1.5.34 H2: 提取为公共函数，消除 agent 和 store 中重复实现的行为发散风险。
// SanitizeCertDirName 将泛域名证书名中的 * 替换为 _，确保目录名跨平台合法。
// v1.6.50: 从 cmd/agent 和 internal/server 重复定义中提取，统一为一处维护。
func SanitizeCertDirName(name string) string {
	return strings.ReplaceAll(name, "*", "_")
}

func CompareSemVer(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")
	parseVer := func(v string) []int {
		parts := strings.Split(v, ".")
		nums := make([]int, 0, 3)
		for _, p := range parts {
			n, _ := strconv.Atoi(strings.SplitN(p, "-", 2)[0])
			nums = append(nums, n)
		}
		for len(nums) < 3 {
			nums = append(nums, 0)
		}
		return nums[:3]
	}
	aa := parseVer(a)
	bb := parseVer(b)
	for i := 0; i < 3; i++ {
		if aa[i] < bb[i] {
			return -1
		}
		if aa[i] > bb[i] {
			return 1
		}
	}
	return 0
}

// IsKnownDNSProvider v1.6.30 M1 (DEPRECATED): 委托给 provider.IsKnown(), 不再返回空实现
// v1.6.29 H1 标记废弃但实现仍是 name != "" 假验证 — 现改为委托给单一真相源
func IsKnownDNSProvider(name string) bool {
	return provider.IsKnown(name)
}
