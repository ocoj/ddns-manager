package model

import (
	"strconv"
	"strings"
	"time"
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
	Hostname   string `json:"hostname"`             // SNI hostname 或 IP
	Port       int    `json:"port"`                 // 端口号
	Thumbprint string `json:"thumbprint"`           // SHA1 指纹 (IIS 证书哈希)
	BundleName string `json:"bundle_name,omitempty"` // 匹配到的 bundle 名称
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
}

type DNSKeyRecord struct {
	Name            string   `json:"name"`              // 用户自定义名称 (e.g. "阿里云-生产")
	Provider        string   `json:"provider"`          // ddns-go 提供商 (e.g. "alidns")
	AccessKeyID     string   `json:"access_key_id"`
	AccessKeySecret string   `json:"access_key_secret"`
	UpdatedAt       string   `json:"updated_at"`
	UsedByNodes     []string `json:"used_by_nodes"`
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
}

type IPv4Config struct {
	Enable       bool     `json:"enable"`
	GetType      string   `json:"gettype"`
	URL          string   `json:"url"`
	NetInterface string   `json:"netinterface"`
	Cmd          string   `json:"cmd"`
	Domains      []string `json:"domains"`
}

type IPv6Config struct {
	Enable       bool     `json:"enable"`
	GetType      string   `json:"gettype"`
	URL          string   `json:"url"`
	NetInterface string   `json:"netinterface"`
	Cmd          string   `json:"cmd"`
	IPv6Reg      string   `json:"ipv6reg"`
	Domains      []string `json:"domains"`
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

// KnownDNSProviders returns the canonical list of supported DNS provider names.
// Must be kept in sync with agent/dns_updater.go:providerRegistry.
func KnownDNSProviders() []string {
	return []string{
		"alidns", "aliesa", "tencentcloud", "trafficroute", "dnspod",
		"dnsla", "cloudflare", "huaweicloud", "callback", "baiducloud",
		"porkbun", "godaddy", "namecheap", "namesilo", "vercel",
		"dynadot", "dynv6", "spaceship", "nowcn", "eranet",
		"tnethk", "gcore", "edgeone", "nsone", "name_com",
		"rainyun", "hipmdnsmgr", "cloudns",
	}
}

// IsKnownDNSProvider checks if a provider name is known.
func IsKnownDNSProvider(name string) bool {
	for _, p := range KnownDNSProviders() {
		if p == name {
			return true
		}
	}
	return false
}
