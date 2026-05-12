package model

import "time"

type DDNSHealthInfo struct {
	Running   bool   `json:"running"`
	LastOK    bool   `json:"last_ok"`
	LastError string `json:"last_error,omitempty"`
	LogLine   string `json:"log_line,omitempty"`
	Status    string `json:"status,omitempty"`
	StatusMsg string `json:"status_msg,omitempty"`
}

type HeartbeatReq struct {
	NodeID      string        `json:"node_id"`
	Fingerprint string        `json:"fingerprint"`
	Status      NodeStatus    `json:"status"`
	ConfigHash  string        `json:"config_hash,omitempty"`
	Logs        []string      `json:"logs,omitempty"`
	Hardware    *HardwareInfo `json:"hardware,omitempty"`
}

type NodeStatus struct {
	AgentVersion string            `json:"agent_version"`
	CertHashes   map[string]string `json:"cert_hashes,omitempty"`
	IPv4         string            `json:"ipv4"`
	IPv6         string            `json:"ipv6"`
	DDNSHealth   *DDNSHealthInfo   `json:"ddns_health,omitempty"`
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
	BundleName string `json:"bundle_name"`
	DeployPath string `json:"deploy_path"`
}

type CertUpdate struct {
	CertHash            string            `json:"cert_hash"`
	BundleName          string            `json:"bundle_name"`
	Files               map[string]string `json:"files"`
	TargetPath          string            `json:"target_path"`
	ReloadServices      []string          `json:"reload_services,omitempty"`
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
	VerifySSL       bool               `json:"verify_ssl" yaml:"verify_ssl"`
	IISCertBindings []CertToIISBinding `json:"iis_cert_bindings,omitempty" yaml:"iis_cert_bindings,omitempty"`
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
