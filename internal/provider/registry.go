// Package provider v1.6.28 M1: 统一 DNS Provider 注册表。
// 消除 dns_updater.go、handlers_admin.go、model.go 三份重复维护。
// 所有 provider 创建走 DNSProviderFactory，确保与 ddns-go v6 同步。
package provider

import (
	"fmt"

	ddnsconfig "github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/dns"
	"github.com/jeessy2/ddns-go/v6/util"
)

// ProviderFactory creates a DNS provider instance.
type ProviderFactory func() dns.DNS

// Registry maps ddns-go DNS provider names to factory functions.
// 单一真相源 — 与 ddns-go's dns/index.go:RunOnce() 保持同步。
var Registry = map[string]ProviderFactory{
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

// NewProvider creates a DNS provider by name.
// Returns nil if the provider name is not registered.
func NewProvider(name string) dns.DNS {
	if fn, ok := Registry[name]; ok {
		return fn()
	}
	return nil
}

// Names returns the list of all registered provider names.
// Used for validation and UI provider lists.
func Names() []string {
	names := make([]string, 0, len(Registry))
	for k := range Registry {
		names = append(names, k)
	}
	return names
}

// IsKnown checks if a provider name is registered.
func IsKnown(name string) bool {
	_, ok := Registry[name]
	return name != "" && ok
}

// ValidateKeyOnline tests if a DNS provider's credentials are valid by
// calling Init + AddUpdateDomainRecords with a test domain.
// Returns (valid, detail). This replaces the duplicated testDNSKeyOnline logic.
func ValidateKeyOnline(providerName, accessKeyID, accessKeySecret, testDomain string) (dns.DNS, *ddnsconfig.DnsConfig, error) {
	fn, ok := Registry[providerName]
	if !ok {
		return nil, nil, fmt.Errorf("unsupported provider: %s", providerName)
	}
	p := fn()

	dc := &ddnsconfig.DnsConfig{
		DNS: ddnsconfig.DNS{Name: providerName, ID: accessKeyID, Secret: accessKeySecret},
	}
	dc.Ipv4.Enable = true
	dc.Ipv4.GetType = "url"
	dc.Ipv4.URL = "http://ipv4.icanhazip.com"
	dc.Ipv4.Domains = []string{testDomain}
	dc.Ipv6.Enable = false

	ipv4cache := &util.IpCache{}
	ipv6cache := &util.IpCache{}
	p.Init(dc, ipv4cache, ipv6cache)
	domains := p.AddUpdateDomainRecords()

	// Check if all updates failed (strong indicator of invalid credentials)
	allFailed := true
	for _, d := range domains.Ipv4Domains {
		if d.UpdateStatus != ddnsconfig.UpdatedFailed {
			allFailed = false
			break
		}
	}
	if allFailed && len(domains.Ipv4Domains) > 0 {
		return p, dc, fmt.Errorf("all domain updates failed (possible invalid credentials)")
	}

	return p, dc, nil
}
