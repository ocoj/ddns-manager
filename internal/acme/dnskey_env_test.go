package acme

import (
	"strings"
	"testing"
)

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

// 说明（v1.6.71 N1）：原 T1/T2/T3（凭据注入 + 环境继承）已由 acmehome_test.go 的
// T34–T38 取代 —— 那些用例覆盖了"父环境无 HOME"这一原实现结构性无法复现的场景（I27）。

// T4: resolveDNSKey truth table (provider match, completeness, unique fallback,
// ambiguity refusal).
func TestResolveDNSKey_TruthTable(t *testing.T) {
	canonical := &DNSProvider{Name: "alidns", KeyID: "AK1", KeySecret: "SK1", KeyName: "权威"}
	duplicate := &DNSProvider{Name: "alidns", KeyID: "AK2", KeySecret: "SK2", KeyName: "重复"}
	incomplete := &DNSProvider{Name: "alidns", KeyID: "", KeySecret: "", KeyName: "空"}
	other := &DNSProvider{Name: "cloudflare", KeyID: "CF", KeyName: "CF"}

	tests := []struct {
		name     string
		meta     map[string]interface{}
		keys     map[string]*DNSProvider
		wantNil  bool
		wantName string
	}{
		{"no keys", map[string]interface{}{"provider": "alidns"}, nil, true, ""},
		{"no provider", map[string]interface{}{}, map[string]*DNSProvider{"权威": canonical}, true, ""},
		{"unsupported provider", map[string]interface{}{"provider": "nope"}, map[string]*DNSProvider{"权威": canonical}, true, ""},
		{"exact hit", map[string]interface{}{"provider": "alidns", "dns_key": "权威"}, map[string]*DNSProvider{"权威": canonical, "重复": duplicate}, false, "权威"},
		{"provider mismatch", map[string]interface{}{"provider": "alidns", "dns_key": "CF"}, map[string]*DNSProvider{"CF": other}, true, ""},
		{"incomplete credentials", map[string]interface{}{"provider": "alidns", "dns_key": "空"}, map[string]*DNSProvider{"空": incomplete}, true, ""},
		{"unique fallback after rename", map[string]interface{}{"provider": "alidns", "dns_key": "旧名"}, map[string]*DNSProvider{"权威": canonical}, false, "权威"},
		{"no candidate falls back to account.conf", map[string]interface{}{"provider": "alidns", "dns_key": "旧名"}, map[string]*DNSProvider{"CF": other, "空": incomplete}, true, ""},
		{"ambiguous candidates are refused", map[string]interface{}{"provider": "alidns", "dns_key": "旧名"}, map[string]*DNSProvider{"权威": canonical, "重复": duplicate}, true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := resolveDNSKey(tc.meta, tc.keys)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("expected nil provider, got %q (reason=%q)", got.KeyName, reason)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected provider %q, got nil (reason=%q)", tc.wantName, reason)
			}
			if got.KeyName != tc.wantName {
				t.Errorf("got %q, want %q", got.KeyName, tc.wantName)
			}
		})
	}
}

// The DNSProvider struct must carry the dns_keys.json entry name (S5) — this is
// what gets persisted into meta.dns_key.
func TestDNSProvider_CarriesKeyName(t *testing.T) {
	dp := DNSProvider{Name: "alidns", KeyID: "AK", KeySecret: "SK", KeyName: "权威"}
	if dp.KeyName != "权威" {
		t.Fatal("KeyName must be preserved")
	}
}

// B6: a single lookup entry point must serve issuance and renewal, and it must
// tolerate case differences — otherwise a provider could be accepted for
// credential resolution while its credentials were silently never injected.
func TestDNSAPILookup_UnifiedAndCaseTolerant(t *testing.T) {
	spec, ok := dnsAPILookup("alidns")
	if !ok || spec.env != "Ali_Key" || spec.secret != "Ali_Secret" {
		t.Fatalf("exact lookup failed: %+v ok=%v", spec, ok)
	}
	for _, variant := range []string{"Alidns", "ALIDNS", "aliDNS"} {
		got, ok := dnsAPILookup(variant)
		if !ok {
			t.Errorf("dnsAPILookup(%q) must succeed (B6)", variant)
			continue
		}
		if got.env != spec.env || got.secret != spec.secret || got.api != spec.api {
			t.Errorf("dnsAPILookup(%q) = %+v, want %+v", variant, got, spec)
		}
	}
	if _, ok := dnsAPILookup("no-such-provider"); ok {
		t.Error("unknown provider must not resolve")
	}

	// Credential injection must follow the same tolerance (issuance path).
	t.Setenv("HOME", "/root")
	m := envMap(acmeShEnv(&DNSProvider{Name: "Alidns", KeyID: "AK", KeySecret: "SK"}, "/root/.acme.sh"))
	if m["Ali_Key"] != "AK" || m["Ali_Secret"] != "SK" {
		t.Errorf("case-variant provider must still inject credentials: %v", m)
	}
}
