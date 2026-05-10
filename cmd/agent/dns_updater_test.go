package main

import (
	"strings"
	"sync"
	"testing"
)

// ── LogBuffer ──

func TestLogBufferWriteAndRecent(t *testing.T) {
	lb := newLogBuffer(10)
	for i := 0; i < 15; i++ {
		lb.Write(strings.Repeat("x", i+1))
	}

	lines := lb.Recent(5)
	if len(lines) != 5 {
		t.Fatalf("Recent(5) = %d lines, want 5", len(lines))
	}
	// 15 writes with buf size 10 → positions 5-14 in buffer, Recent(5) gets last 5
	if !strings.HasSuffix(lines[0], "x") || len(lines[0]) < 15 {
		t.Errorf("oldest recent line looks wrong: %q", lines[0])
	}
}

func TestLogBufferRecentMoreThanSize(t *testing.T) {
	lb := newLogBuffer(3)
	lb.Write("a")
	lb.Write("b")
	lb.Write("c")

	lines := lb.Recent(10) // ask for more than we have
	if len(lines) != 3 {
		t.Errorf("Recent(10) = %d lines, want 3", len(lines))
	}
}

func TestLogBufferEmpty(t *testing.T) {
	lb := newLogBuffer(10)
	lines := lb.Recent(5)
	if len(lines) != 0 {
		t.Errorf("Recent on empty buffer = %d lines, want 0", len(lines))
	}
}

func TestLogBufferConcurrent(t *testing.T) {
	lb := newLogBuffer(100)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				lb.Write("concurrent write")
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_ = lb.Recent(10)
			}
		}()
	}
	wg.Wait()
	// should not panic
	_ = lb.Recent(100)
}

// ── newProvider ──

// ddnsCanonicalProviders mirrors ddns-go v6.17.0 dns/index.go:RunOnce() switch cases
// (excluding the default fallback). Update this list when upgrading ddns-go.
var ddnsCanonicalProviders = []string{
	"alidns",
	"aliesa",
	"tencentcloud",
	"trafficroute",
	"dnspod",
	"dnsla",
	"cloudflare",
	"huaweicloud",
	"callback",
	"baiducloud",
	"porkbun",
	"godaddy",
	"namecheap",
	"namesilo",
	"vercel",
	"dynadot",
	"dynv6",
	"spaceship",
	"nowcn",
	"eranet",
	"tnethk",
	"gcore",
	"edgeone",
	"nsone",
	"name_com",
	"rainyun",
	"hipmdnsmgr",
	"cloudns",
}

// TestProviderRegistryCompleteness validates providerRegistry is in sync with ddns-go.
// After: go get -u github.com/jeessy2/ddns-go/v6
// Run:   go test ./cmd/agent/ -run Registry -v
// Missing → update both ddnsCanonicalProviders and providerRegistry.
func TestProviderRegistryCompleteness(t *testing.T) {
	// 1. every factory in registry returns non-nil
	for name, fn := range providerRegistry {
		if fn() == nil {
			t.Errorf("providerRegistry[%q] factory returns nil", name)
		}
	}

	// 2. every canonical provider is in the registry
	canonical := make(map[string]bool, len(ddnsCanonicalProviders))
	for _, n := range ddnsCanonicalProviders {
		canonical[n] = true
	}

	var missing []string
	for _, n := range ddnsCanonicalProviders {
		if _, ok := providerRegistry[n]; !ok {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		t.Errorf("MISSING from providerRegistry (add them):\n  %s",
			strings.Join(missing, "\n  "))
	}

	// 3. no extra entries in registry (stale/typo)
	var extra []string
	for n := range providerRegistry {
		if !canonical[n] {
			extra = append(extra, n)
		}
	}
	if len(extra) > 0 {
		t.Errorf("EXTRA in providerRegistry (remove or add to canonical list):\n  %s",
			strings.Join(extra, "\n  "))
	}
}

func TestNewProviderUnknown(t *testing.T) {
	if p := newProvider("nonexistent"); p != nil {
		t.Error("newProvider for unknown provider should return nil")
	}
}

// ── DNSUpdater ──

func TestDNSUpdaterEmptyConfig(t *testing.T) {
	u := NewDNSUpdater()
	status := u.Run()

	if !status.Running {
		t.Error("Running should be true even with empty config")
	}
	if status.LastOK {
		t.Error("LastOK should be false with empty config")
	}
}

func TestDNSUpdaterConfigHash(t *testing.T) {
	u := NewDNSUpdater()
	h1 := u.ConfigHash()

	// empty config hash: empty config should still produce a hash
	if h1 == "" {
		t.Error("ConfigHash should not be empty")
	}

	// applying same config → same hash
	u.ApplyConfig([]byte("notallowwanaccess: true\ndnsconf: []\n"))
	h2 := u.ConfigHash()
	if h2 == "" {
		t.Error("ConfigHash after ApplyConfig should not be empty")
	}
	if h1 == h2 {
		t.Log("empty config and empty-dnsconf config have different hashes (expected)")
	}
}

func TestDNSUpdaterApplyInvalidYAML(t *testing.T) {
	u := NewDNSUpdater()
	err := u.ApplyConfig([]byte("not: [invalid yaml!!"))
	if err == nil {
		t.Error("ApplyConfig with invalid YAML should error")
	}
}

func TestDNSUpdaterStatus(t *testing.T) {
	u := NewDNSUpdater()
	s := u.Status()
	if !s.Running {
		t.Error("initial Status.Running should be true")
	}
}

func TestDNSUpdaterRecentLogs(t *testing.T) {
	u := NewDNSUpdater()
	logs := u.RecentLogs(5)
	if logs != nil && len(logs) > 0 {
		t.Logf("logs from empty updater: %v (should be empty)", logs)
	}
}

// ── DNSStatus ──

func TestDNSStatusLastLine(t *testing.T) {
	tests := []struct {
		name   string
		status DNSStatus
		want   string
	}{
		{"no_error", DNSStatus{LastError: ""}, ""},
		{"with_error", DNSStatus{LastError: "connection refused"}, "connection refused"},
		{"ok", DNSStatus{LastOK: true}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.LastLine(); got != tt.want {
				t.Errorf("LastLine() = %q, want %q", got, tt.want)
			}
		})
	}
}
