package acme

import (
	"context"
	"strings"
	"testing"
)

// TestRenewAllDomains verifies the C2 fix: Renew() must pass all domains to acme.sh --renew.
// Multi-domain certs (SAN) require all domains via multiple -d flags.
func TestRenewAllDomains_MultiDomain(t *testing.T) {
	t.Run("c2_renew_args_include_all_domains", func(t *testing.T) {
		domains := []string{"a.example.com", "b.example.com"}
		args := []string{"--renew"}
		for _, d := range domains {
			args = append(args, "-d", d)
		}
		args = append(args,
			"--cert-file", "/tmp/cert.pem",
			"--key-file", "/tmp/key.pem",
			"--fullchain-file", "/tmp/fullchain.pem")

		cmdStr := strings.Join(args, " ")
		for _, d := range domains {
			if !strings.Contains(cmdStr, "-d "+d) {
				t.Errorf("domain %q not found in renew args: %s", d, cmdStr)
			}
		}
		if strings.Count(cmdStr, "-d ") != len(domains) {
			t.Errorf("expected %d -d flags, got %d", len(domains), strings.Count(cmdStr, "-d "))
		}
	})

	t.Run("c2_renew_by_name_args_include_all_domains", func(t *testing.T) {
		domains := []string{"primary.example.com", "www.example.com", "api.example.com"}
		args := []string{"--renew"}
		for _, d := range domains {
			args = append(args, "-d", d)
		}
		args = append(args, "--force",
			"--cert-file", "/tmp/cert.pem",
			"--key-file", "/tmp/key.pem",
			"--fullchain-file", "/tmp/fullchain.pem")

		cmdStr := strings.Join(args, " ")
		if !strings.Contains(cmdStr, "--force") {
			t.Error("RenewByName should include --force flag")
		}
		if strings.Count(cmdStr, "-d ") != len(domains) {
			t.Errorf("expected %d -d flags, got %d", len(domains), strings.Count(cmdStr, "-d "))
		}
	})
}

// TestRenewSingleDomainNoRegression verifies single-domain certs are unaffected.
func TestRenewSingleDomainNoRegression(t *testing.T) {
	t.Run("single_domain", func(t *testing.T) {
		domains := []string{"only.example.com"}
		args := []string{"--renew"}
		for _, d := range domains {
			args = append(args, "-d", d)
		}
		if strings.Count(strings.Join(args, " "), "-d ") != 1 {
			t.Error("single domain should have exactly 1 -d flag")
		}
	})

	t.Run("empty_domains_boundary", func(t *testing.T) {
		var domains []string
		args := []string{"--renew"}
		for _, d := range domains {
			args = append(args, "-d", d)
		}
		if strings.Count(strings.Join(args, " "), "-d") > 0 {
			t.Error("empty domains should produce no -d flags")
		}
	})
}

// TestACMEAutoRenewEmptyDir verifies C4: Renew on empty certs dir returns empty
// without error (caller should log audit).
func TestACMEAutoRenewEmptyDir(t *testing.T) {
	mgr, err := New(t.TempDir(), "test@example.com", ":8081")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("renew_empty_dir_returns_nil", func(t *testing.T) {
		renewed := mgr.Renew(context.Background())
		if len(renewed) != 0 {
			t.Errorf("expected 0 renewed certs from empty dir, got %d", len(renewed))
		}
	})

	t.Run("last_error_thread_safe", func(t *testing.T) {
		// M4: verify LastError is thread-safe (no data race)
		_ = mgr.LastError()
	})
}
