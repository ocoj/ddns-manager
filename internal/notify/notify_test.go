package notify

import (
	"testing"
)

func TestIsConfigured(t *testing.T) {
	tests := []struct {
		name   string
		cfg    Config
		expect bool
	}{
		{
			"fully configured",
			Config{Host: "smtp.example.com", Port: 587, Username: "a@b.com", Password: "secret", To: "c@d.com"},
			true,
		},
		{
			"port 465",
			Config{Host: "smtp.example.com", Port: 465, Username: "a@b.com", Password: "secret", To: "c@d.com"},
			true,
		},
		{
			"missing host",
			Config{Port: 587, Username: "a@b.com", Password: "secret", To: "c@d.com"},
			false,
		},
		{
			"missing port (0)",
			Config{Host: "smtp.example.com", Port: 0, Username: "a@b.com", Password: "secret", To: "c@d.com"},
			false,
		},
		{
			"missing username",
			Config{Host: "smtp.example.com", Port: 587, Password: "secret", To: "c@d.com"},
			false,
		},
		{
			"missing password",
			Config{Host: "smtp.example.com", Port: 587, Username: "a@b.com", To: "c@d.com"},
			false,
		},
		{
			"missing To",
			Config{Host: "smtp.example.com", Port: 587, Username: "a@b.com", Password: "secret"},
			false,
		},
		{
			"everything empty",
			Config{},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsConfigured(); got != tt.expect {
				t.Errorf("IsConfigured() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestMasked(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     string
	}{
		{"long password", "MySecretPassword123!", "My****************3!"},
		{"short password", "abc", "****"},
		{"empty password", "", ""},
		{"exactly 4 chars", "abcd", "****"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Password: tt.password}
			masked := cfg.Masked()
			if masked.Password != tt.want {
				t.Errorf("Masked password = %q, want %q", masked.Password, tt.want)
			}
			// Masked should not mutate original
			if cfg.Password != tt.password {
				t.Error("Masked() mutated original config")
			}
		})
	}
}

func TestSendTestNotConfigured(t *testing.T) {
	cfg := &Config{}
	err := cfg.SendTest()
	if err == nil {
		t.Error("SendTest with empty config should error")
	}
}

func TestCertAlertStructure(t *testing.T) {
	a := CertAlert{
		BundleName: "test.example.com",
		DaysLeft:   15,
		ExpiresAt:  "2026-06-01",
	}
	if a.BundleName != "test.example.com" {
		t.Error("BundleName mismatch")
	}
	if a.DaysLeft != 15 {
		t.Error("DaysLeft mismatch")
	}
}

func TestSendEventAlertNotConfigured(t *testing.T) {
	cfg := &Config{}
	// not configured → should return nil (silently skip)
	err := cfg.SendEventAlert("security", "test", "detail")
	if err != nil {
		t.Errorf("SendEventAlert with empty config should return nil, got %v", err)
	}
}

func TestSendEventAlertToggleOff(t *testing.T) {
	cfg := &Config{
		Host: "smtp.example.com", Port: 587,
		Username: "a@b.com", Password: "secret", To: "c@d.com",
		// all notification toggles off by default
	}
	// configured but toggle off → should return nil
	err := cfg.SendEventAlert("heartbeat_fail", "test", "detail")
	if err != nil {
		t.Errorf("SendEventAlert with toggle off should return nil, got %v", err)
	}
}

func TestSendCertAlertToggleOff(t *testing.T) {
	cfg := &Config{
		Host: "smtp.example.com", Port: 587,
		Username: "a@b.com", Password: "secret", To: "c@d.com",
		// NotifyCertExpiry false by default
	}
	err := cfg.SendCertAlert([]CertAlert{{BundleName: "test", DaysLeft: 5, ExpiresAt: "2026-06-01"}})
	if err != nil {
		t.Errorf("SendCertAlert with toggle off should return nil, got %v", err)
	}
}
