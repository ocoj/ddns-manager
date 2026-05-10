package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Server.Listen != ":9877" {
		t.Errorf("Listen = %q, want :9877", cfg.Server.Listen)
	}
	if cfg.Cert.RenewalDaysBefore != 30 {
		t.Errorf("RenewalDaysBefore = %d, want 30", cfg.Cert.RenewalDaysBefore)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.Logging.Level)
	}
	if cfg.Logging.RetentionDays != 90 {
		t.Errorf("RetentionDays = %d, want 90", cfg.Logging.RetentionDays)
	}
	if cfg.DataDir != "./data" {
		t.Errorf("DataDir = %q, want ./data", cfg.DataDir)
	}
}

func TestLoadNotExist(t *testing.T) {
	cfg, err := Load("/nonexistent/path/manager.yaml")
	if err != nil {
		t.Fatalf("Load non-existent: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected default config, got nil")
	}
	if cfg.Server.Listen != ":9877" {
		t.Errorf("default Listen = %q", cfg.Server.Listen)
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manager.yaml")

	cfg := DefaultConfig()
	cfg.Server.Listen = ":8888"
	cfg.Logging.Level = "debug"
	cfg.DataDir = "/custom/data"

	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.Server.Listen != ":8888" {
		t.Errorf("Listen = %q, want :8888", loaded.Server.Listen)
	}
	if loaded.Logging.Level != "debug" {
		t.Errorf("Level = %q, want debug", loaded.Logging.Level)
	}
	if loaded.DataDir != "/custom/data" {
		t.Errorf("DataDir = %q, want /custom/data", loaded.DataDir)
	}
}

func TestLoadEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manager.yaml")
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load empty file: %v", err)
	}
	if cfg.Server.Listen != ":9877" {
		t.Errorf("expected default Listen, got %q", cfg.Server.Listen)
	}
}

func TestLoadPartialOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manager.yaml")
	yaml := `server:
  listen: ":9999"
logging:
  level: warn
`
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":9999" {
		t.Errorf("Listen = %q, want :9999", cfg.Server.Listen)
	}
	if cfg.Logging.Level != "warn" {
		t.Errorf("Level = %q, want warn", cfg.Logging.Level)
	}
	// unset fields get defaults
	if cfg.Logging.RetentionDays != 90 {
		t.Errorf("RetentionDays = %d, want 90 (default)", cfg.Logging.RetentionDays)
	}
}

func TestSavePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manager.yaml")

	cfg := DefaultConfig()
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions = %o, want 0600", info.Mode().Perm())
	}
}
