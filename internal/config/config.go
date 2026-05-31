// Package config provides manager configuration.
package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// ManagerConfig is the global manager configuration.
type ManagerConfig struct {
	Server  ServerConfig  `yaml:"server"`
	Cert    CertConfig    `yaml:"cert"`
	DDNS    DDNSConfig    `yaml:"ddns"`
	Agent   AgentConfig   `yaml:"agent"`
	Logging LoggingConfig `yaml:"logging"`
	DataDir string        `yaml:"data_dir"`
}

type ServerConfig struct {
	Listen       string `yaml:"listen"`        // :9877
	TLSCert      string `yaml:"tls_cert"`
	TLSKey       string `yaml:"tls_key"`
	RedirectPort string `yaml:"redirect_port"` // HTTP→HTTPS redirect port
	TrustedProxy string `yaml:"trusted_proxy"` // v1.6.56: 受信反向代理 IP，设置后信任其 IP 头
}

type CertConfig struct {
	Provider          string `yaml:"provider"`           // acme.sh path
	RenewalDaysBefore int    `yaml:"renewal_days_before"` // 30
}

type DDNSConfig struct {
	GithubReleaseURL string `yaml:"github_release_url"`
	LatestVersion    string `yaml:"latest_version"`     // enforced ddns-go version
}

type AgentConfig struct {
	LatestVersion string `yaml:"latest_version"` // enforced agent version
}

type LoggingConfig struct {
	Level         string `yaml:"level"`
	RetentionDays int    `yaml:"retention_days"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *ManagerConfig {
	return &ManagerConfig{
		Server: ServerConfig{
			Listen: ":9877",
		},
		Cert: CertConfig{
			Provider:          "/usr/local/bin/acme.sh",
			RenewalDaysBefore: 30,
		},
		DDNS: DDNSConfig{
			GithubReleaseURL: "https://api.github.com/repos/jeessy2/ddns-go/releases/latest",
		},
		Logging: LoggingConfig{
			Level:         "info",
			RetentionDays: 90,
		},
		DataDir: "./data",
	}
}

// Load reads manager.yaml from path.
func Load(path string) (*ManagerConfig, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "./data"
	}
	return cfg, nil
}

// Save writes manager.yaml.
func (c *ManagerConfig) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
