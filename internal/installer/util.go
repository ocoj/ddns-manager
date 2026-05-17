// Package installer provides shared utilities for ddns-manager installers.
// Extracted from cmd/installer/main.go — platform-agnostic functions used by
// both cmd/installer-linux and cmd/installer-windows.
package installer

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kk/ddns-manager/internal/model"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// ── Config I/O ──

// LoadConfig reads an AgentConfig from a YAML/JSON file.
func LoadConfig(path string) (*model.AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg model.AgentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SaveConfig writes an AgentConfig as YAML, creating parent directories.
func SaveConfig(cfg *model.AgentConfig, path string) error {
	os.MkdirAll(filepath.Dir(path), 0700)
	yamlData, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, yamlData, 0600)
}

// ── File helpers ──

// FindLocalAgent scans dir for a node-agent binary.
// Windows: matches node-agent*.exe. Linux: matches node-agent-v* (no extension).
// Returns the first match or empty string.
func FindLocalAgent(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := strings.ToLower(e.Name())
		if strings.HasPrefix(n, "node-agent") && strings.HasSuffix(n, ".exe") {
			return filepath.Join(dir, e.Name())
		}
		// Linux: no .exe suffix
		if runtime.GOOS != "windows" && strings.HasPrefix(n, "node-agent") && !strings.Contains(n, ".") {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

// CopyFile copies src to dst with fsync.
func CopyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()

	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()

	if _, err := io.Copy(d, s); err != nil {
		return err
	}
	return d.Sync()
}

// ExeDir returns the directory containing the running executable.
func ExeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// ── Crypto ──

// GenerateFingerprint returns "sha256:" + SHA256(hostname + machineID).
func GenerateFingerprint(machineID string) string {
	hostname, _ := os.Hostname()
	h := sha256.Sum256([]byte(hostname + machineID))
	return "sha256:" + hex.EncodeToString(h[:])
}

// GeneratePassword returns a hex-encoded 16-byte random password.
func GeneratePassword() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("随机数生成失败: %v", err)
	}
	return hex.EncodeToString(b)
}

// ── Terminal ──

// ReadLine reads a line from stdin with backspace/Ctrl-C/Ctrl-U support.
func ReadLine(reader *bufio.Reader) (string, error) {
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err == nil {
		defer term.Restore(fd, oldState)
	}

	var buf strings.Builder
	for {
		r, _, err := reader.ReadRune()
		if err != nil {
			return "", err
		}
		if r == '\r' || r == '\n' {
			fmt.Print("\r\n")
			return strings.TrimSpace(buf.String()), nil
		}
		if r == 0x7f || r == 0x08 {
			s := buf.String()
			if len(s) > 0 {
				runes := []rune(s)
				runes = runes[:len(runes)-1]
				buf.Reset()
				for _, ru := range runes {
					buf.WriteRune(ru)
				}
				fmt.Print("\b \b")
			}
			continue
		}
		if r == 0x03 {
			fmt.Print("^C\r\n")
			return "", fmt.Errorf("interrupted")
		}
		if r == 0x15 {
			s := buf.String()
			for range []rune(s) {
				fmt.Print("\b \b")
			}
			buf.Reset()
			continue
		}
		buf.WriteRune(r)
		fmt.Print(string(r))
	}
}

// ── Retry ──

// RetryDo calls fn up to maxRetries times with exponential backoff.
func RetryDo(maxRetries int, desc string, fn func() error) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if i < maxRetries-1 {
			time.Sleep(time.Duration(i+1) * 2 * time.Second)
		}
	}
	return fmt.Errorf("%s: %w (重试%d次)", desc, lastErr, maxRetries)
}
