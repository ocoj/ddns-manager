//go:build windows

package installer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// IsAdmin returns true if running with administrator privileges.
func IsAdmin() bool {
	// On Windows, os.Geteuid() is not meaningful; use a lightweight check.
	// Write a test file to a protected location.
	f, err := os.Create(filepath.Join(os.Getenv("SystemRoot"), "Temp", "ddns-installer-admin-test"))
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

// StopAgent stops the node-agent Windows service.
func StopAgent() error {
	exec.Command("sc", "stop", "node-agent").Run()
	return nil
}

// StartAgent starts the node-agent Windows service.
func StartAgent() error {
	exec.Command("sc", "start", "node-agent").Run()
	return nil
}

// SetConsoleUTF8 sets the Windows console code page to UTF-8 (65001).
func SetConsoleUTF8() {
	if runtime.GOOS == "windows" {
		exec.Command("chcp", "65001").Run()
	}
}

// InstallService creates the node-agent Windows service (auto-start, LocalSystem).
func InstallService(installDir string) error {
	agentBin := filepath.Join(installDir, "node-agent.exe")

	// Remove old service if exists
	exec.Command("sc", "delete", "node-agent").Run()

	out, err := exec.Command("sc", "create", "node-agent",
		"binPath=", fmt.Sprintf(`"%s" -daemon`, agentBin),
		"start=", "auto",
		"DisplayName=", "ddns-manager Node Agent",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc create: %v %s", err, string(out))
	}

	// Configure failure recovery: restart after 5s, reset count after 24h
	exec.Command("sc", "failure", "node-agent",
		"reset=", "86400",
		"actions=", "restart/5000",
	).Run()

	return nil
}

// UninstallAgent removes the Windows service and install directory.
func UninstallAgent(dir string) {
	exec.Command("sc", "stop", "node-agent").Run()
	exec.Command("sc", "delete", "node-agent").Run()
	os.RemoveAll(dir)
	os.RemoveAll(filepath.Join(os.Getenv("ProgramData"), "ddns-agent"))
}
