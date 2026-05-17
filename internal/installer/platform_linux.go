//go:build linux

package installer

import (
	"os"
	"os/exec"
)

// IsRoot returns true if running as root (uid 0).
func IsRoot() bool { return os.Geteuid() == 0 }

// StopAgent stops the node-agent systemd timer.
func StopAgent() error {
	exec.Command("systemctl", "stop", "node-agent.timer").Run()
	return nil
}

// StartAgent starts (or restarts) the node-agent systemd timer.
func StartAgent() error {
	exec.Command("systemctl", "restart", "node-agent.timer").Run()
	return nil
}

// InstallService writes systemd service and timer units, then enables the timer.
func InstallService(installDir string) error {
	agentBin := installDir + "/node-agent"

	svc := `[Unit]
Description=ddns-manager Node Agent
After=network-online.target

[Service]
Type=oneshot
ExecStart=` + agentBin + ` -heartbeat
`
	os.WriteFile("/etc/systemd/system/node-agent.service", []byte(svc), 0644)

	timer := `[Unit]
Description=ddns-manager Node Agent Timer

[Timer]
OnBootSec=30s
OnUnitActiveSec=5min
RandomizedDelaySec=30s

[Install]
WantedBy=timers.target
`
	os.WriteFile("/etc/systemd/system/node-agent.timer", []byte(timer), 0644)

	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "--now", "node-agent.timer").Run()
	return nil
}

// UninstallAgent removes systemd units and the install directory.
func UninstallAgent(dir string) {
	exec.Command("systemctl", "stop", "node-agent.timer").Run()
	exec.Command("systemctl", "disable", "node-agent.timer").Run()
	os.Remove("/etc/systemd/system/node-agent.service")
	os.Remove("/etc/systemd/system/node-agent.timer")
	exec.Command("systemctl", "daemon-reload").Run()
	os.RemoveAll(dir)
}
