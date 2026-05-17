//go:build !windows

package installer

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// GetMachineID returns a stable machine identifier.
// Linux: /etc/machine-id → /var/lib/dbus/machine-id → hostname fallback.
func GetMachineID() (string, error) {
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile("/etc/machine-id")
		if err != nil {
			data, err = os.ReadFile("/var/lib/dbus/machine-id")
			if err != nil {
				return "", fmt.Errorf("no machine-id found: %w", err)
			}
		}
		return strings.TrimSpace(string(data)), nil
	default:
		hostname, _ := os.Hostname()
		return hostname + "-" + runtime.GOOS + "-" + runtime.GOARCH, nil
	}
}
