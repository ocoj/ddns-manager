//go:build !windows

package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// getMachineID returns a stable machine identifier on non-Windows platforms.
//
// Linux: /etc/machine-id (systemd-generated, survives reboots, stable across kernel updates)
//   fallback: /var/lib/dbus/machine-id
//
// Other (macOS/BSD/etc): hostname + OS/arch as fallback
func getMachineID() (string, error) {
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
