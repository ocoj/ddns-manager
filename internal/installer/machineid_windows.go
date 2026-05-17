//go:build windows

package installer

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// GetMachineID returns a stable machine identifier on Windows.
// Reads HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid.
func GetMachineID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("open registry: %w", err)
	}
	defer k.Close()
	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", fmt.Errorf("read MachineGuid: %w", err)
	}
	guid = strings.TrimSpace(guid)
	if guid == "" {
		return "", fmt.Errorf("MachineGuid is empty")
	}
	return guid, nil
}
