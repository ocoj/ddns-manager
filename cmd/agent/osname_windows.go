//go:build windows

package main

import (
	"golang.org/x/sys/windows/registry"
)

// osProductName reads the Windows product name from the registry.
// v1.5.20 L2: 补充 Windows 友好操作系统名称（如 "Windows Server 2022 Standard"），
// 替代原有的 bare "windows/amd64" 展示。
func osProductName() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()

	name, _, err := k.GetStringValue("ProductName")
	if err != nil {
		return ""
	}
	return name
}
