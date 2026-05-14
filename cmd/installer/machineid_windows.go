//go:build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// getMachineID returns a stable machine identifier on Windows.
// Reads HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid — a GUID
// created during Windows installation that never changes.
//
// ⚠️ 禁止使用 PowerShell/WMI 获取 UUID:
//    - PowerShell 版本/模块差异导致输出尾随字符不一致 (\r\n vs \n vs 无)
//    - 同一台机器产生不同指纹, v1.5.13 已造成生产故障
//    - 注册表 MachineGuid 是 Go 原生实现, 零外部依赖, 所有 Windows 版本通用
func getMachineID() (string, error) {
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
