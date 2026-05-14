//go:build windows

package main

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// windowsVersion returns the Windows OS version (major, minor, build).
// Reads from registry HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion.
func windowsVersion() (major, minor, build uint32) {
	major, minor, build = 6, 1, 7601 // fallback: Win7/2008R2
	if runtime.GOOS != "windows" {
		return
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	if v, _, err := k.GetIntegerValue("CurrentMajorVersionNumber"); err == nil {
		major = uint32(v)
	}
	if v, _, err := k.GetIntegerValue("CurrentMinorVersionNumber"); err == nil {
		minor = uint32(v)
	}
	if v, _, err := k.GetIntegerValue("CurrentBuildNumber"); err == nil {
		build = uint32(v)
	}
	if major == 0 {
		if s, _, err := k.GetStringValue("CurrentVersion"); err == nil {
			parts := strings.Split(s, ".")
			if len(parts) >= 1 {
				if v, err2 := strconv.Atoi(parts[0]); err2 == nil {
					major = uint32(v)
				}
			}
			if len(parts) >= 2 {
				if v, err2 := strconv.Atoi(parts[1]); err2 == nil {
					minor = uint32(v)
				}
			}
		}
	}
	return
}

// useModernPFX detects if the current Windows version supports Modern PFX (PBES2+AES-256).
// Supported: Win10 1809+ (build 17763), Server 2019+, Win 11.
// isIISInstalled checks if IIS (W3SVC) is present on this Windows machine.
// Returns false if IIS is not installed — cert binding will be skipped.
func isIISInstalled() bool {
	_, err := exec.Command("sc", "query", "W3SVC").CombinedOutput()
	return err == nil
}

func useModernPFX() bool {
	major, _, build := windowsVersion()
	return major >= 10 && build >= 17763
}
