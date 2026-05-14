//go:build !windows

package main

// osProductName returns the OS product name on non-Windows platforms.
// v1.5.20 L2: Linux/macOS 通过 /etc/os-release 读取友好名称，此处为 stub。
func osProductName() string { return "" }
