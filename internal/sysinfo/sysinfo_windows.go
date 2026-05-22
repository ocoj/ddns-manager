//go:build windows

package sysinfo

// v1.6.45 L1: 本文件为 Go 跨平台编译占位桩。管理端仅部署 Linux, Windows 平台上
// CPUPercent()/MemoryInfo()/DiskInfo() 全部返回 0 是设计要求 (非遗漏)。
// 实际采集逻辑见 sysinfo_linux.go (通过 /proc/stat, sysconf 等读取)。
// 仅被 internal/server/access_stats.go 引用 (Manager 组件, 仅 Linux 部署)。
// Agent 端不依赖 sysinfo 包。

func CPUPercent() float64        { return 0 }
func MemoryInfo() (uint64, uint64) { return 0, 0 }
func DiskInfo() (uint64, uint64)   { return 0, 0 }
