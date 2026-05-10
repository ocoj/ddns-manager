//go:build windows

package sysinfo

func CPUPercent() float64        { return 0 }
func MemoryInfo() (uint64, uint64) { return 0, 0 }
func DiskInfo() (uint64, uint64)   { return 0, 0 }
