//go:build !windows

package sysinfo

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type cpuSample struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
}

func readCPUSample() (cpuSample, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		return cpuSample{
			user:    parseUint(fields[1]),
			nice:    parseUint(fields[2]),
			system:  parseUint(fields[3]),
			idle:    parseUint(fields[4]),
			iowait:  parseUint(fields[5]),
			irq:     parseUint(fields[6]),
			softirq: parseUint(fields[7]),
			steal:   parseUint(fields[8]),
		}, nil
	}
	return cpuSample{}, sc.Err()
}

func CPUPercent() float64 {
	s1, err := readCPUSample()
	if err != nil {
		return 0
	}
	time.Sleep(time.Second)
	s2, err := readCPUSample()
	if err != nil {
		return 0
	}

	total1 := s1.user + s1.nice + s1.system + s1.idle + s1.iowait + s1.irq + s1.softirq + s1.steal
	total2 := s2.user + s2.nice + s2.system + s2.idle + s2.iowait + s2.irq + s2.softirq + s2.steal
	idle1 := s1.idle + s1.iowait
	idle2 := s2.idle + s2.iowait

	totalDelta := total2 - total1
	idleDelta := idle2 - idle1
	if totalDelta == 0 {
		return 0
	}
	return float64(totalDelta-idleDelta) / float64(totalDelta) * 100
}

func MemoryInfo() (used, total uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	var memTotal, memAvailable uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			memTotal = parseMemValue(line)
		}
		if strings.HasPrefix(line, "MemAvailable:") {
			memAvailable = parseMemValue(line)
		}
	}
	if memTotal == 0 {
		return 0, 0
	}
	return memTotal - memAvailable, memTotal
}

func DiskInfo() (used, total uint64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0, 0
	}
	total = stat.Blocks * uint64(stat.Bsize)
	used = total - (stat.Bavail * uint64(stat.Bsize))
	return
}

func parseUint(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

func parseMemValue(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[1], 10, 64)
	return v * 1024
}
