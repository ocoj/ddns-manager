package server

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kk/ddns-manager/internal/sysinfo"
)

// accessStats 持久化配置
const accessBucketsFile = "access_buckets.json"
const accessMaxAge = 48*60 + 10 // 48h+10min 缓冲（分钟）
const accessFlushInterval = 60 * time.Second

type accessStatsCollector struct {
	mu      sync.Mutex
	buckets map[int64]map[string]int64 // unixMinute -> ip -> count
	dir     string                      // 持久化目录
	tz      *time.Location              // 配置时区
}

func newAccessStatsCollector(dataDir string) *accessStatsCollector {
	c := &accessStatsCollector{
		buckets: make(map[int64]map[string]int64),
		dir:     dataDir,
		tz:      time.UTC, // 默认 UTC, 后续通过 SetTimezone 覆盖
	}
	c.loadFromDisk()
	go c.flushLoop()
	return c
}

// SetTimezone 设置时区，影响图表时间轴和流量记录。
func (c *accessStatsCollector) SetTimezone(tz *time.Location) {
	c.mu.Lock()
	c.tz = tz
	c.mu.Unlock()
}

// nowInTZ 返回当前时间在配置时区下的值(线程安全)。
func (c *accessStatsCollector) nowInTZ() time.Time {
	c.mu.Lock()
	tz := c.tz
	c.mu.Unlock()
	return time.Now().In(tz)
}

// loadFromDisk 从 access_buckets.json 恢复48h内流量桶
func (c *accessStatsCollector) loadFromDisk() {
	path := filepath.Join(c.dir, accessBucketsFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Printf("[access] 加载流量记录失败: %v", err)
		return
	}
	var buckets map[int64]map[string]int64
	if err := json.Unmarshal(data, &buckets); err != nil {
		log.Printf("[access] 解析流量记录失败: %v", err)
		return
	}
	cutoff := c.nowInTZ().Add(-time.Duration(accessMaxAge) * time.Minute).Truncate(time.Minute).Unix()
	for t, b := range buckets {
		if t >= cutoff {
			c.buckets[t] = b
		}
	}
	log.Printf("[access] 从磁盘恢复 %d 分钟流量记录", len(c.buckets))
}

// flushLoop 每60秒将内存桶序列化到磁盘
func (c *accessStatsCollector) flushLoop() {
	ticker := time.NewTicker(accessFlushInterval)
	defer ticker.Stop()
	for range ticker.C {
		c.flushToDisk()
	}
}

// flushToDisk 将内存桶写入 access_buckets.json（环形48h）
func (c *accessStatsCollector) flushToDisk() {
	c.mu.Lock()
	cutoff := c.nowInTZ().Add(-time.Duration(accessMaxAge) * time.Minute).Truncate(time.Minute).Unix()
	buckets := make(map[int64]map[string]int64, len(c.buckets))
	for t, b := range c.buckets {
		if t >= cutoff {
			buckets[t] = b
		} else {
			delete(c.buckets, t)
		}
	}
	c.mu.Unlock()

	path := filepath.Join(c.dir, accessBucketsFile)
	data, err := json.Marshal(buckets)
	if err != nil {
		log.Printf("[access] 序列化流量记录失败: %v", err)
		return
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		log.Printf("[access] 写入流量记录失败: %v", err)
	}
}

func (c *accessStatsCollector) record(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.nowInTZ()
	min := now.Truncate(time.Minute).Unix()
	if c.buckets[min] == nil {
		c.buckets[min] = make(map[string]int64)
		// prune 48h+10min 旧桶
		cutoff := now.Add(-time.Duration(accessMaxAge) * time.Minute).Truncate(time.Minute).Unix()
		for t := range c.buckets {
			if t < cutoff {
				delete(c.buckets, t)
			}
		}
	}
	c.buckets[min][ip]++
	// also count total
	c.buckets[min]["__total__"]++
}

func (c *accessStatsCollector) snapshot(windowMinutes int) *accessStatsSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.nowInTZ()
	cutoff := now.Add(-time.Duration(windowMinutes) * time.Minute).Truncate(time.Minute).Unix()

	// 生成连续时间线: 从 cutoff 到 now, 每分钟一个点, 无数据填0
	startMin := time.Unix(cutoff, 0).UTC()
	var timestamps []string
	var totalSeries []int64
	for t := startMin; !t.After(now.Truncate(time.Minute)); t = t.Add(time.Minute) {
		timestamps = append(timestamps, t.Format("15:04"))
		unix := t.Unix()
		if b, ok := c.buckets[unix]; ok {
			totalSeries = append(totalSeries, b["__total__"])
		} else {
			totalSeries = append(totalSeries, 0)
		}
	}

	// Top IPs: 聚合各IP的分钟序列
	type ipStats struct {
		series []int64
		total  int64
	}
	ipData := make(map[string]*ipStats)
	for i := range timestamps {
		// parse back the unix from startMin + i minutes
		unix := startMin.Add(time.Duration(i) * time.Minute).Unix()
		b := c.buckets[unix]
		if b == nil {
			continue
		}
		for ip, count := range b {
			if ip == "__total__" {
				continue
			}
			if ipData[ip] == nil {
				ipData[ip] = &ipStats{series: make([]int64, len(timestamps))}
			}
			ipData[ip].series[i] = count
			ipData[ip].total += count
		}
	}

	// Sort IPs by total, take top 5
	type ipEntry struct {
		ip     string
		total  int64
		series []int64
	}
	var topIPs []ipEntry
	for ip, d := range ipData {
		topIPs = append(topIPs, ipEntry{ip: ip, total: d.total, series: d.series})
	}
	sort.Slice(topIPs, func(i, j int) bool { return topIPs[i].total > topIPs[j].total })
	if len(topIPs) > 5 {
		topIPs = topIPs[:5]
	}

	var topResult []map[string]interface{}
	for _, e := range topIPs {
		topResult = append(topResult, map[string]interface{}{
			"ip": e.ip, "series": e.series, "total": e.total,
		})
	}

	return &accessStatsSnapshot{
		Timestamps:  timestamps,
		TotalSeries: totalSeries,
		TopIPs:      topResult,
	}
}

type accessStatsSnapshot struct {
	Timestamps  []string                 `json:"timestamps"`
	TotalSeries []int64                  `json:"total_series"`
	TopIPs      []map[string]interface{} `json:"top_ips"`
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	nodes, _ := s.store.LoadNodes()
	online, total, healthy := 0, len(nodes), 0
	now := time.Now()
	for _, n := range nodes {
		if now.Sub(n.LastSeen) < 5*time.Minute {
			online++
		}
		if n.Status.DDNSHealth != nil && n.Status.DDNSHealth.Status == "OK" {
			healthy++
		}
	}
	dnsKeys, _ := s.store.LoadDNSKeys()
	certs, _ := s.store.ListCertBundles()
	certsTotal := 0
	for _, c := range certs {
		if !strings.HasPrefix(c, "acme-") {
			certsTotal++
		}
	}
	jsonOK(w, map[string]interface{}{
		"nodes_total": total, "nodes_online": online, "nodes_healthy": healthy,
		"dns_keys": len(dnsKeys), "cert_bundles": certsTotal,
		"acme_bundles": len(certs),
	})
}

func (s *Server) handleAccessStats(w http.ResponseWriter, r *http.Request) {
	windowStr := r.URL.Query().Get("window")
	window := 60
	if windowStr != "" {
		if v, err := strconv.Atoi(windowStr); err == nil && v > 0 && v <= 2880 {
			window = v
		}
	}
	snapshot := s.accessCollector.snapshot(window)

	// also grab recent events from logger
	var recentEvents []interface{}
	if s.logMgr != nil {
		evs := s.logMgr.Query("", 10, 0)
		for _, e := range evs {
			recentEvents = append(recentEvents, e)
		}
	}

	jsonOK(w, map[string]interface{}{
		"timestamps":    snapshot.Timestamps,
		"total_series":  snapshot.TotalSeries,
		"top_ips":       snapshot.TopIPs,
		"recent_events": recentEvents,
	})
}

// ── admin: nodes ──

func (s *Server) StartSysInfoCollector(shutdown <-chan struct{}) {
	// immediate first sample
	s.updateSysInfo()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.updateSysInfo()
			case <-shutdown:
				return
			}
		}
	}()
}

func (s *Server) updateSysInfo() {
	cpu := sysinfo.CPUPercent()
	memUsed, memTotal := sysinfo.MemoryInfo()
	diskUsed, diskTotal := sysinfo.DiskInfo()
	s.sysInfoMu.Lock()
	s.sysInfoCache = map[string]interface{}{
		"cpu_percent":  cpu,
		"memory_used":  memUsed,
		"memory_total": memTotal,
		"disk_used":    diskUsed,
		"disk_total":   diskTotal,
	}
	s.sysInfoMu.Unlock()
}

func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	s.sysInfoMu.RLock()
	cached := s.sysInfoCache
	s.sysInfoMu.RUnlock()
	if cached == nil {
		jsonOK(w, map[string]interface{}{"cpu_percent": 0, "memory_used": 0, "memory_total": 0, "disk_used": 0, "disk_total": 0})
		return
	}
	jsonOK(w, cached)
}

