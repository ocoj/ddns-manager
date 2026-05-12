// Package logger provides structured event logging for ddns-manager.
package logger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Event represents a single log entry.
type Event struct {
	Time     time.Time `json:"time"`
	Category string    `json:"category"`
	Action   string    `json:"action"`
	Node     string    `json:"node,omitempty"`
	Detail   string    `json:"detail"`
	Status   string    `json:"status"` // success, error, warning, info
	IP       string    `json:"ip,omitempty"`
	User     string    `json:"user,omitempty"`
}

// statusIconMap maps event statuses to display symbols (package-level to avoid per-event allocations).
var statusIconMap = map[string]string{
	"success": "✓", "error": "✗", "warning": "!", "info": "→",
}

// Manager handles structured logging.
type Manager struct {
	mu         sync.Mutex   // protects ring buffer (events, writeIdx)
	fileMu     sync.Mutex   // protects file writes and rotation
	file       *os.File
	logPath    string
	events     []Event       // in-memory ring buffer
	maxSize    int
	writeIdx      int        // ring buffer write index (wraps at 2^63)
	retention     int        // days to retain log files
	lastRotate    time.Time  // tracks last log file rotation
	lastDiskCheck time.Time  // tracks last disk space check (debounce)
	maxFileMB     int        // rotate when file exceeds this
	tz           *time.Location // 时区，用于日志轮转日期文件名
}

// New creates a Logger that writes to the given file path.
func New(logPath string, maxSize int) (*Manager, error) {
	return NewWithConfig(logPath, maxSize, 30, 50)
}

// NewWithConfig creates a Logger with full configuration.
// logPath: path to event log file
// maxSize: in-memory ring buffer size
// retentionDays: used only for manual cleanup (NOT auto)
// maxFileMB: rotate when log file exceeds this many MB
func NewWithConfig(logPath string, maxSize, retentionDays, maxFileMB int) (*Manager, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if maxSize < 100 {
		maxSize = 10000
	}
	if retentionDays < 1 {
		retentionDays = 30
	}
	if maxFileMB < 1 {
		maxFileMB = 50
	}
	m := &Manager{
		file:       f,
		logPath:    logPath,
		events:     make([]Event, maxSize),
		maxSize:       maxSize,
		retention:     retentionDays,
		lastRotate:    time.Now(),
		lastDiskCheck: time.Now(),
		maxFileMB:     maxFileMB,
		tz:            time.Local,
	}
	m.reloadFromDisk()
	return m, nil
}

// SetTimezone 设置时区，影响日志文件轮转日期文件名。
func (m *Manager) SetTimezone(loc *time.Location) {
	if loc != nil {
		m.tz = loc
	}
}

// reloadFromDisk reads recent events from the log file into ring buffer.
// Uses tail-based reading: for large files, only reads the last ~2MB to avoid
// loading the entire file into memory (which can be 50MB+).
func (m *Manager) reloadFromDisk() {
	f, err := os.Open(m.logPath)
	if err != nil {
		return
	}
	defer f.Close()

	const tailChunk = 2 << 20 // 2MB tail read for large files

	fi, err := f.Stat()
	if err != nil {
		return
	}

	var scanner *bufio.Scanner
	totalEvents := 0

	if fi.Size() <= tailChunk+int64(m.maxSize*256) {
		// small file: read everything
		scanner = bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
	} else {
		// large file: seek to end - tailChunk, skip first partial line
		offset := fi.Size() - tailChunk
		if offset < 0 {
			offset = 0
		}
		if _, err := f.Seek(offset, 0); err != nil {
			scanner = bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 1<<20), 1<<20)
			// fall through to normal scan
		} else {
			// discard the first (probably partial) line
			tmp := bufio.NewScanner(f)
			tmp.Buffer(make([]byte, 1<<20), 1<<20)
			if tmp.Scan() {
				_ = tmp.Text() // skip partial first line
			}
			// estimate total events from file size (avg ~200 bytes/event)
			totalEvents = int(fi.Size() / 200)
			scanner = tmp
		}
	}

	var allEvents []Event
	if totalEvents > m.maxSize*2 {
		allEvents = make([]Event, 0, m.maxSize)
	} else {
		allEvents = make([]Event, 0, m.maxSize/4+1)
	}
	for scanner.Scan() {
		var e Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err == nil {
			allEvents = append(allEvents, e)
		}
	}

	// load last maxSize into ring buffer
	start := 0
	if len(allEvents) > m.maxSize {
		start = len(allEvents) - m.maxSize
	}

	m.mu.Lock()
	for i, e := range allEvents[start:] {
		m.events[i] = e
	}
	// writeIdx: if we tail-read, totalEvents is an estimate; correct it
	if totalEvents > 0 && totalEvents > len(allEvents) {
		m.writeIdx = totalEvents
	} else {
		m.writeIdx = len(allEvents)
	}
	m.mu.Unlock()

	log.Printf("[logger] 从磁盘回读 %d 条事件 (缓存 %d)", len(allEvents), len(allEvents)-start)
}

// EnsureDiskSpace checks disk usage and frees space when free disk falls below 10%.
// Deletes the oldest log file(s) until >10% free (i.e. used < 90%).
func (m *Manager) EnsureDiskSpace() (freedFiles int, freedMB float64) {
	dir := filepath.Dir(m.logPath)
	
	// usage is the percentage of blocks used; we want at least 10% free
	usage := m.diskUsagePercent(dir)
	if usage >= 0 && usage < 90 {
		return 0, 0 // enough free space (>10%)
	}
	
	log.Printf("[logger] 磁盘已用 %.0f%% ≥ 90%%，开始释放空间", usage)
	
	// Collect all log files (current + rotated)
	var logFiles []os.FileInfo
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, _ := e.Info()
		if info != nil && (strings.HasPrefix(e.Name(), "events") || strings.HasPrefix(e.Name(), "events-")) && strings.HasSuffix(e.Name(), ".log") {
			logFiles = append(logFiles, info)
		}
	}
	if len(logFiles) == 0 {
		return 0, 0
	}
	
	// Sort oldest first
	sort.Slice(logFiles, func(i, j int) bool {
		return logFiles[i].ModTime().Before(logFiles[j].ModTime())
	})
	
	// Delete oldest files until space > 10% or only current file remains
	currentName := filepath.Base(m.logPath)
	for _, fi := range logFiles {
		if fi.Name() == currentName {
			continue // never delete the current log file
		}
		path := filepath.Join(dir, fi.Name())
		os.Remove(path)
		mb := float64(fi.Size()) / (1 << 20)
		freedFiles++
		freedMB += mb
		log.Printf("[logger] 空间不足，已删除: %s (%.1fMB)", fi.Name(), mb)
		
		usage = m.diskUsagePercent(dir)
		if usage < 0 || usage < 90 {
			break
		}
	}
	
	if freedFiles > 0 {
		log.Printf("[logger] 释放完成: %d 个文件, %.1fMB, 当前使用 %.0f%%", freedFiles, freedMB, usage)
	}
	return
}

func (m *Manager) diskUsagePercent(dir string) float64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return -1
	}
	if stat.Blocks == 0 {
		return -1
	}
	used := stat.Blocks - stat.Bfree
	return float64(used) / float64(stat.Blocks) * 100
}

// CleanupBefore deletes log files with content before the given date.
func (m *Manager) CleanupBefore(before time.Time) (deletedFiles int, deletedMB float64) {
	dir := filepath.Dir(m.logPath)
	currentName := filepath.Base(m.logPath)
	
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() || e.Name() == currentName {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "events-") || !strings.HasSuffix(name, ".log") {
			continue
		}
		// Parse date from filename: events-2026-05-03.log
		dateStr := strings.TrimPrefix(strings.TrimSuffix(name, ".log"), "events-")
		fileDate, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			continue
		}
		if fileDate.Before(before) {
			info, _ := e.Info()
			path := filepath.Join(dir, name)
			os.Remove(path)
			deletedFiles++
			if info != nil {
				deletedMB += float64(info.Size()) / (1 << 20)
			}
			log.Printf("[logger] 手动清理: %s", name)
		}
	}
	return
}

// ArchiveLogs creates a tar.gz of all log files and returns the path.
func (m *Manager) ArchiveLogs() (string, error) {
	dir := filepath.Dir(m.logPath)
	tmpFile, err := os.CreateTemp("", "ddns-logs-*.tar.gz")
	if err != nil {
		return "", err
	}
	tmpFile.Close()
	
	args := []string{"-czf", tmpFile.Name(), "-C", dir}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "events") && strings.HasSuffix(name, ".log") {
			args = append(args, name)
		}
	}
	
	cmd := exec.Command("tar", args...)
	if err := cmd.Run(); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}
	return tmpFile.Name(), nil
}

// ListLogFiles returns information about all log files.
func (m *Manager) ListLogFiles() []map[string]interface{} {
	dir := filepath.Dir(m.logPath)
	entries, _ := os.ReadDir(dir)
	var result []map[string]interface{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "events") || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		info, _ := e.Info()
		item := map[string]interface{}{
			"name":  e.Name(),
			"size":  info.Size(),
			"mtime": info.ModTime(),
		}
		// Try to extract date range
		item["type"] = "active"
		if strings.HasPrefix(e.Name(), "events-") {
			item["type"] = "rotated"
		}
		result = append(result, item)
	}
	return result
}

// rotateIfNeeded rotates the log file if it exceeds maxFileMB.
func (m *Manager) rotateIfNeeded() {
	info, err := m.file.Stat()
	if err != nil {
		return
	}
	mb := int(info.Size() / (1 << 20))
	if mb < m.maxFileMB {
		return
	}

	m.file.Close()
	rotated := strings.TrimSuffix(m.logPath, ".log") + "-" + time.Now().In(m.tz).Format("2006-01-02") + ".log"
	os.Rename(m.logPath, rotated)

	f, err := os.OpenFile(m.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("[logger] 轮转失败: %v", err)
		return
	}
	m.file = f
	m.lastRotate = time.Now()
	log.Printf("[logger] 日志已轮转 → %s", rotated)
}

// Log records an event to file and memory.
// Timestamps are stored in UTC — use DisplayTime / FormatEventInTZ for local display.
func (m *Manager) Log(category, action, detail, status string) {
	e := Event{
		Time:     time.Now().UTC(),
		Category: category,
		Action:   action,
		Detail:   detail,
		Status:   status,
	}
	m.logEvent(e)
}

// LogWithNode records a node-related event.
func (m *Manager) LogWithNode(category, action, node, detail, status string) {
	e := Event{
		Time:     time.Now().UTC(),
		Category: category,
		Action:   action,
		Node:     node,
		Detail:   detail,
		Status:   status,
	}
	m.logEvent(e)
}

// LogAuth records an authentication event.
func (m *Manager) LogAuth(action, user, ip, detail, status string) {
	e := Event{
		Time:     time.Now().UTC(),
		Category: "auth",
		Action:   action,
		User:     user,
		IP:       ip,
		Detail:   detail,
		Status:   status,
	}
	m.logEvent(e)
}

func (m *Manager) logEvent(e Event) {
	// Fast path: ring buffer write under dedicated lock (no I/O)
	m.mu.Lock()
	m.events[m.writeIdx%m.maxSize] = e
	m.writeIdx++
	m.mu.Unlock()

	// File I/O under separate lock to avoid blocking ring buffer readers during disk ops
	m.fileMu.Lock()
	defer m.fileMu.Unlock()

	// rotate if needed
	m.rotateIfNeeded()

	// check disk space (debounced, once per minute)
	if m.lastDiskCheck.Add(time.Minute).Before(time.Now()) {
		m.EnsureDiskSpace()
		m.lastDiskCheck = time.Now()
	}

	// write to file (check error in production; log to stderr as last resort)
	data, _ := json.Marshal(e)
	if _, err := m.file.Write(append(data, '\n')); err != nil {
		log.Printf("[logger] write error: %v", err)
	}

	// 终端实时输出 (在锁外执行)
	statusIcon := statusIconMap[e.Status]
	if statusIcon == "" {
		statusIcon = "·"
	}
	extra := ""
	if e.Node != "" {
		extra += fmt.Sprintf(" 节点=%s", e.Node)
	}
	if e.IP != "" {
		extra += fmt.Sprintf(" IP=%s", e.IP)
	}
	log.Printf("[%s] %s %s: %s%s", e.Category, statusIcon, e.Action, e.Detail, extra)
}

// Query returns events matching filters, newest first.
// status: ""=all, "success", "error", "warning", "info"
// category: ""=all, "heartbeat", "config", "auth", etc.
func (m *Manager) Query(category string, limit int, offset int) []Event {
	return m.QueryFiltered(category, "", limit, offset)
}

// QueryFiltered returns events with category AND status filters.
func (m *Manager) QueryFiltered(category, status string, limit, offset int) []Event {
	if limit <= 0 {
		limit = 50
	}
	if limit > 5000 {
		limit = 5000
	}

	// snapshot ring buffer under lock
	m.mu.Lock()
	total := m.writeIdx
	if total > m.maxSize {
		total = m.maxSize
	}
	start := m.writeIdx - total
	if start < 0 {
		start = 0
	}
	snapshot := make([]Event, 0, total)
	for i := start; i < m.writeIdx; i++ {
		e := m.events[i%m.maxSize]
		if !e.Time.IsZero() {
			snapshot = append(snapshot, e)
		}
	}
	m.mu.Unlock()

	// filter outside lock
	var filtered []Event
	for _, e := range snapshot {
		if category != "" && e.Category != category {
			continue
		}
		if status != "" && e.Status != status {
			continue
		}
		filtered = append(filtered, e)
	}

	// newest first
	if len(filtered) > 1 {
		for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
			filtered[i], filtered[j] = filtered[j], filtered[i]
		}
	}

	if offset >= len(filtered) {
		return nil
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	return filtered[offset:end]
}

// Count returns total events matching filter.
func (m *Manager) Count(category string) int {
	return m.CountFiltered(category, "")
}

// CountFiltered returns event count with filters.
func (m *Manager) CountFiltered(category, status string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	total := m.writeIdx
	if total > m.maxSize {
		total = m.maxSize
	}
	start := m.writeIdx - total
	if start < 0 {
		start = 0
	}
	for i := start; i < m.writeIdx; i++ {
		e := m.events[i%m.maxSize]
		if e.Time.IsZero() {
			continue
		}
		if category != "" && e.Category != category {
			continue
		}
		if status != "" && e.Status != status {
			continue
		}
		n++
	}
	return n
}

// QueryByTime returns events matching filters AND within a time range.
// from/to can be zero-time (time.Time{}) meaning "no bound".
// node="" means no node filter.
func (m *Manager) QueryByTime(category, status, node string, from, to time.Time, limit, offset int) []Event {
	if limit <= 0 {
		limit = 50
	}
	if limit > 5000 {
		limit = 5000
	}

	m.mu.Lock()
	total := m.writeIdx
	if total > m.maxSize {
		total = m.maxSize
	}
	start := m.writeIdx - total
	if start < 0 {
		start = 0
	}
	snapshot := make([]Event, 0, total)
	for i := start; i < m.writeIdx; i++ {
		e := m.events[i%m.maxSize]
		if !e.Time.IsZero() {
			snapshot = append(snapshot, e)
		}
	}
	m.mu.Unlock()

	var filtered []Event
	for _, e := range snapshot {
		if category != "" && e.Category != category {
			continue
		}
		if status != "" && e.Status != status {
			continue
		}
		if node != "" && e.Node != node {
			continue
		}
		if !from.IsZero() && e.Time.Before(from) {
			continue
		}
		if !to.IsZero() && e.Time.After(to) {
			continue
		}
		filtered = append(filtered, e)
	}

	if len(filtered) > 1 {
		for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
			filtered[i], filtered[j] = filtered[j], filtered[i]
		}
	}

	if offset >= len(filtered) {
		return nil
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	return filtered[offset:end]
}

// Categories returns distinct categories.
func (m *Manager) Categories() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]bool{}
	total := m.writeIdx
	if total > m.maxSize {
		total = m.maxSize
	}
	start := m.writeIdx - total
	if start < 0 {
		start = 0
	}
	for i := start; i < m.writeIdx; i++ {
		e := m.events[i%m.maxSize]
		if e.Time.IsZero() {
			continue
		}
		seen[e.Category] = true
	}
	var cats []string
	for k := range seen {
		if k != "" {
			cats = append(cats, k)
		}
	}
	sort.Strings(cats)
	return cats
}

// Statuses returns distinct status values in the ring buffer.
func (m *Manager) Statuses() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]bool{}
	total := m.writeIdx
	if total > m.maxSize {
		total = m.maxSize
	}
	start := m.writeIdx - total
	if start < 0 {
		start = 0
	}
	for i := start; i < m.writeIdx; i++ {
		e := m.events[i%m.maxSize]
		if e.Time.IsZero() {
			continue
		}
		if e.Status != "" {
			seen[e.Status] = true
		}
	}
	var ss []string
	for s := range seen {
		ss = append(ss, s)
	}
	sort.Strings(ss)
	return ss
}

// Stats returns log statistics.
func (m *Manager) Stats() map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	byCategory := map[string]int{}
	byStatus := map[string]int{}
	total := m.writeIdx
	if total > m.maxSize {
		total = m.maxSize
	}
	start := m.writeIdx - total
	if start < 0 {
		start = 0
	}
	for i := start; i < m.writeIdx; i++ {
		e := m.events[i%m.maxSize]
		if e.Time.IsZero() {
			continue
		}
		byCategory[e.Category]++
		byStatus[e.Status]++
	}
	fileSize := int64(0)
	if info, err := os.Stat(m.logPath); err == nil {
		fileSize = info.Size()
	}
	return map[string]interface{}{
		"total_events": total,
		"by_category":  byCategory,
		"by_status":    byStatus,
		"file_size":    fileSize,
		"retention":    m.retention,
	}
}

// Close flushes and closes the log file.
func (m *Manager) Close() error {
	return m.file.Close()
}

// FormatTime formats a time for display (uses the time's embedded timezone).
func FormatTime(t time.Time) string { return t.Format("2006-01-02 15:04:05") }

// DisplayTime converts a UTC-stored time to the logger's configured timezone for display.
func (m *Manager) DisplayTime(t time.Time) string {
	return t.In(m.tz).Format("2006-01-02 15:04:05")
}

// FormatEventInTZ formats an event for display in the logger's configured timezone.
func (m *Manager) FormatEventInTZ(e Event) string {
	extra := ""
	if e.Node != "" {
		extra += fmt.Sprintf(" node=%s", e.Node)
	}
	if e.User != "" {
		extra += fmt.Sprintf(" user=%s", e.User)
	}
	if e.IP != "" {
		extra += fmt.Sprintf(" ip=%s", e.IP)
	}
	return fmt.Sprintf("%s [%s] %s: %s%s (%s)", m.DisplayTime(e.Time), e.Category, e.Action, e.Detail, extra, e.Status)
}

// FormatEvent formats an event for human-readable display (legacy, uses embedded timezone).
func FormatEvent(e Event) string {
	extra := ""
	if e.Node != "" {
		extra += fmt.Sprintf(" node=%s", e.Node)
	}
	if e.User != "" {
		extra += fmt.Sprintf(" user=%s", e.User)
	}
	if e.IP != "" {
		extra += fmt.Sprintf(" ip=%s", e.IP)
	}
	return fmt.Sprintf("%s [%s] %s: %s%s (%s)", FormatTime(e.Time), e.Category, e.Action, e.Detail, extra, e.Status)
}
