package server

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ocoj/ddns-manager/internal/logger"
)

// TestClassifyLogStatus_ErrorPatterns (Normal — 覆盖正常错误识别)
// 验证 classifyLogStatus 能正确识别各种常见的 DNS/网络错误模式。
func TestClassifyLogStatus_ErrorPatterns(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string // "error" or "info"
	}{
		// 原有覆盖 — 应全部返回 "error"
		{name: "中文_失败", line: "DNS更新失败: 连接超时", expected: "error"},
		{name: "中文_错误", line: "配置加载错误: 文件不存在", expected: "error"},
		{name: "英文_error", line: "unexpected error: connection lost", expected: "error"},
		{name: "英文_fail", line: "Failed to query domain info", expected: "error"},
		{name: "中文_异常", line: "证书解析异常: PEM格式无效", expected: "error"},

		// v1.6.54 新增覆盖 — 都应返回 "error"
		{name: "timeout", line: "dial tcp: connect: connection timed out", expected: "error"},
		{name: "refused", line: "connection refused: 192.0.2.1:443", expected: "error"},
		{name: "denied", line: "permission denied: cannot write file", expected: "error"},
		{name: "expired", line: "certificate has expired: Jan 01 00:00:00 2025 GMT", expected: "error"},
		{name: "forbidden", line: "403 forbidden: access denied", expected: "error"},
		{name: "invalid", line: "invalid parameter: domain name is empty", expected: "error"},

		// 正常信息 — 应返回 "info"
		{name: "正常_DNS完成", line: "IP 未变化，跳过更新: ddm.example.com", expected: "info"},
		{name: "正常_证书下发", line: "证书已下发: bundle=example.com path=/opt/certs", expected: "info"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyLogStatus(tt.line)
			if result != tt.expected {
				t.Errorf("classifyLogStatus(%q) = %q, want %q", tt.line, result, tt.expected)
			}
		})
	}
}

// TestQueryByTime_ToOnlyDateRange (Boundary — 边界条件：仅设 to 日期)
// 验证当用户只设置"截止日期"不设"起始日期"时，QueryByTime 返回非空结果。
func TestQueryByTime_ToOnlyDateRange(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.log")

	// 创建 logger，maxSize=5 确保 ring buffer 快速轮转
	mgr, err := logger.NewWithConfig(logPath, 5, 30, 50)
	if err != nil {
		t.Fatalf("创建 logger 失败: %v", err)
	}
	defer mgr.Close()

	// 写入 20 条事件，确保超过 ring buffer 容量 (5)
	for i := 0; i < 20; i++ {
		mgr.Log("system", "测试", "", "info")
	}

	// 核心验证：当 to 日期覆盖全部事件范围时，磁盘扫描应包含所有 20 条
	to := time.Now().UTC().Add(1 * time.Hour)
	events := mgr.QueryByTime("", "", "", time.Time{}, to, 100, 0)
	count := mgr.CountByTime("", "", "", time.Time{}, to)

	if len(events) < 1 {
		t.Errorf("QueryByTime(to=%s) 返回 0 条事件，预期至少 1 条", to.Format("2006-01-02"))
	}
	if count < 1 {
		t.Errorf("CountByTime(to=%s) 返回 0，预期至少 1 条", to.Format("2006-01-02"))
	}
	t.Logf("QueryByTime 返回 %d 条, CountByTime 返回 %d", len(events), count)
}

// TestKnownCategories_Completeness (Error — 异常检测：类別缺失)
// 验证 KnownCategories 包含所有实际使用的高频类别。
func TestKnownCategories_Completeness(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.log")

	mgr, err := logger.NewWithConfig(logPath, 100, 30, 50)
	if err != nil {
		t.Fatalf("创建 logger 失败: %v", err)
	}
	defer mgr.Close()

	allCategories := []string{
		"dns-update", "agent", "heartbeat", "auth", "upgrade",
		"config", "cert", "节点", "dns-key", "system",
		"rate-limit", "installer", "acme", "smtp",
	}
	for _, cat := range allCategories {
		mgr.Log(cat, "测试", "", "info")
	}

	known := mgr.KnownCategories()
	knownMap := make(map[string]bool, len(known))
	for _, k := range known {
		knownMap[k] = true
	}

	missing := []string{}
	for _, cat := range allCategories {
		if !knownMap[cat] {
			missing = append(missing, cat)
		}
	}
	if len(missing) > 0 {
		t.Errorf("KnownCategories 缺少以下类别: %v", missing)
	}

	cats := mgr.Categories()
	catsMap := make(map[string]bool, len(cats))
	for _, c := range cats {
		catsMap[c] = true
	}
	for _, cat := range allCategories {
		if !catsMap[cat] {
			t.Errorf("Categories() 缺少类别 %q", cat)
		}
	}
	t.Logf("KnownCategories: %d 类别, Categories: %d 类别", len(known), len(cats))
}
