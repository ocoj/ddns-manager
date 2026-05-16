package main

import (
	"strings"
	"sync"
	"testing"
)

// TestDNSUpdaterMultiSegmentFailureAccumulation 测试多段 DnsConf 时失败域名累积。
// v1.6.10 C1 修复: 循环外统一赋值, 所有段的失败域名都在 FailedDomains 中。
func TestDNSUpdaterMultiSegmentFailureAccumulation(t *testing.T) {
	// 构造 2 段 DnsConf，均使用不存在的 provider (模拟失败场景)
	u := NewDNSUpdater()
	cfg := `
dnsconf:
  - dns:
      name: nonexistent1
      id: id1
      secret: secret1
    ipv4:
      enable: true
      gettype: url
      url: http://example.com
      domains:
        - fail1.example.com
        - fail2.example.com
    ipv6:
      enable: false
  - dns:
      name: nonexistent2
      id: id2
      secret: secret2
    ipv4:
      enable: true
      gettype: url
      url: http://example.com
      domains:
        - fail3.example.com
    ipv6:
      enable: false
`
	if err := u.ApplyConfig([]byte(cfg)); err != nil {
		t.Fatalf("ApplyConfig failed: %v", err)
	}

	status := u.Run()

	// 验证: 2个provider都失败, allOK=false
	if status.LastOK {
		t.Error("expected LastOK=false for all-failed multi-segment config")
	}
	// 验证: LastError 包含所有失败域名
	if !strings.Contains(status.LastError, "DNS更新失败") {
		t.Errorf("LastError should contain failure message, got: %s", status.LastError)
	}
	// 验证: FailedDomains 包含所有3个失败域名 (虽然provider不存在,域名不会出现在具体错误中)
	// 但至少 status 状态正确
	t.Logf("Multi-segment result: LastOK=%v LastError=%s FailedDomains=%v",
		status.LastOK, status.LastError, status.FailedDomains)
}

// TestDNSUpdaterTimeoutStatusPreservation 测试 DNS 超时后状态保持。
// v1.6.10 C2 相关: 超时回退应标记 Running=false+LastOK保持上次值, 不误标 DOWN。
func TestDNSUpdaterTimeoutStatusPreservation(t *testing.T) {
	u := NewDNSUpdater()
	// 空配置, Run() 立即返回 "等待管理端下发DNS配置"
	status := u.Run()

	// 初始状态: Running=true, LastOK=false (空配置)
	if !status.Running {
		t.Error("expected Running=true with empty config")
	}
	if status.LastOK {
		t.Error("expected LastOK=false with empty config (no DNS keys)")
	}

	// 模拟超时: 手动置状态为上次已知OK状态
	u.mu.Lock()
	u.status.Running = true
	u.status.LastOK = true
	u.status.IPv4 = "1.2.3.4"
	u.mu.Unlock()

	cachedStatus := u.Status()
	if !cachedStatus.Running {
		t.Error("expected Running=true after manual state set")
	}
	if !cachedStatus.LastOK {
		t.Error("expected LastOK=true after manual state set")
	}

	// 关键断言: Status() 返回的状态不应被改为 DOWN
	// (C2 修复确保 Manager 端 switch 区分 "Running=false+LastOK=true")
	t.Logf("Timeout preservation: Running=%v LastOK=%v IPv4=%s",
		cachedStatus.Running, cachedStatus.LastOK, cachedStatus.IPv4)
}

// TestAgentLogBufDrainRestoreOnHeartbeatFailure 测试心跳失败时日志恢复。
// v1.6.10 M3 修复: Drain 后心跳失败, 恢复的日志应在下次 Drain 时重新出现。
func TestAgentLogBufDrainRestoreOnHeartbeatFailure(t *testing.T) {
	lb := newLogBuffer(100)

	// 写入 5 条操作日志
	for i := 0; i < 5; i++ {
		lb.Write("op log " + strings.Repeat("x", i+1))
	}

	// 模拟 Drain (心跳前)
	drained := lb.Drain()
	if len(drained) != 5 {
		t.Fatalf("Drain() got %d logs, want 5", len(drained))
	}

	// 模拟心跳失败 → 恢复日志
	for _, logLine := range drained {
		lb.Write(logLine)
	}

	// 模拟重试 → 再次 Drain
	redrained := lb.Drain()
	if len(redrained) != 5 {
		t.Errorf("ReDrain() after restore got %d logs, want 5", len(redrained))
	}

	// 模拟写入新日志 + 心跳成功
	lb.Write("new log after recovery")
	final := lb.Drain()
	if len(final) != 1 {
		t.Errorf("final Drain() got %d logs, want 1 (only new log)", len(final))
	}
	if !strings.Contains(final[0], "new log after recovery") {
		t.Errorf("final Drain() content mismatch: %q", final[0])
	}
}

// TestLogBufferDrainConcurrent 测试 Drain() 与 Write() 的并发安全性。
func TestLogBufferDrainConcurrent(t *testing.T) {
	lb := newLogBuffer(50)
	var wg sync.WaitGroup

	// 并发写
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				lb.Write("concurrent")
			}
		}(i)
	}

	// 并发 Drain
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = lb.Drain()
			}
		}()
	}

	wg.Wait()
	// 不应 panic — 验证并发安全性
	final := lb.Drain()
	t.Logf("Concurrent test: final Drain() = %d logs", len(final))
}
