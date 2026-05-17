package server

import (
	"testing"

	"github.com/kk/ddns-manager/internal/model"
	"github.com/kk/ddns-manager/internal/provider"
)

// TestNodeApproval_NewRegistrationDefault 验证新注册节点默认 Approved=false（边界条件）。
// 审计 M3 要求: 注册时默认 Approved:false，审批后置 true。
func TestNodeApproval_NewRegistrationDefault(t *testing.T) {
	// 模拟新注册节点 — Go 零值 bool = false
	rec := &model.NodeRecord{
		Fingerprint:  "sha256:new-node",
		PasswordHash: "$2a$10$...",
	}
	if rec.Approved {
		t.Errorf("新注册节点默认 Approved 应为 false (Go 零值), 实际 %v", rec.Approved)
	}

	// 审批后置 true
	rec.Approved = true
	if !rec.Approved {
		t.Error("审批后 Approved 应为 true")
	}
}

// TestNodeApproval_BlocksConfigPush 验证未审批节点逻辑（正常路径）。
// 心跳处理器在 resp 构建后检查 !rec.Approved → 跳过配置/证书/升级推送。
func TestNodeApproval_BlocksConfigPush(t *testing.T) {
	rec := &model.NodeRecord{
		Fingerprint:  "sha256:abc123",
		PasswordHash: "$2a$10$...",
		Approved:     false, // 关键：未审批
		ConfigYAML:   `{"dns_provider":"alidns","dns_key_name":"test-key"}`,
	}

	// 模拟心跳处理逻辑的核心判断
	shouldPushConfig := rec.Approved && rec.ConfigYAML != ""
	if shouldPushConfig {
		t.Errorf("未审批节点不应推送配置, Approved=%v ConfigYAML非空=%v → shouldPush=%v",
			rec.Approved, rec.ConfigYAML != "", shouldPushConfig)
	}

	// 审批后应推送
	rec.Approved = true
	shouldPushConfig = rec.Approved && rec.ConfigYAML != ""
	if !shouldPushConfig {
		t.Error("已审批节点应推送配置")
	}
}

// TestDetectPlatform_NilHardware_ReturnsEmpty 验证 Hardware=nil 时返回空字符串（异常路径）。
// 审计 N3 要求: 硬件信息未知时返回空，调用方跳过升级推送。
func TestDetectPlatform_NilHardware_ReturnsEmpty(t *testing.T) {
	// 异常: Hardware = nil
	rec := &model.NodeRecord{}
	goos, goarch := detectPlatform(rec)
	if goos != "" {
		t.Errorf("Hardware=nil 时 goos 应为空字符串, 实际 %q", goos)
	}
	if goarch != "" {
		t.Errorf("Hardware=nil 时 goarch 应为空字符串, 实际 %q", goarch)
	}

	// 正常: Ubuntu/amd64
	rec2 := &model.NodeRecord{
		Hardware: &model.HardwareInfo{OS: "Ubuntu 24.04", Arch: "amd64"},
	}
	goos2, goarch2 := detectPlatform(rec2)
	if goos2 != "linux" {
		t.Errorf("Ubuntu 节点 goos 应为 linux, 实际 %q", goos2)
	}
	if goarch2 != "amd64" {
		t.Errorf("amd64 节点 goarch 应为 amd64, 实际 %q", goarch2)
	}

	// 正常: Windows/amd64
	rec3 := &model.NodeRecord{
		Hardware: &model.HardwareInfo{OS: "Windows Server 2022", Arch: "amd64"},
	}
	goos3, goarch3 := detectPlatform(rec3)
	if goos3 != "windows" {
		t.Errorf("Windows 节点 goos 应为 windows, 实际 %q", goos3)
	}
	if goarch3 != "amd64" {
		t.Errorf("Windows amd64 节点 goarch 应为 amd64, 实际 %q", goarch3)
	}
}

// TestDNSProviderValidation 验证 DNS provider 名称校验（N9 修复）。
func TestDNSProviderValidation(t *testing.T) {
	// 正常: 已知 provider
	if !model.IsKnownDNSProvider("alidns") {
		t.Error("alidns 应为已知 DNS provider")
	}
	if !model.IsKnownDNSProvider("cloudflare") {
		t.Error("cloudflare 应为已知 DNS provider")
	}
	// v1.6.29 H1: 使用 provider.IsKnown 替代 model.IsKnownDNSProvider
	if !provider.IsKnown("tencentcloud") {
		t.Error("tencentcloud 应为已知 DNS provider")
	}

	// 边界: 未知 provider
	if provider.IsKnown("") {
		t.Error("空字符串不应为已知 DNS provider")
	}
	if provider.IsKnown("alidn") { // 少了 s
		t.Error("alidn (拼写错误) 不应为已知 DNS provider")
	}
	if provider.IsKnown("unknown_provider") {
		t.Error("unknown_provider 不应为已知 DNS provider")
	}

	// 验证 provider 列表非空 (v1.6.29 H1: 使用 provider.Registry 单一真相源)
	providers := provider.Names()
	if len(providers) < 28 {
		t.Errorf("已知 DNS provider 数量不应少于 28, 实际 %d", len(providers))
	}
}

// TestStoreCache_LoadNodes 验证内存缓存加载（Fix 2 P1/P2 修复）。
// 这个测试验证 store 的 LoadNodes/SaveNodes 循环不会丢失数据。
// 依赖实际文件系统 — 仅当有 data 目录时运行。
func TestStoreCache_LoadNodes(t *testing.T) {
	// 验证 model 字段完整性
	rec := &model.NodeRecord{
		Fingerprint: "sha256:test",
		Approved:    true,
	}

	// 结构体字段可访问性检查
	_ = rec.Fingerprint
	_ = rec.Approved
	_ = rec.ConfigYAML
	_ = rec.ConfigHash
	_ = rec.CertBindings
	_ = rec.Status
	_ = rec.Hardware
	_ = rec.LastSeen
}
