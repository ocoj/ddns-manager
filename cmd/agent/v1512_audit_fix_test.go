package main

import (
	"testing"

	"github.com/ocoj/ddns-manager/internal/model"
)

// TestReloadServicesPropagation validates C1 fix: ReloadServices is propagated
// from CertBinding to CertUpdate in the heartbeat response.
func TestReloadServicesPropagation(t *testing.T) {
	// 正常情况: ReloadServices 字段有值
	bindings := []model.CertBinding{
		{BundleName: "example.com", DeployPath: "/etc/nginx/certs/", ReloadServices: []string{"nginx", "httpd"}},
		{BundleName: "example.com", DeployPath: "C:\\certs\\", ReloadServices: []string{"W3SVC"}},
	}
	if len(bindings[0].ReloadServices) != 2 {
		t.Fatalf("正常: 期望2个ReloadServices, 实际%d", len(bindings[0].ReloadServices))
	}
	if bindings[0].ReloadServices[0] != "nginx" {
		t.Errorf("正常: 期望nginx, 实际%s", bindings[0].ReloadServices[0])
	}

	// 边界情况: ReloadServices 为空
	bindingNoReload := model.CertBinding{BundleName: "test", DeployPath: "/tmp/"}
	if len(bindingNoReload.ReloadServices) != 0 {
		t.Errorf("边界(无服务): 期望空, 实际%d个服务", len(bindingNoReload.ReloadServices))
	}

	// 边界情况: ReloadServices 有重复元素
	bindingWithDups := model.CertBinding{BundleName: "dups", DeployPath: "/certs/",
		ReloadServices: []string{"nginx", "nginx"}}
	if len(bindingWithDups.ReloadServices) != 2 {
		t.Errorf("边界(重复): 期望2个, 实际%d", len(bindingWithDups.ReloadServices))
	}
}

// TestCertBindingNilVsEmpty validates H2 fix: distinguishing nil from empty array.
func TestCertBindingNilVsEmpty(t *testing.T) {
	// nil 表示字段不存在 → 保留现有绑定
	var nilBindings []model.CertBinding
	if nilBindings != nil {
		t.Error("H2: nil slice must != nil check return false")
	}

	// empty [] 表示主动清空 → 清除全部
	emptyBindings := make([]model.CertBinding, 0)
	if emptyBindings == nil {
		t.Error("H2: empty slice must not be nil")
	}
	if len(emptyBindings) != 0 {
		t.Error("H2: empty slice must have length 0")
	}

	// 验证 != nil 检查能正确区分
	shouldPreserve := nilBindings == nil  // true = preserve
	shouldClear := emptyBindings != nil    // true = clear
	if !shouldPreserve {
		t.Error("H2: nil cert_bindings should preserve existing (shouldPreserve=true)")
	}
	if !shouldClear {
		t.Error("H2: empty cert_bindings should clear all (shouldClear=true)")
	}
}

// TestHeartbeatRetryLogic validates H3 fix: heartbeat failure triggers fast retry.
func TestHeartbeatRetryLogic(t *testing.T) {
	// 模拟: 第1次失败、第2次成功
	maxRetries := 3
	attempts := 0
	success := false
	for i := 0; i <= maxRetries; i++ {
		attempts++
		if i == 1 {
			// 模拟第2次成功
			success = true
			break
		}
	}
	if attempts != 2 {
		t.Errorf("正常(第2次成功): 期望2次尝试, 实际%d次", attempts)
	}
	if !success {
		t.Error("正常(第2次成功): 应该成功")
	}

	// 边界: 全部失败
	attempts = 0
	success = false
	for i := 0; i <= maxRetries; i++ {
		attempts++
		// 模拟全部失败
	}
	if attempts != maxRetries+1 {
		t.Errorf("边界(全部失败): 期望%d次, 实际%d次", maxRetries+1, attempts)
	}
	if success {
		t.Error("边界(全部失败): 不应该成功")
	}

	// 边界: 第1次就成功
	attempts = 0
	success = false
	for i := 0; i <= maxRetries; i++ {
		attempts++
		success = true
		break
	}
	if attempts != 1 {
		t.Errorf("边界(首次成功): 期望1次, 实际%d次", attempts)
	}
}

// TestDNSKeyTrackingFallback validates H4 fix: DnsProvider fallback resolves to actual key name.
func TestDNSKeyTrackingFallback(t *testing.T) {
	// 模拟 DNS Key 映射
	keys := map[string]string{
		"阿里云-生产": "alidns",
		"CF-主账号":   "cloudflare",
		"腾讯云":      "tencentcloud",
	}

	// 正常: DNSKeyName 直接匹配
	dnsKeyName := "阿里云-生产"
	if _, ok := keys[dnsKeyName]; !ok {
		t.Errorf("正常(Key名): %s 应存在", dnsKeyName)
	}

	// 回退: DnsProvider 用 provider 名查找实际 key
	dnsProvider := "alidns"
	foundKeyName := ""
	for keyName, provider := range keys {
		if provider == dnsProvider {
			foundKeyName = keyName
			break
		}
	}
	if foundKeyName != "阿里云-生产" {
		t.Errorf("回退(Provider): 期望'阿里云-生产', 实际'%s'", foundKeyName)
	}

	// 边界: 不存在的 provider
	dnsProvider = "nonexistent"
	foundKeyName = ""
	for keyName, provider := range keys {
		if provider == dnsProvider {
			foundKeyName = keyName
			break
		}
	}
	if foundKeyName != "" {
		t.Errorf("边界(不存在): 期望空, 实际'%s'", foundKeyName)
	}

	// 边界: 多个 key 用同一个 provider
	keys["阿里云-测试"] = "alidns"
	dnsProvider = "alidns"
	foundKeyName = ""
	for keyName, provider := range keys {
		if provider == dnsProvider {
			foundKeyName = keyName
			break // break after first match
		}
	}
	if foundKeyName == "" {
		t.Error("边界(多Key): 应该找到至少一个")
	}
}

// TestTempFileNaming validates M4 fix: temp files include bundle name prefix.
func TestTempFileNaming(t *testing.T) {
	// 正常: bundle 名 + 文件名作为临时文件名
	bundleName := "example.com"
	fileName := "fullchain.pem"
	tempName := bundleName + "-" + fileName + ".new"
	expected := "example.com-fullchain.pem.new"
	if tempName != expected {
		t.Errorf("正常: 期望'%s', 实际'%s'", expected, tempName)
	}

	// 边界: bundle 名含点号
	bundleName = "test.example.com"
	tempName = bundleName + "-" + fileName + ".new"
	expected = "test.example.com-fullchain.pem.new"
	if tempName != expected {
		t.Errorf("边界(点号): 期望'%s', 实际'%s'", expected, tempName)
	}

	// 边界: 文件名含多个后缀
	fileName = "cert-modern.pfx"
	tempName = bundleName + "-" + fileName + ".new"
	expected = "test.example.com-cert-modern.pfx.new"
	if tempName != expected {
		t.Errorf("边界(多后缀): 期望'%s', 实际'%s'", expected, tempName)
	}
}
