package model

import (
	"testing"
)

// TestSanitizeCertDirName v1.6.50 H1: 验证泛域名证书目录名跨平台合法化。
// 覆盖: 正常名 / 泛域名(含*) / 空串 / 多星 / 无星
func TestSanitizeCertDirName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"正常域名", "example.com", "example.com"},
		{"泛域名_单星", "*.example.com", "_.example.com"},
		{"空串", "", ""},
		{"多星泛域名", "*.*.example.com", "_._.example.com"},
		{"仅有星号", "*", "_"},
		{"含下划线无星", "_example.com", "_example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeCertDirName(tt.input)
			if got != tt.expected {
				t.Errorf("SanitizeCertDirName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestSanitizeCertDirName_Idempotent 验证幂等性: 多次调用结果一致。
func TestSanitizeCertDirName_Idempotent(t *testing.T) {
	input := "*.example.com"
	first := SanitizeCertDirName(input)
	for i := 0; i < 5; i++ {
		if got := SanitizeCertDirName(input); got != first {
			t.Errorf("幂等性失败: 第%d次调用 %q, 预期 %q", i+1, got, first)
		}
	}
	// 验证对已处理结果再次处理不变
	twice := SanitizeCertDirName(first)
	if twice != first {
		t.Errorf("重复处理失败: SanitizeCertDirName(SanitizeCertDirName(%q)) = %q, want %q",
			input, twice, first)
	}
}

// TestSanitizeCertDirName_Unchanged 验证不含*的串完全不变 (零副作用)。
func TestSanitizeCertDirName_Unchanged(t *testing.T) {
	inputs := []string{
		"my-cert-bundle",
		"www.example.com",
		"api_v2.production",
		"a.b.c.d.e.f.g.h",
	}
	for _, input := range inputs {
		if got := SanitizeCertDirName(input); got != input {
			t.Errorf("SanitizeCertDirName(%q) = %q, 不应修改", input, got)
		}
	}
}
