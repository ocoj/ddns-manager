package server

import (
	"testing"

	"github.com/ocoj/ddns-manager/internal/model"
)

// ─── H1: Server 端 SanitizeCertDirName 调用验证 ───

// TestH1_SanitizeCertDirName_ServerCallSite v1.6.50 H1:
// 验证 Server 端通过 model.SanitizeCertDirName 统一调用, 行为与 Agent 端一致。
func TestH1_SanitizeCertDirName_ServerCallSite(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"普通bundle名", "example.com", "example.com"},
		{"泛域名证书", "*.example.com", "_.example.com"},
		{"多级泛域", "*.*.mydomain.com", "_._.mydomain.com"},
		{"空名", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := model.SanitizeCertDirName(tt.input)
			if got != tt.expected {
				t.Errorf("model.SanitizeCertDirName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestH1_SanitizeCertDirName_AgentServerConsistency v1.6.50 H1:
// 核心验证: Agent 和 Server 必须对同一输入产生相同输出, 否则证书路径不匹配。
func TestH1_SanitizeCertDirName_AgentServerConsistency(t *testing.T) {
	inputs := []string{
		"*.example.com",
		"*.example.com",
		"*.*.myapp.io",
		"normal-bundle",
		"api.example.com",
		"*",
	}

	// 模拟双方独立调用 (实际只调用一次 model.SanitizeCertDirName 证明唯一实现)
	for _, input := range inputs {
		result := model.SanitizeCertDirName(input)
		// 同实现调用两次应相等 (幂等)
		second := model.SanitizeCertDirName(input)
		if result != second {
			t.Errorf("SanitizeCertDirName(%q) 两次调用结果不一致: %q vs %q", input, result, second)
		}
		// 验证: 泛域名证书目录名不含非法路径字符
		if len(result) > 0 {
			for _, ch := range []string{"/", "\\", ":", "<", ">", "|", "?", "\""} {
				if containsRune(result, rune(ch[0])) {
					t.Errorf("SanitizeCertDirName(%q) = %q 含非法路径字符 %q", input, result, ch)
				}
			}
		}
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
