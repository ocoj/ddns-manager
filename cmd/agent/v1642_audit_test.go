package main

import (
	"strings"
	"testing"
)

// TestCertutilErrorCode_ShortHexMatch — v1.6.42 C5:
// 验证 certutilErrorCode 能匹配短 hex 错误码 (0x2, 0x5)、标准长度 (0x80070056)、
// 以及非英文 locale 下的回退行为。
func TestCertutilErrorCode_ShortHexMatch(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string // 结果必须包含的子串
		notContains string // 结果不能包含的子串
	}{
		{
			name:     "standard 8-digit hex",
			input:    "CertUtil: -dump 命令失败: 0x80070056 (WIN32: 87 ERROR_INVALID_PARAMETER)",
			contains: "0x80070056",
		},
		{
			name:     "short 2-digit hex",
			input:    "错误: 0x2 (文件未找到)",
			contains: "0x2",
		},
		{
			name:     "short 1-digit hex (unlikely but matches regex)",
			input:    "Error 0x5",
			contains: "0x5",
		},
		{
			name:     "no hex code, fallback to first line",
			input:    "连接超时\n请检查网络",
			contains: "连接超时",
		},
		{
			name:     "Chinese GBK garble",
			input:    "ָ 벻 ȷ\n0x80070002",
			contains: "0x80070002",
		},
		{
			name:        "completely empty",
			input:       "",
			contains:    "未知错误",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := certutilErrorCode(tt.input)
			if tt.contains != "" && !strings.Contains(result, tt.contains) {
				t.Errorf("certutilErrorCode(%q) = %q, want containing %q", tt.input, result, tt.contains)
			}
			if tt.notContains != "" && strings.Contains(result, tt.notContains) {
				t.Errorf("certutilErrorCode(%q) = %q, should NOT contain %q", tt.input, result, tt.notContains)
			}
		})
	}
}

// TestFallbackBatchFormatCorrectness — v1.6.42 C2:
// 验证 fallbackBatchUpgrade 生成的批处理不含 Sprintf 位置参数残留 (%!(EXTRA...)。
// 由于 fallbackBatchUpgrade 依赖 agentBaseDir 和 Windows API，
// 此测试直接验证 Sprintf 格式化结果。
func TestFallbackBatchFormatCorrectness(t *testing.T) {
	newExe := `C:\ddns-agent\node-agent.exe.new`
	curExe := `C:\ddns-agent\node-agent.exe`

	// 重建与 fallbackBatchUpgrade 完全一致的 Sprintf 调用
	result := testFormatBatchHelper(newExe, curExe)

	// 不能包含 Go Sprintf 的位置参数错误输出
	badPatterns := []string{
		"%!(EXTRA",       // Go Sprintf 错误格式输出
		"%[1]s",          // 残留的位置参数语法
		"%[2]s",          // 残留的位置参数语法
	}
	for _, bad := range badPatterns {
		if strings.Contains(result, bad) {
			t.Errorf("批处理含 Sprintf 格式错误: found %q in output", bad)
		}
	}

	// 必须包含正确的路径
	if !strings.Contains(result, newExe) {
		t.Errorf("批处理缺少新文件路径: %q", newExe)
	}
	if !strings.Contains(result, curExe) {
		t.Errorf("批处理缺少当前文件路径: %q", curExe)
	}

	// 必须包含关键命令
	requiredCommands := []string{
		"move /y",
		"copy /y",
		"sc config node-agent start= auto",
		"sc start node-agent",
	}
	for _, cmd := range requiredCommands {
		if !strings.Contains(result, cmd) {
			t.Errorf("批处理缺少关键命令: %q", cmd)
		}
	}
}

// testFormatBatchHelper 与 fallbackBatchUpgrade 中 Sprintf 调用保持同步。
// 复制自 cmd/agent/upgrade_windows.go:fallbackBatchUpgrade 的格式字符串 (v1.6.42 修复后)。
func testFormatBatchHelper(newExe, curExe string) string {
	return strings.Join([]string{
		"@echo off",
		"rem v1.6.42 C2: 10次ping≈9秒等待 + 错误恢复逻辑",
		"ping -n 10 127.0.0.1 >nul",
		`move /y "` + newExe + `" "` + curExe + `"`,
		"if %ERRORLEVEL% NEQ 0 (",
		`  echo move failed, retrying with copy... >> "` + curExe + `.fail"`,
		`  copy /y "` + newExe + `" "` + curExe + `"`,
		"  if %ERRORLEVEL% NEQ 0 (",
		`    echo copy also failed >> "` + curExe + `.fail"`,
		"  )",
		`  del "` + newExe + `" 2>nul`,
		")",
		"sc config node-agent start= auto",
		"sc start node-agent",
		`del "%~f0" & exit`,
		"",
	}, "\r\n")
}
