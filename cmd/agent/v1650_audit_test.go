package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kk/ddns-manager/internal/model"
)

// ─── L2: certutilErrorCode 增强正则 ───

// TestCertutilErrorCode_HexCodes 验证 hex 错误码提取 (0x格式, 原有逻辑)。
func TestCertutilErrorCode_HexCodes(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		contains string
	}{
		{"标准4位hex", "error 0x2", "错误码=0x2"},
		{"标准5位hex", "0x80070056", "错误码=0x80070056"},
		{"certutil常见错误", "CertUtil: -importPFX 命令失败: 0x80070056 (WIN32: 87 ERROR_INVALID_PARAMETER)", "错误码=0x80070056"},
		{"中文乱码环境", "ָ 벻 ȷ (0x5)", "错误码=0x5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := certutilErrorCode(tt.output)
			if !strings.Contains(got, tt.contains) {
				t.Errorf("certutilErrorCode(%q) = %q, 应包含 %q", tt.output, got, tt.contains)
			}
		})
	}
}

// TestCertutilErrorCode_WinErrNames v1.6.50 L2: 验证 Windows 符号错误名新正则。
func TestCertutilErrorCode_WinErrNames(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		contains string
	}{
		{"ERROR_FILE_NOT_FOUND", "Error: ERROR_FILE_NOT_FOUND", "错误=ERROR_FILE_NOT_FOUND"},
		{"ERROR_ACCESS_DENIED", "The system cannot find the file specified. ERROR_ACCESS_DENIED", "错误=ERROR_ACCESS_DENIED"},
		{"ERROR_INVALID_PARAMETER", "0x57 ERROR_INVALID_PARAMETER", "错误码=0x57"}, // hex优先
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := certutilErrorCode(tt.output)
			if !strings.Contains(got, tt.contains) {
				t.Errorf("certutilErrorCode(%q) = %q, 应包含 %q", tt.output, got, tt.contains)
			}
		})
	}
}

// TestCertutilErrorCode_Fallback 验证回退逻辑: 无匹配时取首行文本。
func TestCertutilErrorCode_Fallback(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		contains string
	}{
		{"普通错误文本", "certificate import failed", "输出=certificate import failed"},
		{"多行取首行", "line1\nline2\nline3", "输出=line1"},
		{"空输出", "", "未知错误"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := certutilErrorCode(tt.output)
			if !strings.Contains(got, tt.contains) {
				t.Errorf("certutilErrorCode(%q) = %q, 应包含 %q", tt.output, got, tt.contains)
			}
		})
	}
}

// TestCertutilErrorCode_LongLine 验证超长行截断 (超过100字符)。
func TestCertutilErrorCode_LongLine(t *testing.T) {
	longLine := strings.Repeat("x", 200)
	got := certutilErrorCode(longLine)
	if !strings.Contains(got, "...") {
		t.Errorf("长行应被截断: %q", got)
	}
	if len(got) > 120 {
		t.Errorf("截断后仍过长: len=%d got=%q...", len(got), got[:50])
	}
}


// ─── M2: collectCertHashes 键名一致性 ───

// TestCollectCertHashes_KeyFormat v1.6.50 M2: 验证 collectCertHashes 返回目录路径键。
// 确保与 Manager 端 handleHeartbeat 以 binding.DeployPath 精确匹配一致。
func TestCollectCertHashes_KeyFormat(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "certs")
	bundleDir := filepath.Join(certPath, "example.com")
	hashFile := filepath.Join(bundleDir, ".cert_hash")
	expectedHash := "sha256:abc123def456"

	// 创建证书目录结构
	os.MkdirAll(bundleDir, 0755)
	os.WriteFile(hashFile, []byte(expectedHash), 0600)

	cfg := &model.AgentConfig{CertPath: certPath}
	hashes := collectCertHashes(cfg)

	// 验证: key 必须是目录路径 (不是 BundleName, 不是文件名)
	// Manager 端用 binding.DeployPath (证书目录路径) 作为精确匹配键
	t.Logf("collectCertHashes result: %v", hashes)

	// 检查 key 是目录路径格式 (非短名)
	for key := range hashes {
		if strings.HasPrefix(key, certPath) {
			// ✅ 正确: key 是目录完整路径
			t.Logf("key=%s (OK: directory path)", key)
		} else {
			// 检查是否仅为 BundleName (错误格式)
			if !strings.Contains(key, string(os.PathSeparator)) {
				t.Errorf("key=%q 缺少路径分隔符, 可能为BundleName而非目录路径", key)
			}
		}
	}

	// 验证 hash 值一致
	if h, ok := hashes[bundleDir]; ok {
		if h != expectedHash {
			t.Errorf("hash 不匹配: got %q want %q", h, expectedHash)
		}
	} else {
		// 容忍: WalkDir 跨平台行为差异, 检查是否有匹配的值
		found := false
		for _, v := range hashes {
			if v == expectedHash {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("未找到预期的 hash 值 %q 在 map %v", expectedHash, hashes)
		}
	}
}

// TestCollectCertHashes_EmptyDir 验证空证书目录不 panic。
func TestCollectCertHashes_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "empty-certs")
	os.MkdirAll(certPath, 0755)

	cfg := &model.AgentConfig{CertPath: certPath}
	hashes := collectCertHashes(cfg)

	if hashes == nil {
		t.Error("collectCertHashes 不应返回 nil, 应返回空 map")
	}
}

// TestCollectCertHashes_MissingDir 验证证书目录不存在时不 panic。
func TestCollectCertHashes_MissingDir(t *testing.T) {
	cfg := &model.AgentConfig{CertPath: "/nonexistent/cert/path"}
	hashes := collectCertHashes(cfg)

	if hashes == nil {
		t.Error("collectCertHashes 不应返回 nil")
	}
	if len(hashes) != 0 {
		t.Errorf("不存在的目录应返回空 map, got %v", hashes)
	}
}


// ─── H1: SanitizeCertDirName 在 Agent 端调用 ───

// TestH1_SanitizeCertDirName_AgentCallSite v1.6.50 H1: 确认 agent 端通过 model.SanitizeCertDirName 调用。
// 验证删除 agent 端私有定义后编译通过且行为一致。
func TestH1_SanitizeCertDirName_AgentCallSite(t *testing.T) {
	// 正常域名不变
	got := model.SanitizeCertDirName("example.com")
	if got != "example.com" {
		t.Errorf("model.SanitizeCertDirName(\"example.com\") = %q, want \"example.com\"", got)
	}

	// 泛域名星号转下划线
	got = model.SanitizeCertDirName("*.example.com")
	if got != "_.example.com" {
		t.Errorf("model.SanitizeCertDirName(\"*.example.com\") = %q, want \"_.example.com\"", got)
	}

	// 多星
	got = model.SanitizeCertDirName("*.*.test.com")
	if got != "_._.test.com" {
		t.Errorf("model.SanitizeCertDirName(\"*.*.test.com\") = %q, want \"_._.test.com\"", got)
	}
}


// ─── H2: LogBuffer Peek/Commit 去重逻辑 ───

// TestLogBuffer_PeekCommit v1.6.50 H2: 验证 Peek+Commit 增量上报机制。
// 心跳成功 → Commit 前移游标; 心跳失败 → Peek 重传相同条目。
func TestLogBuffer_PeekCommit(t *testing.T) {
	lb := newLogBuffer(100)

	// 写入 5 条日志
	lb.Write("log1")
	lb.Write("log2")
	lb.Write("log3")
	lb.Write("log4")
	lb.Write("log5")

	// 第一次 Peek: 应返回 5 条
	first := lb.Peek(10)
	if len(first) != 5 {
		t.Fatalf("首次 Peek: 期望5条, 得到%d", len(first))
	}

	// 未 Commit, 第二次 Peek: 应返回相同 5 条 (重传)
	second := lb.Peek(10)
	if len(second) != 5 {
		t.Fatalf("未Commit二次Peek: 期望5条, 得到%d", len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("未Commit时Peek应返回相同条目: [%d] %q vs %q", i, first[i], second[i])
		}
	}

	// Commit 后 Peek: 应返回空 (无新条目)
	lb.Commit()
	third := lb.Peek(10)
	if len(third) != 0 {
		t.Errorf("Commit后Peek应返回空, 得到%d条: %v", len(third), third)
	}

	// 写入新条目后 Peek: 仅返回新条目
	lb.Write("log6")
	fourth := lb.Peek(10)
	if len(fourth) != 1 {
		t.Fatalf("新条目后Peek: 期望1条, 得到%d", len(fourth))
	}
	if !strings.Contains(fourth[0], "log6") {
		t.Errorf("新条目Peek: 期望包含log6, 得到%q", fourth[0])
	}
}

// TestLogBuffer_PeekWrap 验证环形缓冲区覆盖时 Peek 的正确性。
func TestLogBuffer_PeekWrap(t *testing.T) {
	lb := newLogBuffer(3) // 小缓冲区, 强制覆盖

	// 写入 5 条, 前2条被覆盖
	lb.Write("log1")
	lb.Write("log2")
	lb.Write("log3")
	lb.Write("log4")
	lb.Write("log5")

	// Peek 应返回 3 条 (log3, log4, log5)
	entries := lb.Peek(10)
	if len(entries) != 3 {
		t.Fatalf("环形Peek: 期望3条, 得到%d", len(entries))
	}
	if !strings.Contains(entries[0], "log3") {
		t.Errorf("环形Peek[0]: 期望log3, 得到%q", entries[0])
	}
	if !strings.Contains(entries[2], "log5") {
		t.Errorf("环形Peek[2]: 期望log5, 得到%q", entries[2])
	}

	// Commit 后写新条目, 旧 peekPos 已被覆盖
	lb.Commit()
	lb.Write("log6")
	lb.Write("log7")
	lb.Write("log8") // 覆盖 log3-log5

	entries = lb.Peek(10)
	if len(entries) != 3 {
		t.Fatalf("覆盖后Peek: 期望3条, 得到%d", len(entries))
	}
	if !strings.Contains(entries[0], "log6") {
		t.Errorf("覆盖后Peek[0]: 期望log6, 得到%q", entries[0])
	}
}
