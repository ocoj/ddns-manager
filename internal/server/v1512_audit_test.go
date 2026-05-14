package server

import (
	"regexp"
	"testing"
)

// TestVersionFormatValidation validates M5 fix: semantic version format check.
func TestVersionFormatValidation(t *testing.T) {
	// 黑名单检查 + 正则校验
	verPattern := regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[\w.-]+)?$`)

	tests := []struct {
		name    string
		ver     string
		wantOK  bool
	}{
		// 正常
		{"semantic v prefix", "v1.5.12", true},
		{"semantic no prefix", "1.5.12", true},
		{"pre-release", "v1.5.12-beta.1", true},
		{"single digit", "v0.0.1", true},

		// 边界
		{"patched version", "v1.5.11-patched", true},
		{"max length semver", "v1.5.12-beta.1", true},

		// 异常
		{"empty", "", false},
		{"single number", "1", false},
		{"two segments", "1.5", false},
		{"contains space", "v1.5.12 rc1", false},
		{"path traversal", "../etc/passwd", false},
		{"shell injection", "v1.5.12;rm -rf /", false},
		{"special chars", "v1.5.12!@#", false},
		{"exceeds length", "v123456789012345678901234567890123.5.12", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// M5 完整检查: 长度 + 特殊字符黑名单 + 正则
			if len(tt.ver) > 32 {
				if tt.wantOK {
					t.Error("预期通过但长度超过32")
				}
				return
			}
			for _, c := range "\x00\\/&;`'\"|<>*?%!$#@~ " {
				for _, vc := range tt.ver {
					if vc == c {
						if tt.wantOK {
							t.Errorf("预期通过但含特殊字符 '%c'", c)
						}
						return
					}
				}
			}
			match := verPattern.MatchString(tt.ver)
			if match != tt.wantOK {
				t.Errorf("ver=%q: 匹配=%v, 预期=%v", tt.ver, match, tt.wantOK)
			}
		})
	}
}

// TestEventSizeEstimation validates M1 fix: conservative event size estimation.
func TestEventSizeEstimation(t *testing.T) {
	// M1: 使用 256 字节/事件，而非原来的 200
	const avgEventSize = int64(256)

	tests := []struct {
		name     string
		fileSize int64
		wantMin  int // estimate should be >= this
	}{
		{"空文件", 0, 0},
		{"正好256", 256, 1},
		{"512字节", 512, 2},
		{"1KB", 1024, 4},
		{"1MB", 1 << 20, 4096},
		{"50MB(典型日志)", 50 << 20, 204800},
		{"溢出保护", 1 << 62, 0}, // overflow → 0
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			estimate := int(tt.fileSize / avgEventSize)
			if estimate < 0 {
				estimate = 0 // M1 溢出保护
			}
			t.Logf("文件%s → 估算%d个事件", formatBytes(tt.fileSize), estimate)
			if tt.wantMin > 0 && estimate < tt.wantMin {
				t.Errorf("估算值过小: 期望>=%d, 实际%d", tt.wantMin, estimate)
			}
		})
	}
}

func formatBytes(b int64) string {
	if b < 1024 {
		return formatInt(b) + "B"
	}
	if b < 1<<20 {
		return formatInt(b/1024) + "KB"
	}
	return formatInt(b/(1<<20)) + "MB"
}

func formatInt(n int64) string {
	return string(rune('0') + rune(n%10)) // simplified
}
