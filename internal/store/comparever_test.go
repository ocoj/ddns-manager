package store

import (
	"testing"

	"github.com/ocoj/ddns-manager/internal/model"
)

// TestCompareVer_SemanticComparison verifies that model.CompareSemVer correctly
// compares semantic version strings with various edge cases.
// v1.5.34 H2: 测试从 compareVer 迁移到 model.CompareSemVer 公共实现
func TestCompareVer_SemanticComparison(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want int
	}{
		// Normal cases
		{"equal same", "1.5.8", "1.5.8", 0},
		{"a greater major", "2.0.0", "1.9.9", 1},
		{"a greater minor", "1.6.0", "1.5.9", 1},
		{"a greater patch", "1.5.9", "1.5.8", 1},
		{"a less major", "1.0.0", "2.0.0", -1},
		{"a less minor", "1.4.0", "1.5.0", -1},
		{"a less patch", "1.5.7", "1.5.8", -1},
		// v-prefix stripping
		{"v prefix a", "v1.5.8", "1.5.8", 0},
		{"v prefix b", "1.5.8", "v1.5.8", 0},
		{"v prefix both", "v1.5.8", "v1.5.8", 0},
		// Unequal length (CompareSemVer pads to 3)
		{"a shorter", "1.5", "1.5.0", 0},
		{"b shorter", "1.5.0", "1.5", 0},
		{"a major only", "2", "1.9.9", 1},
		{"b major only", "1.9.9", "2", -1},
		// Pre-release tags stripped (CompareSemVer feature)
		{"pre-release a", "1.5.8-beta1", "1.5.8", 0},
		{"pre-release b", "1.5.8", "1.5.8-beta1", 0},
		// Boundary: non-numeric segments (Atoi returns 0)
		// "1.x.8" → [1,0,8] < [1,5,8] → -1
		{"non-numeric a", "1.x.8", "1.5.8", -1},
		{"non-numeric b", "1.5.8", "1.x.8", 1},
		{"both non-numeric", "a.b.c", "x.y.z", 0},
		// Boundary: empty strings
		{"empty both", "", "", 0},
		{"empty a", "", "1.0.0", -1},
		{"empty b", "1.0.0", "", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := model.CompareSemVer(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("CompareSemVer(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// TestCompareVer_RealWorldVersions verifies comparison with real version strings
// that appear in the ddns-manager codebase.
func TestCompareVer_RealWorldVersions(t *testing.T) {
	// Simulate the agent version comparison in heartbeat handler
	tests := []struct {
		agentVer      string
		targetVer     string
		shouldUpgrade bool
	}{
		{"1.5.6", "1.5.8", true},
		{"1.5.8", "1.5.8", false},
		{"1.5.8", "1.5.6", false}, // already newer
		{"1.6.0", "1.5.9", false},
		{"1.5.7", "1.5.8", true},
		// "dev" is handled separately in real code (before CompareSemVer call)
		// CompareSemVer("dev", "1.5.8") → [0,0,0] < [1,5,8] → -1 → shouldUpgrade=true
		// This is correct — if somehow passed, dev should be upgraded to real version
		{"dev", "1.5.8", true},
	}

	for _, tt := range tests {
		result := model.CompareSemVer(tt.agentVer, tt.targetVer)
		shouldUpgrade := result < 0
		if shouldUpgrade != tt.shouldUpgrade {
			t.Errorf("CompareSemVer(%q, %q) shouldUpgrade=%v, want %v (result=%d)",
				tt.agentVer, tt.targetVer, shouldUpgrade, tt.shouldUpgrade, result)
		}
	}
}
