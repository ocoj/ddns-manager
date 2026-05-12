package store

import (
	"testing"
)

// TestCompareVer_SemanticComparison verifies that compareVer correctly
// compares semantic version strings with various edge cases.
// Covers: M2 fix — strconv.Atoi replaces silent fmt.Sscanf misparsing.
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
		// Unequal length
		{"a shorter", "1.5", "1.5.0", 0},
		{"b shorter", "1.5.0", "1.5", 0},
		{"a major only", "2", "1.9.9", 1},
		{"b major only", "1.9.9", "2", -1},
		// Boundary: non-numeric segments (M2 fix: no longer silently parse as 0)
		{"non-numeric a", "1.x.8", "1.5.8", 0},
		{"non-numeric b", "1.5.8", "1.x.8", 0},
		{"both non-numeric", "a.b.c", "x.y.z", 0},
		// Boundary: empty strings
		{"empty both", "", "", 0},
		{"empty a", "", "1.0.0", 0},
		{"empty b", "1.0.0", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVer(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("compareVer(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// TestCompareVer_RealWorldVersions verifies comparison with real version strings
// that appear in the ddns-manager codebase.
func TestCompareVer_RealWorldVersions(t *testing.T) {
	// Simulate the agent version comparison in heartbeat handler
	tests := []struct {
		agentVer string
		targetVer string
		shouldUpgrade bool
	}{
		{"1.5.6", "1.5.8", true},
		{"1.5.8", "1.5.8", false},
		{"1.5.8", "1.5.6", false}, // already newer
		{"1.6.0", "1.5.9", false},
		{"1.5.7", "1.5.8", true},
		{"dev", "1.5.8", false}, // dev < 1.5.8? compareVer returns 0 for non-numeric
	}

	for _, tt := range tests {
		result := compareVer(tt.agentVer, tt.targetVer)
		shouldUpgrade := result < 0
		if shouldUpgrade != tt.shouldUpgrade {
			t.Errorf("compareVer(%q, %q) shouldUpgrade=%v, want %v (result=%d)",
				tt.agentVer, tt.targetVer, shouldUpgrade, tt.shouldUpgrade, result)
		}
	}
}
