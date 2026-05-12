package server

import (
	"testing"

	"github.com/kk/ddns-manager/internal/model"
)

// TestDetectPlatform_ArchNormalization verifies that deb-style arch names
// (x86_64, aarch64, armv7l) are normalized to Go standard names used in
// build outputs and agent_manifest.json keys.
func TestDetectPlatform_ArchNormalization(t *testing.T) {
	tests := []struct {
		name     string
		os       string
		arch     string
		wantOS   string
		wantArch string
	}{
		// Normal cases
		{"amd64 go style", "linux", "amd64", "linux", "amd64"},
		{"arm64 go style", "linux", "arm64", "linux", "arm64"},
		// Deb-style normalization (L1 fix)
		{"x86_64 deb style", "linux", "x86_64", "linux", "amd64"},
		{"X86_64 uppercase", "linux", "X86_64", "linux", "amd64"},
		{"aarch64 deb style", "linux", "aarch64", "linux", "arm64"},
		{"AARCH64 uppercase", "linux", "AARCH64", "linux", "arm64"},
		{"armv7l 32-bit arm", "linux", "armv7l", "linux", "arm"},
		{"armv6l pi zero", "linux", "armv6l", "linux", "arm"},
		{"armv8l 32-bit armv8", "linux", "armv8l", "linux", "arm"},
		{"armhf deb style", "linux", "armhf", "linux", "arm"},
		{"i386 32-bit", "linux", "i386", "linux", "i386"},
		{"i686 32-bit", "linux", "i686", "linux", "i386"},
		// Windows
		{"windows amd64", "windows server 2022", "amd64", "windows", "amd64"},
		{"windows x86_64", "windows 11", "x86_64", "windows", "amd64"},
		// Boundary: nil hardware
		{"nil hardware", "", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rec *model.NodeRecord
			if tt.name == "nil hardware" {
				rec = &model.NodeRecord{} // Hardware is nil
			} else {
				rec = &model.NodeRecord{
					Hardware: &model.HardwareInfo{
						OS:   tt.os,
						Arch: tt.arch,
					},
				}
			}
			goos, goarch := detectPlatform(rec)
			if goos != tt.wantOS || goarch != tt.wantArch {
				t.Errorf("detectPlatform(%q, %q) = (%q, %q), want (%q, %q)",
					tt.os, tt.arch, goos, goarch, tt.wantOS, tt.wantArch)
			}
		})
	}
}

// TestDetectPlatform_UnknownArchReturnsOriginal verifies that truly unknown
// architecture strings are passed through unchanged (not silently dropped).
func TestDetectPlatform_UnknownArchReturnsOriginal(t *testing.T) {
	rec := &model.NodeRecord{
		Hardware: &model.HardwareInfo{
			OS:   "linux",
			Arch: "riscv64",
		},
	}
	goos, goarch := detectPlatform(rec)
	if goos != "linux" {
		t.Errorf("goos = %q, want linux", goos)
	}
	if goarch != "riscv64" {
		t.Errorf("goarch = %q, want riscv64 (pass-through)", goarch)
	}
}
