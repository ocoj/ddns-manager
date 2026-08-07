package server

import (
	"testing"

	"github.com/ocoj/ddns-manager/internal/model"
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

// TestShouldPushConfig_Condition 验证 v1.6.59 的 hash-only 推送条件, 作为回归基准保留 (C4)。
// v1.6.64 方案B 的完整推送条件 (含 key 版本比对) 见 TestShouldRenderConfig_Condition。
func TestShouldPushConfig_Condition(t *testing.T) {
	// 使用与 handleHeartbeat 中一致的变量名：
	//   cfgHash   = 当前根据 saved ConfigYAML + DNS keys 渲染出的配置 hash
	//   reqHash   = Agent 上报的 ConfigHash
	//   recHash   = Manager 存储的该节点 ConfigHash
	shouldPush := func(cfgHash, reqHash, recHash string) bool {
		return cfgHash != recHash || reqHash != recHash
	}

	cases := []struct {
		name    string
		cfgHash string
		reqHash string
		recHash string
		want    bool
	}{
		{
			name:    "DNS Key 凭据更新后应推送",
			cfgHash: "sha256:new",
			reqHash: "sha256:old",
			recHash: "sha256:old",
			want:    true,
		},
		{
			name:    "节点配置修改后应推送",
			cfgHash: "sha256:new",
			reqHash: "sha256:old",
			recHash: "sha256:old",
			want:    true,
		},
		{
			name:    "Agent 配置丢失/不同步时应推送",
			cfgHash: "sha256:current",
			reqHash: "sha256:missing",
			recHash: "sha256:current",
			want:    true,
		},
		{
			name:    "首次推送（Manager 无记录）时应推送",
			cfgHash: "sha256:first",
			reqHash: "",
			recHash: "",
			want:    true,
		},
		{
			name:    "一切正常时不应推送",
			cfgHash: "sha256:current",
			reqHash: "sha256:current",
			recHash: "sha256:current",
			want:    false,
		},
		{
			name:    "Manager 记录损坏时应推送以修复记录",
			cfgHash: "sha256:current",
			reqHash: "sha256:current",
			recHash: "sha256:stale",
			want:    true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldPush(tt.cfgHash, tt.reqHash, tt.recHash)
			if got != tt.want {
				t.Errorf("shouldPush(cfgHash=%q, reqHash=%q, recHash=%q) = %v, want %v",
					tt.cfgHash, tt.reqHash, tt.recHash, got, tt.want)
			}
		})
	}
}

// TestShouldRenderConfig_Condition 验证 v1.6.64 方案B 配置推送的完整判断条件:
//   shouldRender (入口): reqHash != recHash || recHash == "" || recKeysVer < curKeyVer
//   shouldPush (渲染后): rendered != "" && cfgHash != reqHash
func TestShouldRenderConfig_Condition(t *testing.T) {
	shouldRender := func(reqHash, recHash string, recKeysVer, curKeyVer uint64) bool {
		return reqHash != recHash || recHash == "" || recKeysVer < curKeyVer
	}
	shouldPush := func(cfgHash, reqHash string) bool {
		return cfgHash != reqHash
	}

	cases := []struct {
		name       string
		reqHash    string
		recHash    string
		recKeysVer uint64
		curKeyVer  uint64
		wantRender bool
	}{
		{
			name:    "win-test关机死锁: hash一致但key版本落后 → 应渲染",
			reqHash: "sha256:old", recHash: "sha256:old",
			recKeysVer: 0, curKeyVer: 1, wantRender: true,
		},
		{
			name:    "一切正常: hash一致且版本一致 → 不渲染",
			reqHash: "sha256:c", recHash: "sha256:c",
			recKeysVer: 1, curKeyVer: 1, wantRender: false,
		},
		{
			name:    "首次推送: recHash为空 → 渲染",
			reqHash: "", recHash: "",
			recKeysVer: 0, curKeyVer: 1, wantRender: true,
		},
		{
			name:    "Agent hash漂移 → 渲染",
			reqHash: "sha256:x", recHash: "sha256:c",
			recKeysVer: 1, curKeyVer: 1, wantRender: true,
		},
		{
			name:    "版本落后但Agent hash已最新 → 渲染(仅同步版本)",
			reqHash: "sha256:c", recHash: "sha256:c",
			recKeysVer: 0, curKeyVer: 1, wantRender: true,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRender(tt.reqHash, tt.recHash, tt.recKeysVer, tt.curKeyVer); got != tt.wantRender {
				t.Errorf("shouldRender(%q,%q,%d,%d) = %v, want %v",
					tt.reqHash, tt.recHash, tt.recKeysVer, tt.curKeyVer, got, tt.wantRender)
			}
		})
	}

	pushCases := []struct {
		name, cfgHash, reqHash string
		want                   bool
	}{
		{name: "渲染hash与Agent一致 → 不推送(仅同步版本)", cfgHash: "sha256:c", reqHash: "sha256:c", want: false},
		{name: "渲染hash不同(Secret已变) → 推送", cfgHash: "sha256:new", reqHash: "sha256:old", want: true},
	}
	for _, tt := range pushCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldPush(tt.cfgHash, tt.reqHash); got != tt.want {
				t.Errorf("shouldPush(%q,%q) = %v, want %v", tt.cfgHash, tt.reqHash, got, tt.want)
			}
		})
	}
}
