package server

import (
	"testing"

	"github.com/kk/ddns-manager/internal/model"
)

// TestDetectPlatform_Amd64NotMapped 验证 CRITICAL-1 修复:
// amd64 节点应返回 "amd64" (Go标准命名)，不应返回 "x86_64"
func TestDetectPlatform_Amd64NotMapped(t *testing.T) {
	rec := &model.NodeRecord{
		Hardware: &model.HardwareInfo{OS: "Ubuntu 24.04", Arch: "amd64"},
	}
	goos, goarch := detectPlatform(rec)
	if goos != "linux" {
		t.Errorf("预期 goos=linux, 实际 %s", goos)
	}
	if goarch != "amd64" {
		t.Errorf("CRITICAL BUG: 预期 goarch=amd64 (Go标准命名), 实际 %s — 这会导致manifest查找失败", goarch)
	}
}

// TestDetectPlatform_EmptyHardware 边界: Hardware为nil时返回空字符串，调用方应跳过升级推送
func TestDetectPlatform_EmptyHardware(t *testing.T) {
	rec := &model.NodeRecord{} // Hardware = nil
	goos, goarch := detectPlatform(rec)
	if goos != "" {
		t.Errorf("Hardware为nil时预期 goos=\"\" (空), 实际 %q — 调用方应跳过升级", goos)
	}
	if goarch != "" {
		t.Errorf("Hardware为nil时预期 goarch=\"\" (空), 实际 %q — 调用方应跳过升级", goarch)
	}
}

// TestDetectPlatform_WindowsAmd64 Windows节点OS检测
func TestDetectPlatform_WindowsAmd64(t *testing.T) {
	rec := &model.NodeRecord{
		Hardware: &model.HardwareInfo{OS: "Windows Server 2022 Datacenter", Arch: "amd64"},
	}
	goos, goarch := detectPlatform(rec)
	if goos != "windows" {
		t.Errorf("预期 goos=windows, 实际 %s", goos)
	}
	if goarch != "amd64" {
		t.Errorf("预期 goarch=amd64, 实际 %s (Windows也应用Go标准命名)", goarch)
	}
}

// TestDetectPlatform_Arm32 ARM 32位应返回 "arm" 不返回 "armv7"
func TestDetectPlatform_Arm32(t *testing.T) {
	rec := &model.NodeRecord{
		Hardware: &model.HardwareInfo{OS: "Raspbian GNU/Linux 12", Arch: "arm"},
	}
	_, goarch := detectPlatform(rec)
	if goarch != "arm" {
		t.Errorf("预期 goarch=arm (Go标准: runtime.GOARCH on armv6l/armv7l = \"arm\"), 实际 %s", goarch)
	}
}

// TestDetectPlatform_Arm64 ARM64正常映射
func TestDetectPlatform_Arm64(t *testing.T) {
	rec := &model.NodeRecord{
		Hardware: &model.HardwareInfo{OS: "Ubuntu 24.04", Arch: "arm64"},
	}
	_, goarch := detectPlatform(rec)
	if goarch != "arm64" {
		t.Errorf("预期 goarch=arm64, 实际 %s", goarch)
	}
}

// TestDetectPlatform_Darwin 未知OS: 应回退到linux默认
func TestDetectPlatform_Darwin(t *testing.T) {
	rec := &model.NodeRecord{
		Hardware: &model.HardwareInfo{OS: "macOS 15.0", Arch: "arm64"},
	}
	goos, goarch := detectPlatform(rec)
	if goos != "linux" {
		t.Errorf("非Windows OS 预期回退 goos=linux, 实际 %s", goos)
	}
	if goarch != "arm64" {
		t.Errorf("预期 goarch=arm64, 实际 %s", goarch)
	}
}

// TestDetectPlatform_UnknownArch 未知架构: 透传原始值
func TestDetectPlatform_UnknownArch(t *testing.T) {
	rec := &model.NodeRecord{
		Hardware: &model.HardwareInfo{OS: "Linux", Arch: "riscv64"},
	}
	_, goarch := detectPlatform(rec)
	if goarch != "riscv64" {
		t.Errorf("预期未知架构透传 goarch=riscv64, 实际 %s", goarch)
	}
}
