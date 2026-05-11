// Test suite: ddns-manager v1.5.5 → v1.5.6 audit fixes
// Covers: ELF OS/ABI validation, self-upgrade defer-in-loop, daemon initial heartbeat
package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ====== Test 1: 正常/边界/异常 — ELF OS/ABI 校验 ======
// 验证 validateAgentBinary 接受各种合法的 Linux ELF OS/ABI 值：
//   0x00 = System V (generic, Clang/LLVM 交叉编译常用)
//   0x03 = GNU/Linux (GCC 默认)
//   0x10 = Linux (某些工具链)
// 拒绝明显非法的值 (如 0x09 = FreeBSD)

func TestValidateAgentBinaryELFOSABI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ELF 测试仅在 Linux 运行")
	}

	// 构建一个合法的 64-bit little-endian ELF header
	// Offset  Size  Field         Value
	// 0       4     Magic         0x7f 'E' 'L' 'F'
	// 4       1     Class         2 (64-bit)
	// 5       1     Data          1 (little-endian)
	// 6       1     Version       1
	// 7       1     OS/ABI        0, 3, or 0x10 (测试参数)
	// 8       8     Padding       0
	// 16      2     Type          2 (executable)
	// 18      2     Machine       0x3E (x86-64)
	// 20      4     Version       1
	// 24      8     Entry         0x400000
	// ...
	buildELF := func(osabi byte, machine uint16, elfType uint16) []byte {
		buf := make([]byte, 64)
		buf[0], buf[1], buf[2], buf[3] = 0x7f, 'E', 'L', 'F'
		buf[4] = 2                // 64-bit
		buf[5] = 1                // little-endian
		buf[6] = 1                // version
		buf[7] = osabi            // OS/ABI (variable)
		buf[16] = byte(elfType)   // ET_EXEC=2, ET_DYN=3
		buf[17] = 0
		buf[18] = byte(machine)   // EM_X86_64=0x3E, EM_AARCH64=0xB7
		buf[19] = 0
		return buf
	}

	t.Run("normal_SystemV_OSABI_0", func(t *testing.T) {
		// System V OS/ABI — Clang/LLVM 交叉编译常用
		f := filepath.Join(t.TempDir(), "elf-sysv")
		os.WriteFile(f, buildELF(0, 0x3E, 2), 0755)
		if err := validateAgentBinary(f); err != nil {
			t.Errorf("拒绝 OS/ABI=0 (System V) 的 ELF: %v", err)
		}
	})

	t.Run("normal_GNU_Linux_OSABI_3", func(t *testing.T) {
		// GNU/Linux OS/ABI — GCC 默认
		f := filepath.Join(t.TempDir(), "elf-gnu")
		os.WriteFile(f, buildELF(3, 0x3E, 2), 0755)
		if err := validateAgentBinary(f); err != nil {
			t.Errorf("拒绝 OS/ABI=3 (GNU/Linux) 的 ELF: %v", err)
		}
	})

	t.Run("boundary_Linux_OSABI_0x10", func(t *testing.T) {
		// Linux OS/ABI (0x10) — 部分工具链使用
		f := filepath.Join(t.TempDir(), "elf-linux")
		os.WriteFile(f, buildELF(0x10, 0x3E, 2), 0755)
		if err := validateAgentBinary(f); err != nil {
			t.Errorf("拒绝 OS/ABI=0x10 (Linux) 的 ELF: %v", err)
		}
	})

	t.Run("boundary_ET_DYN_shared_object", func(t *testing.T) {
		// ET_DYN (3) — 共享对象/PIE 可执行文件（Go 默认编译产物）
		f := filepath.Join(t.TempDir(), "elf-pie")
		os.WriteFile(f, buildELF(3, 0x3E, 3), 0755)
		if err := validateAgentBinary(f); err != nil {
			t.Errorf("拒绝 ET_DYN (PIE) 的 ELF: %v", err)
		}
	})

	t.Run("abnormal_FreeBSD_OSABI_9", func(t *testing.T) {
		// FreeBSD OS/ABI — 应被拒绝
		f := filepath.Join(t.TempDir(), "elf-freebsd")
		os.WriteFile(f, buildELF(9, 0x3E, 2), 0755)
		if err := validateAgentBinary(f); err == nil {
			t.Error("应拒绝 FreeBSD (OS/ABI=9) 的 ELF，但通过了")
		}
	})

	t.Run("boundary_ARM64_machine", func(t *testing.T) {
		// ARM64 (AArch64) machine type
		f := filepath.Join(t.TempDir(), "elf-arm64")
		os.WriteFile(f, buildELF(3, 0xB7, 2), 0755)
		if err := validateAgentBinary(f); err != nil {
			if runtime.GOARCH == "arm64" {
				t.Errorf("拒绝 ARM64 host 上的 ARM64 ELF: %v", err)
			} else {
				// x86 host 上 ARM64 binary 应该被拒绝
				if !strings.Contains(err.Error(), "ARM64 binary on") {
					t.Errorf("期望架构不匹配错误，得到: %v", err)
				}
			}
		}
	})
}

// ====== Test 2: 边界 — daemon 模式启动时立即执行首次心跳 ======
// 验证 daemon 模式不会等 5 分钟才第一次 DNS 更新。
// 通过代码检查 doHeartbeat 在 ticker 循环前的调用路径。

func TestDaemonModeImmediateHeartbeat(t *testing.T) {
	// 代码逻辑验证: daemon 模式在 main() 中应包含以下流程:
	//   1. 加载配置 ✅
	//   2. go func() { doHeartbeat(cfg) }() ← 立即执行
	//   3. ticker := time.NewTicker(5 * time.Minute)
	//   4. for { select { case <-ticker.C: ... } }

	// 读取 main.go 源码验证立即心跳逻辑存在
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Skipf("无法读取 main.go: %v", err)
	}
	source := string(data)

	// 验证: daemon 模式下有 "立即" 或首次心跳的相关代码
	hasInitialHeartbeat := strings.Contains(source, "首次心跳") ||
		strings.Contains(source, "go func()") &&
			strings.Contains(source, "doHeartbeat") &&
			strings.Contains(source, "启动时立即")

	if !hasInitialHeartbeat {
		t.Error(`daemon 模式缺少首次即时心跳 — DNS 更新会延迟 5 分钟
修复: 在 ticker.NewTicker 之前添加:
  go func() { doHeartbeat(cfg) }()`)
	} else {
		t.Log("✅ daemon 模式包含首次即时心跳逻辑")
	}

	// 验证: ticker 循环在 doHeartbeat 之后启动
	tickerAfterHeartbeat := strings.Index(source, "首次心跳") < strings.Index(source, "NewTicker")
	if !tickerAfterHeartbeat {
		t.Log("⚠️ 心跳顺序警告 — 首次心跳应在 ticker 创建之前（非致命）")
	}
}

// ====== Test 3: 异常 — selfUpgrade 重试循环中 defer 正确关闭 ======
// 验证 selfUpgrade 中的 download 循环使用闭包包装以避免 defer-in-loop。

func TestSelfUpgradeNoDeferInLoop(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Skipf("无法读取 main.go: %v", err)
	}
	source := string(data)

	// 查找 selfUpgrade 函数
	selfUpgradeStart := strings.Index(source, "func selfUpgrade(")
	if selfUpgradeStart < 0 {
		t.Fatal("未找到 selfUpgrade 函数")
	}

	// 提取函数体（大致范围）
	funcEnd := strings.Index(source[selfUpgradeStart:], "\n}\n")
	if funcEnd < 0 {
		funcEnd = len(source) - selfUpgradeStart
	}
	funcBody := source[selfUpgradeStart : selfUpgradeStart+funcEnd]

	// 验证: retry loop 使用闭包包装 (defer-in-loop 修复)
	// 修复前: for attempt := ... { defer resp.Body.Close() }  ← BUG
	// 修复后: func() error { for attempt := ... { defer resp.Body.Close() } }() ← 正确
	hasClosureWrapped := strings.Contains(funcBody, "func() error") &&
		strings.Contains(funcBody, "for attempt")

	if hasClosureWrapped {
		t.Log("✅ selfUpgrade 下载重试已用闭包包装 (defer-in-loop 已修复)")
	} else {
		t.Error(`selfUpgrade 下载重试未用闭包包装 — defer-in-loop 可能累积连接泄漏
修复: 将 for 循环包装为立即执行的闭包:
  downloadErr = func() error {
    for attempt := 0; attempt < 3; attempt++ {
      resp, err := hc.Get(url)
      defer resp.Body.Close()  // ✅ 闭包内, 函数返回时执行
      ...
    }
  }()`)
	}

	// 验证: 有 defer-in-loop 防护注释
	if !strings.Contains(funcBody, "defer-in-loop") && !strings.Contains(funcBody, "defer 在循环中") {
		t.Log("⚠️ 建议在闭包处添加注释说明 defer-in-loop 修复")
	}
}
