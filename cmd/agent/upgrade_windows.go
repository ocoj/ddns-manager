//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/windows"
)

// v1.6.28 C1+C3: Windows 升级方案 C — Go native helper 替代 cmd 批处理
//
// 升级流程:
//   1. sc config node-agent start= disabled (禁止 SCM 自动重启)
//   2. 写入新二进制为 node-agent.exe.new
//   3. 启动 upgrade_helper.exe (独立 Go 程序, 通过 DETACHED_PROCESS 分离)
//   4. 关闭 upgradeShutdownCh → SCM 标准退出
//
// upgrade_helper.exe 负责:
//   a. 等待旧进程 PID 退出 (轮询进程句柄, 最多 60 秒)
//   b. MoveFileEx 原子替换 node-agent.exe
//   c. sc config start= auto + sc start
//   d. 自删除
//
// 与旧方案对比:
//   旧: cmd /c upgrade_helper.bat → ping -n 3 (仅 3 秒) → move 无验证 → sc start
//   新: Go helper → 进程句柄等待 (可靠) → MoveFileEx 原子替换 → 验证 sc start 结果

var upgradeShutdownCh chan struct{}

func replaceRunningBinary(curExe, newExe, version string) error {
	upgradeLogger("Phase1: 禁用服务自动重启...")
	if out, err := exec.Command("sc", "config", "node-agent", "start=", "disabled").CombinedOutput(); err != nil {
		upgradeLogger("sc config disabled 失败: %v %s", err, string(out))
		// 非致命: 即使禁用了也可能失败(权限), 继续执行
	}

	dir := filepath.Dir(curExe)
	pid := os.Getpid()

	// Phase 2: 写入新二进制为 node-agent.exe.new
	newBinaryPath := curExe + ".new"
	if err := copyFile(newExe, newBinaryPath); err != nil {
		return fmt.Errorf("copy new binary: %w", err)
	}
	upgradeLogger("新二进制已写入: %s (PID=%d)", newBinaryPath, pid)

	// Phase 3: 写入 upgrade_helper.exe (与 Agent 同目录)
	helperPath := filepath.Join(dir, "upgrade_helper.exe")
	helperExe := findHelperExe()
	if helperExe == "" {
		// 降级: 如果没有 helper exe, 使用旧批处理兜底
		upgradeLogger("未找到 upgrade_helper.exe, 降级到批处理方案")
		return fallbackBatchUpgrade(newBinaryPath, curExe)
	}
	if err := copyFile(helperExe, helperPath); err != nil {
		upgradeLogger("复制 upgrade_helper.exe 失败: %v, 降级到批处理", err)
		return fallbackBatchUpgrade(newBinaryPath, curExe)
	}
	upgradeLogger("upgrade_helper.exe 已就绪: %s", helperPath)

	// Phase 4: 启动升级助手 (DETACHED_PROCESS, 不继承控制台)
	upgradeLogger("启动升级助手: %s %d %s %s", helperPath, pid, newBinaryPath, curExe)
	cmd := exec.Command(helperPath, strconv.Itoa(pid), newBinaryPath, curExe)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS,
		HideWindow:    true,
	}
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		upgradeLogger("启动升级助手失败: %v", err)
		return fmt.Errorf("start upgrade helper: %w", err)
	}
	upgradeLogger("升级助手已启动 (PID=%d)", cmd.Process.Pid)

	// Phase 5: 触发 SCM 标准退出
	if upgradeShutdownCh != nil {
		close(upgradeShutdownCh)
	}
	return nil
}

// findHelperExe 查找 upgrade_helper.exe 的路径。
// 优先查找 Agent 安装目录, 其次二进制同级目录, 最后 PATH。
func findHelperExe() string {
	// 1. Agent 安装目录 (由 Manager 推送的二进制带 helper)
	helper := filepath.Join(agentBaseDir, "upgrade_helper.exe")
	if _, err := os.Stat(helper); err == nil {
		return helper
	}
	// 2. 当前二进制同级目录
	if exe, err := os.Executable(); err == nil {
		helper = filepath.Join(filepath.Dir(exe), "upgrade_helper.exe")
		if _, err := os.Stat(helper); err == nil {
			return helper
		}
	}
	// 3. PATH 搜索
	if p, err := exec.LookPath("upgrade_helper.exe"); err == nil {
		return p
	}
	return ""
}

// copyFile 复制文件, 保留可执行权限。
func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()

	d, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer d.Close()

	if _, err := io.Copy(d, s); err != nil {
		return err
	}
	return d.Sync()
}

// fallbackBatchUpgrade v1.6.28: 旧的批处理升级作为降级兜底。
// 仅在 upgrade_helper.exe 不可用时使用。
func fallbackBatchUpgrade(newExe, curExe string) error {
	dir := filepath.Dir(curExe)

	helperPath := filepath.Join(dir, "upgrade_helper.bat")
	helper := fmt.Sprintf("@echo off\r\n"+
		"ping -n 3 127.0.0.1 >nul\r\n"+
		"move /y \"%s\" \"%s\"\r\n"+
		"if %%ERRORLEVEL%% NEQ 0 (\r\n"+
		"  echo move failed > \"%s.fail\"\r\n"+
		"  sc config node-agent start= auto\r\n"+
		"  sc start node-agent\r\n"+
		"  del \"%%~f0\" & exit /b 1\r\n"+
		")\r\n"+
		"sc config node-agent start= auto\r\n"+
		"sc start node-agent\r\n"+
		"del \"%%~f0\" & exit\r\n",
		newExe, curExe, curExe)

	if err := os.WriteFile(helperPath, []byte(helper), 0700); err != nil {
		return fmt.Errorf("write upgrade helper: %w", err)
	}

	upgradeLogger("降级批处理已写入: %s", helperPath)
	cmd := exec.Command("cmd", "/c", helperPath)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start upgrade helper: %w", err)
	}
	upgradeLogger("降级批处理已启动 (PID=%d)", cmd.Process.Pid)

	if upgradeShutdownCh != nil {
		close(upgradeShutdownCh)
	}
	return nil
}

func restartAgentAfterUpgrade() {}
