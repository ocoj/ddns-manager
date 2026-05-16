//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// v1.6.12 C6: 彻底废弃不可靠的批处理升级方案。
// 旧方案问题:
//   1. reg add Defender排除 在Win10被拒绝(Access Denied)
//   2. chcp 65001/timeout /t 在无console环境卡死
//   3. setlocal enabledelayedexpansion 复杂且易出错
//   4. 孤儿cmd.exe累积(每次升级泄漏一个进程)
//   5. batch文件日志重定向(>>)在并发时文件锁死锁
//
// 新方案:
//   1. sc config disabled (Go直接调用, 不依赖cmd)
//   2. 启动极简cmd助手: ping等待→move替换→sc config auto→sc start
//   3. 关闭upgradeShutdownCh → Execute() select检测 → SCM标准退出
//   4. Go进程通过SCM协议干净退出 → sc start正常启动新二进制

// upgradeShutdownCh is closed by replaceRunningBinary to trigger a clean SCM exit.
// Set by svc_windows.go Execute(), read (closed) by replaceRunningBinary.
var upgradeShutdownCh chan struct{}

func replaceRunningBinary(curExe, newExe, version string) error {
	upgradeLogger("Phase1: 禁用服务自动重启...")
	// sc config disabled 防止SCM在进程退出后自动拉起旧二进制
	if out, err := exec.Command("sc", "config", "node-agent", "start=", "disabled").CombinedOutput(); err != nil {
		upgradeLogger("sc config disabled 失败: %v %s", err, string(out))
		// 不致命, 继续执行
	}

	dir := filepath.Dir(curExe)

	// Phase2: 写极简升级助手脚本 (仅在当前cmd.exe退出后执行 move+restart)
	// 不再使用 chcp/reg add/timeout/setlocal — 完全避控台依赖
	helperPath := filepath.Join(dir, "upgrade_helper.bat")
	helper := fmt.Sprintf("@echo off\r\n"+
		"ping -n 3 127.0.0.1 >nul\r\n"+ // 等待3秒确保Go进程完全退出
		"move /y \"%s\" \"%s\"\r\n"+ // 新二进制 → 正式位置
		"sc config node-agent start= auto\r\n"+ // 恢复自动启动
		"sc start node-agent\r\n"+ // 启动新版本服务
		"del \"%%~f0\" & exit\r\n", // 自删
		newExe, curExe)

	if err := os.WriteFile(helperPath, []byte(helper), 0700); err != nil {
		upgradeLogger("助手脚本写入失败: %v", err)
		return fmt.Errorf("write upgrade helper: %w", err)
	}

	upgradeLogger("Phase2: 启动升级助手...")
	// 用 DETACHED_PROCESS + HideWindow 确保进程完全独立, 不继承控制台
	cmd := exec.Command("cmd", "/c", helperPath)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		upgradeLogger("启动助手失败: %v", err)
		return fmt.Errorf("start upgrade helper: %w", err)
	}
	upgradeLogger("升级助手已启动 (PID=%d)", cmd.Process.Pid)

	// Phase3: 触发SCM标准退出 (Execute() select检测到→关闭stopCh→StopPending→返回)
	upgradeLogger("Phase3: 触发SCM标准退出...")
	if upgradeShutdownCh != nil {
		close(upgradeShutdownCh)
		// 通道只能关闭一次, 下次Execute()会创建新通道
	}
	return nil
}

// restartAgentAfterUpgrade 在 Windows 上是 no-op (升级助手处理重启)
func restartAgentAfterUpgrade() {}
