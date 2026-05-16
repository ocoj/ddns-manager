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
// v1.6.14 C7: Windows升级保持 netsh/certutil 直调, IIS扫描仍用 WebAdministration API。
//
// IIS扫描历史教训 (见 CHANGELOG v1.6.1→v1.6.7):
//   v1.6.1: netsh → 0个绑定(解析失败)
//   v1.6.2: 全路径 netsh → 仍0绑定
//   v1.6.5: SYSTEM locale输出中文"IP:端口"/"证书哈希", 英文解析彻底失效
//   v1.6.7: WebAdministration API → 结构化JSON, 不受locale影响
//   C7结论: netsh文本解析是死路, 必须用WebAdministration, 不可用时优雅降级
//
// 升级机制:
//   1. sc config disabled (Go直接调用, 不依赖cmd)
//   2. 启动极简cmd助手: ping等待→move替换→sc config auto→sc start
//   3. 关闭upgradeShutdownCh → Execute() select检测 → SCM标准退出
//   4. Go进程通过SCM协议干净退出 → sc start正常启动新二进制

var upgradeShutdownCh chan struct{}

func replaceRunningBinary(curExe, newExe, version string) error {
	upgradeLogger("Phase1: 禁用服务自动重启...")
	if out, err := exec.Command("sc", "config", "node-agent", "start=", "disabled").CombinedOutput(); err != nil {
		upgradeLogger("sc config disabled 失败: %v %s", err, string(out))
	}

	dir := filepath.Dir(curExe)

	helperPath := filepath.Join(dir, "upgrade_helper.bat")
	helper := fmt.Sprintf("@echo off\r\n"+
		"ping -n 3 127.0.0.1 >nul\r\n"+
		"move /y \"%s\" \"%s\"\r\n"+
		"sc config node-agent start= auto\r\n"+
		"sc start node-agent\r\n"+
		"del \"%%~f0\" & exit\r\n",
		newExe, curExe)

	if err := os.WriteFile(helperPath, []byte(helper), 0700); err != nil {
		upgradeLogger("助手脚本写入失败: %v", err)
		return fmt.Errorf("write upgrade helper: %w", err)
	}

	upgradeLogger("Phase2: 启动升级助手...")
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

	upgradeLogger("Phase3: 触发SCM标准退出...")
	if upgradeShutdownCh != nil {
		close(upgradeShutdownCh)
	}
	return nil
}

func restartAgentAfterUpgrade() {}
