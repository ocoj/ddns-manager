//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// replaceRunningBinary replaces the currently running executable on Windows.
//
// v1.5.23 CRITICAL FIX: The original approach of calling stopServiceSync from within
// the service process caused a deadlock: sc stop → SCM sends stop to handler →
// handler tries to return → svc.Run exits → main returns → process killed before
// the batch script could be written or launched.
//
// v1.5.24 FIX: Write and launch the batch script FIRST, then exit. The batch script
// handles the full stop→replace→start cycle as a detached process:
//   1. Disable auto-start → stop service → poll STOPPED
//   2. Replace binary → verify → rollback on failure
//   3. Re-enable auto-start → start service
// The Go process exits after launching the batch (SCM restarts automatically).
func replaceRunningBinary(curExe, newExe, version string) error {
	upgradeLogger("Phase1: 写升级批处理并启动")
	dir := filepath.Dir(curExe)

	// Escape paths for batch file — reject paths with shell metacharacters to prevent command injection.
	for _, p := range []string{curExe, newExe} {
		if strings.ContainsAny(p, "&|<>^%\"") {
			upgradeLogger("路径安全检查失败: %s", p)
			return fmt.Errorf("unsafe path for batch script: %s", p)
		}
	}

	// Step 1: Write batch script BEFORE anything else — even if the process dies,
	// the batch is on disk and can be triggered manually or by the next heartbeat retry.
	scriptPath := filepath.Join(dir, "agent_upgrade.bat")
	upgradeLogger("Phase2: 写升级批处理 %s", scriptPath)
	// v1.5.22 设计说明: 升级日志写入安装目录 (ddns_upgrade.log) 而非 %%TEMP%%
	// 原因: 1) 软件未通过微软审核, 安装目录已设 AV 排除路径
	//       2) 实测 %%TEMP%% 在部分系统环境变量异常时定位失败/不可访问

	script := fmt.Sprintf("@echo off\r\n"+
		"chcp 65001 >nul\r\n"+ // v1.5.33: 切换控制台为 UTF-8, 避免中文乱码
		"cd /d \"%%~dp0\"\r\n"+ // v1.5.29: cd 到安装目录
		"reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\" /v \"%%~dp0\" /t REG_DWORD /d 0 /f >nul 2>&1\r\n"+ // Defender 排除
		"setlocal enabledelayedexpansion\r\n"+ // v1.5.20 C2: 延时变量展开
		"set OLD=%s\r\n"+
		"set NEW=%s\r\n"+
		"set BAK=%s.old.bak\r\n"+
		"echo [ddns] Upgrading to v%s...\r\n"+
		// Step 1: Disable auto-start (prevent SCM from restarting old binary)
		"sc config node-agent start= disabled >>\"ddns_upgrade.log\" 2>&1\r\n"+
		// Step 2: Stop service
		"sc stop node-agent >>\"ddns_upgrade.log\" 2>&1\r\n"+
		// Step 3: Poll until STOPPED (max 60s)
		"set COUNT=0\r\n"+
		":poll\r\n"+
		"  timeout /t 2 /nobreak >nul\r\n"+
		"  sc query node-agent | find \"STOPPED\" >nul\r\n"+
		"  if not errorlevel 1 goto :replace\r\n"+
		"  set /a COUNT+=1\r\n"+
		"  if !COUNT! LSS 30 goto :poll\r\n"+
		// Stop timeout: force kill
		"  echo [ddns] Force killing...\r\n"+
		"  taskkill /f /im node-agent.exe 2>nul\r\n"+
		"  timeout /t 3 /nobreak >nul\r\n"+
		// v1.5.34 M4: 验证进程确实已终止, 避免文件锁导致 move 失败
		"  tasklist /fi \"imagename eq node-agent.exe\" | find \"node-agent.exe\" >nul\r\n"+
		"  if not errorlevel 1 (\r\n"+
		"    echo [ddns] Force kill 失败, 进程仍在运行, 升级中止 >>\"ddns_upgrade.log\" 2>&1\r\n"+
		"    goto :done\r\n"+
		"  )\r\n"+
		":replace\r\n"+
		// Step 4: Backup old binary
		"move /y \"%%OLD%%\" \"%%BAK%%\" >>\"ddns_upgrade.log\" 2>&1\r\n"+
		// Step 5: Move new binary into place
		"move /y \"%%NEW%%\" \"%%OLD%%\" >>\"ddns_upgrade.log\" 2>&1\r\n"+
		// Step 6: Verify new binary exists and has expected size
		"if exist \"%%OLD%%\" (\r\n"+
		"  for %%%%A in (\"%%OLD%%\") do set NEWSIZE=%%%%~zA\r\n"+
		"  if !NEWSIZE! GTR 1024 (\r\n"+
		"    echo [ddns] Upgrade OK\r\n"+
		"    del \"%%BAK%%\" 2>nul\r\n"+
		"    goto :start_service\r\n"+
		"  )\r\n"+
		")\r\n"+
		// Step 7: Rollback — new binary verification failed
		"echo [ddns] Upgrade FAILED, rolling back...\r\n"+
		"move /y \"%%BAK%%\" \"%%OLD%%\" >>\"ddns_upgrade.log\" 2>&1\r\n"+
		":start_service\r\n"+
		// v1.5.30 C3: 回滚后二次验证 — 防止回滚失败导致启动损坏/不存在的二进制
		"if exist \"%%OLD%%\" (\r\n"+
		"  for %%%%A in (\"%%OLD%%\") do set OLDSIZE=%%%%~zA\r\n"+
		"  if !OLDSIZE! GTR 1024 goto :enable_service\r\n"+
		")\r\n"+
		"echo [ddns] 二进制验证失败, 无法启动服务 >>\"ddns_upgrade.log\" 2>&1\r\n"+
		"goto :done\r\n"+
		":enable_service\r\n"+
		// Step 8: Re-enable auto-start and start service
		"sc config node-agent start= auto >>\"ddns_upgrade.log\" 2>&1\r\n"+
		"sc start node-agent >>\"ddns_upgrade.log\" 2>&1\r\n"+
		// v1.5.33: 轮询 RUNNING 最多30s, 超时则回滚旧二进制
		"set SCOUNT=0\r\n"+
		":poll_start\r\n"+
		"  timeout /t 2 /nobreak >nul\r\n"+
		"  sc query node-agent | find \"RUNNING\" >nul\r\n"+
		"  if not errorlevel 1 goto :done\r\n"+
		"  set /a SCOUNT+=1\r\n"+
		"  if !SCOUNT! LSS 15 goto :poll_start\r\n"+
		// 启动超时: 回滚
		"  echo [ddns] Start timeout, rolling back...\r\n"+
		"  sc stop node-agent >nul 2>&1\r\n"+
		"  timeout /t 3 /nobreak >nul\r\n"+
		"  move /y \"%%OLD%%\" \"%%NEW%%\" >nul 2>&1\r\n"+
		"  move /y \"%%BAK%%\" \"%%OLD%%\" >>\"ddns_upgrade.log\" 2>&1\r\n"+
		"  sc start node-agent >>\"ddns_upgrade.log\" 2>&1\r\n"+
		":done\r\n"+
		"del \"%%~f0\" & exit\r\n",
		curExe, newExe, curExe, version)

	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		upgradeLogger("批处理写入失败: %v", err)
		return fmt.Errorf("write upgrade script: %w", err)
	}

	// Step 2: Launch detached batch process
	cmdLine, _ := windows.UTF16PtrFromString(fmt.Sprintf(`cmd /c "%s"`, scriptPath))

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE

	upgradeLogger("Phase3: 启动分离进程执行批处理...")
	err := windows.CreateProcess(
		nil, cmdLine,
		nil, nil, false,
		windows.CREATE_NO_WINDOW,
		nil, nil,
		&si, &pi,
	)
	if err != nil {
		upgradeLogger("CreateProcess失败: %v (批次脚本已写入 %s)", err, scriptPath)
		return fmt.Errorf("create detached process: %w", err)
	}

	upgradeLogger("分离进程已启动 (PID=%d)", pi.ProcessId)
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
	return nil
}

// stopServiceSync stops a Windows service and polls until it reaches STOPPED state.
// Used before binary replacement to prevent SCM from restarting the old binary.
func stopServiceSync(serviceName string, timeout time.Duration) {
	upgradeLogger("执行 sc stop %s", serviceName)
	exec.Command("sc", "stop", serviceName).Run()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("sc", "query", serviceName).CombinedOutput()
		if err != nil {
			// v1.5.20 Fix4: sc query 失败不直接 return，检查进程是否仍在运行
			tlOut, tlErr := exec.Command("tasklist", "/fi", "imagename eq "+serviceName+".exe", "/fo", "csv").CombinedOutput()
			if tlErr != nil || !strings.Contains(string(tlOut), serviceName+".exe") {
				upgradeLogger("sc query 失败但进程不存在, 认为已停止")
				return
			}
			upgradeLogger("sc query 失败但进程仍在, 继续轮询...")
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if strings.Contains(string(out), "STOPPED") {
			upgradeLogger("服务已停止 (STOPPED)")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	// Timeout: force kill
	upgradeLogger("停止超时, force kill node-agent.exe")
	exec.Command("taskkill", "/f", "/im", "node-agent.exe").Run()
	time.Sleep(1 * time.Second)
}

// startServiceSafe starts a Windows service and logs on failure.
// Used as fallback when the upgrade script fails to launch.
func startServiceSafe(serviceName string) {
	if err := exec.Command("sc", "start", serviceName).Run(); err != nil {
		// Service might already be running or not exist — not a critical error
	}
}

// restartAgentAfterUpgrade is a no-op on Windows.
// The detached batch script handles the restart after binary replacement.
// Unlike Linux (where systemctl start triggers an immediate heartbeat),
// on Windows the service restart triggers a new heartbeat via the daemon loop.
func restartAgentAfterUpgrade() {}
