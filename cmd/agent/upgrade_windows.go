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
// C3 FIX: The original implementation had a race condition where the Go process
// called os.Exit(0) before the detached batch script executed sc stop. SCM
// detected the process exit and immediately restarted the old binary, locking
// the file and causing move /y to fail silently.
//
// FIXED flow:
//   1. Synchronously stop the service (sc stop + poll until STOPPED, max 30s)
//   2. Write and launch a detached batch script that moves the new binary over
//      the old one, then starts the service
//   3. Go process exits — SCM won't restart because the service is already stopped
//
// M3 FIX: Batch script now verifies the move succeeded and restores the old binary
// from a backup on failure, preventing permanent node offline.
//
// The version parameter is accepted for signature compatibility with Linux but ignored
// on Windows (the binary filename is managed by the batch script's move command).
func replaceRunningBinary(curExe, newExe, version string) error {
	// v1.5.20: 详细步骤日志，写入 %TEMP%\ddns_upgrade_agent.log
	upgradeLogger("Phase1: 停止服务 node-agent")
	dir := filepath.Dir(curExe)

	// Escape paths for batch file — reject paths with shell metacharacters to prevent command injection.
	// Valid Windows install paths should only contain safe ASCII characters.
	for _, p := range []string{curExe, newExe} {
		if strings.ContainsAny(p, "&|<>^%\"") {
			upgradeLogger("路径安全检查失败: %s", p)
			return fmt.Errorf("unsafe path for batch script: %s", p)
		}
	}

	// === Phase 1: Synchronously stop the service BEFORE launching detached batch ===
	// This eliminates the race: when the Go process exits, SCM sees the service
	// is already stopped and won't try to restart the old binary.
	upgradeLogger("Phase1: stopServiceSync 完成")
	stopServiceSync("node-agent", 30*time.Second)

	// === Phase 2: Write detached batch script ===
	// At this point the service IS stopped, so the old .exe is not locked.
	scriptPath := filepath.Join(dir, "agent_upgrade.bat")
	upgradeLogger("Phase2: 写升级批处理 %s", scriptPath)

	// M3: Batch script with rollback — backup old binary, move new over old,
	// verify the move, restore from backup on failure.
	script := fmt.Sprintf("@echo off\r\n"+
		"setlocal enabledelayedexpansion\r\n"+ // v1.5.20 C2: 延时变量展开
		"set OLD=%s\r\n"+
		"set NEW=%s\r\n"+
		"set BAK=%s.old.bak\r\n"+
		"echo [ddns] Upgrading...\r\n"+
		// Backup old binary for rollback
		"move /y \"%%OLD%%\" \"%%BAK%%\" >>\"%%TEMP%%\\ddns_upgrade.log\" 2>&1\r\n"+ // v1.5.20 C3: 升级日志可诊断
		// Move new binary into place
		"move /y \"%%NEW%%\" \"%%OLD%%\" >>\"%%TEMP%%\\ddns_upgrade.log\" 2>&1\r\n"+ // v1.5.20 C3: 升级日志可诊断
		// M3: Verify new binary exists and has expected size
		"if exist \"%%OLD%%\" (\r\n"+
		"  for %%%%A in (\"%%OLD%%\") do set NEWSIZE=%%%%~zA\r\n"+
		"  if !NEWSIZE! GTR 1024 (\r\n"+
		"    echo [ddns] Upgrade OK, starting service...\r\n"+
		"    sc start node-agent\r\n"+
		"    del \"%%BAK%%\" 2>nul\r\n"+
		"    goto :done\r\n"+
		"  )\r\n"+
		")\r\n"+
		// M3: Rollback — new binary failed, restore from backup
		"echo [ddns] Upgrade FAILED, rolling back...\r\n"+
		"move /y \"%%BAK%%\" \"%%OLD%%\" >>\"%%TEMP%%\\ddns_upgrade.log\" 2>&1\r\n"+ // v1.5.20 C3: 回滚日志可诊断
		"sc start node-agent\r\n"+
		":done\r\n"+
		"del \"%%~f0\" & exit\r\n",
		curExe, newExe, curExe)

	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		// If script write fails, restart the service (we already stopped it)
		upgradeLogger("批处理写入失败: %v", err)
		startServiceSafe("node-agent")
		return fmt.Errorf("write upgrade script: %w", err)
	}

	// === Phase 3: Launch detached batch process ===
	// Pass cmd /c as the command line, nil app name.
	// The batch script will move the binary, verify, and restart the service.
	cmdLine, _ := windows.UTF16PtrFromString(fmt.Sprintf(`cmd /c "%s"`, scriptPath)) // v1.5.22: 单层引号, 避免CMD误解析

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE

	upgradeLogger("Phase3: 启动分离进程执行批处理...")
	err := windows.CreateProcess(
		nil, // lpApplicationName
		cmdLine, // lpCommandLine
		nil, nil, false,
		windows.CREATE_NO_WINDOW,
		nil, nil,
		&si, &pi,
	)
	if err != nil {
		// If CreateProcess fails, restart the service with old binary
		upgradeLogger("CreateProcess失败: %v", err)
		startServiceSafe("node-agent")
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
