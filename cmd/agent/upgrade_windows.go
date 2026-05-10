//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// replaceRunningBinary replaces the currently running executable on Windows.
// The running .exe cannot be renamed directly (file lock), so we:
//   1. Write a detached batch script that waits, moves, and restarts the service
//   2. Start the script via Windows CreateProcess with CREATE_NO_WINDOW
//   3. Exit — SCM auto-restarts the service after 5s (sc failure config)
// replaceRunningBinary on Windows replaces the running .exe via detached batch script.
// The version parameter is accepted for signature compatibility with Linux but ignored
// on Windows (the binary filename is managed by the batch script's move command).
func replaceRunningBinary(curExe, newExe, version string) error {
	dir := filepath.Dir(curExe)
	scriptPath := filepath.Join(dir, "agent_upgrade.bat")

	// Escape paths for batch file — reject paths with shell metacharacters to prevent command injection.
	// Valid Windows install paths should only contain safe ASCII characters.
	for _, p := range []string{curExe, newExe} {
		if strings.ContainsAny(p, "&|<>^%\"") {
			return fmt.Errorf("unsafe path for batch script: %s", p)
		}
	}

	// 等待服务完全停止（最多 30 秒，每 2 秒检查一次），防止 move 时文件被锁定
	// sc stop 是异步的，简单 sleep 在某些情况下不够（如 DNS API 等待中）
	script := fmt.Sprintf("@echo off\r\n"+
		"sc stop node-agent\r\n"+
		"set /a wait=0\r\n"+
		":waitstop\r\n"+
		"ping 127.0.0.1 -n 3 >nul\r\n"+
		"sc query node-agent | findstr /C:\"STOPPED\" >nul && goto :doreplace\r\n"+
		"set /a wait+=1\r\n"+
		"if %%wait%% LSS 15 goto :waitstop\r\n"+
		"echo Service still running, forcing... \r\n"+
		"taskkill /f /im node-agent.exe >nul 2>&1\r\n"+
		"ping 127.0.0.1 -n 3 >nul\r\n"+
		":doreplace\r\n"+
		"move /y \"%s\" \"%s\"\r\n"+
		"sc start node-agent\r\n"+
		"del \"%%~f0\" & exit\r\n",
		newExe, curExe)

	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		return fmt.Errorf("write upgrade script: %w", err)
	}

	// Create detached process — pass cmd /c as the command line, nil app name
	cmdLine, _ := windows.UTF16PtrFromString(fmt.Sprintf(`cmd /c ""%s""`, scriptPath))

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE

	err := windows.CreateProcess(
		nil,          // lpApplicationName
		cmdLine,       // lpCommandLine
		nil, nil, false,
		windows.CREATE_NO_WINDOW,
		nil, nil,
		&si, &pi,
	)
	if err != nil {
		return fmt.Errorf("create detached process: %w", err)
	}

	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
	return nil
}

// restartAgentAfterUpgrade is a no-op on Windows — SCM auto-restarts the service
// via sc failure config (restart/5000). The detached batch script handles the restart.
func restartAgentAfterUpgrade() {}
