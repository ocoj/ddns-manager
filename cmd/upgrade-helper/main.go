//go:build windows

// upgrade-helper — v1.6.28: Windows 升级助手 (替代不可靠的 cmd 批处理)
//
// 由 node-agent 在自升级时启动, 负责:
//  1. 等待旧 Agent 进程退出 (轮询进程句柄, 最多 60 秒)
//  2. 原子替换二进制 (movefile)
//  3. 恢复服务自动启动并拉起新 Agent
//  4. 自删除 (通过批处理延迟删除)
//
// 命令行: upgrade-helper.exe <oldPid> <newExe> <curExe>
//    oldPid:  旧 Agent 进程 PID
//    newExe:  新二进制完整路径 (node-agent.exe.new)
//    curExe:  当前运行的二进制路径 (替换目标)
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

var (
	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	openProcess      = kernel32.NewProc("OpenProcess")
	waitForSingleObj = kernel32.NewProc("WaitForSingleObject")
	closeHandle      = kernel32.NewProc("CloseHandle")
)

const (
	SYNCHRONIZE         = 0x00100000
	PROCESS_QUERY_LIMITED = 0x1000
	WAIT_TIMEOUT        = 0x00000102
	WAIT_FAILED         = 0xFFFFFFFF
)

func main() {
	if len(os.Args) < 4 {
		os.Exit(1)
	}
	oldPidStr := os.Args[1]
	newExe := os.Args[2]
	curExe := os.Args[3]

	// 将 stderr/stdout 重定向到日志文件
	logPath := curExe + ".upgrade.log"
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer logFile.Close()
		os.Stdout = logFile
		os.Stderr = logFile
	}
	fmt.Printf("[%s] upgrade-helper 启动: oldPid=%s new=%s cur=%s\n",
		time.Now().Format("2006-01-02 15:04:05"), oldPidStr, newExe, curExe)

	// Phase 1: 等待旧进程退出
	waitForOldProcess(oldPidStr)

	// Phase 2: 原子替换二进制
	if !replaceBinary(newExe, curExe) {
		fmt.Printf("[%s] 二进制替换失败, 恢复旧版本服务\n", time.Now().Format(time.RFC3339))
		restartService()
		os.Exit(1)
	}
	fmt.Printf("[%s] 二进制替换成功\n", time.Now().Format(time.RFC3339))

	// Phase 3: 恢复服务并启动
	restartService()

	// Phase 4: 自删除
	selfDelete()
}

// waitForOldProcess 等待旧 Agent 进程退出, 最多 60 秒。
// openProcess 用的权限组合: SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION
func waitForOldProcess(pidStr string) {
	var pid uint32
	fmt.Sscanf(pidStr, "%d", &pid)
	if pid == 0 {
		fmt.Printf("[%s] 无效 PID=%s, 跳过等待\n", time.Now().Format(time.RFC3339), pidStr)
		time.Sleep(3 * time.Second)
		return
	}

	hProcess, _, _ := openProcess.Call(
		uintptr(SYNCHRONIZE|PROCESS_QUERY_LIMITED),
		0,
		uintptr(pid),
	)
	if hProcess == 0 {
		fmt.Printf("[%s] 无法打开进程 PID=%d (可能已退出), 等待 3 秒后继续\n",
			time.Now().Format(time.RFC3339), pid)
		time.Sleep(3 * time.Second)
		return
	}
	defer closeHandle.Call(hProcess)

	fmt.Printf("[%s] 等待进程 PID=%d 退出 (最多 60 秒)...\n",
		time.Now().Format(time.RFC3339), pid)

	// 轮询等待: WaitForSingleObject 超时 2 秒, 最多 30 次 = 60 秒
	for i := 0; i < 30; i++ {
		ret, _, _ := waitForSingleObj.Call(hProcess, 2000)
		if ret != WAIT_TIMEOUT {
			fmt.Printf("[%s] 进程 PID=%d 已退出\n", time.Now().Format(time.RFC3339), pid)
			// 额外等待 1 秒确保文件句柄释放
			time.Sleep(1 * time.Second)
			return
		}
		fmt.Printf("[%s] 进程 PID=%d 仍在运行 (%d/30)...\n",
			time.Now().Format(time.RFC3339), pid, i+1)
	}
	fmt.Printf("[%s] 等待超时 (60 秒), 进程 PID=%d 未退出, 强制继续\n",
		time.Now().Format(time.RFC3339), pid)
}

// replaceBinary 原子替换运行中的二进制文件。
// 使用 MoveFileEx + MOVEFILE_REPLACE_EXISTING + MOVEFILE_WRITE_THROUGH。
// Windows 允许替换正在运行的可执行文件的目录项 (内核保持 in-use 文件的映射)。
func replaceBinary(newExe, curExe string) bool {
	// 先尝试直接 MoveFileEx (原子替换)
	newPtr, _ := syscall.UTF16PtrFromString(newExe)
	curPtr, _ := syscall.UTF16PtrFromString(curExe)

	// MOVEFILE_REPLACE_EXISTING = 0x1 | MOVEFILE_WRITE_THROUGH = 0x8
	err := windows.MoveFileEx(newPtr, curPtr, 0x1|0x8)
	if err != nil {
		fmt.Printf("[%s] MoveFileEx 失败: %v, 尝试 delete+rename\n",
			time.Now().Format(time.RFC3339), err)
		// 降级方案: 先尝试删除旧文件, 再 rename
		os.Remove(curExe)
		if err := os.Rename(newExe, curExe); err != nil {
			fmt.Printf("[%s] rename 也失败: %v\n", time.Now().Format(time.RFC3339), err)
			return false
		}
	}
	return true
}

// restartService 恢复服务自动启动并启动服务, 轮询验证 RUNNING 状态。
// sc config start= auto → sc start → sc query 轮询 RUNNING (最多30s)
func restartService() {
	fmt.Printf("[%s] 恢复服务自动启动...\n", time.Now().Format(time.RFC3339))
	out, err := exec.Command("sc", "config", "node-agent", "start=", "auto").CombinedOutput()
	if err != nil {
		fmt.Printf("[%s] sc config auto 失败: %v %s\n",
			time.Now().Format(time.RFC3339), err, string(out))
	}
	time.Sleep(500 * time.Millisecond)

	fmt.Printf("[%s] 启动服务...\n", time.Now().Format(time.RFC3339))
	out, err = exec.Command("sc", "start", "node-agent").CombinedOutput()
	if err != nil {
		fmt.Printf("[%s] sc start 失败: %v %s\n",
			time.Now().Format(time.RFC3339), err, string(out))
		// v1.6.28 C3: 最后一次尝试 (延迟 2 秒重试)
		time.Sleep(2 * time.Second)
		out, err = exec.Command("sc", "start", "node-agent").CombinedOutput()
		if err != nil {
			fmt.Printf("[%s] sc start 重试仍失败: %v %s\n",
				time.Now().Format(time.RFC3339), err, string(out))
			return
		}
		fmt.Printf("[%s] sc start 重试成功\n", time.Now().Format(time.RFC3339))
	} else {
		fmt.Printf("[%s] sc start 返回成功\n", time.Now().Format(time.RFC3339))
	}

	// v1.6.29 C5: 轮询验证服务进入 RUNNING 状态 (最多 30s)
	// 防止新二进制有bug导致启动即崩溃, sc start 报告成功但服务立即 STOPPED
	for i := 0; i < 15; i++ {
		time.Sleep(2 * time.Second)
		queryOut, queryErr := exec.Command("sc", "query", "node-agent").CombinedOutput()
		queryStr := string(queryOut)
		if queryErr != nil {
			fmt.Printf("[%s] sc query 失败 (%d/15): %v\n",
				time.Now().Format(time.RFC3339), i+1, queryErr)
			continue
		}
		if strings.Contains(queryStr, "RUNNING") {
			fmt.Printf("[%s] 服务验证通过: RUNNING (%d/15)\n",
				time.Now().Format(time.RFC3339), i+1)
			return
		}
		if strings.Contains(queryStr, "STOPPED") {
			fmt.Printf("[%s] 服务验证失败: 状态=STOPPED (%d/15), 新二进制可能崩溃\n",
				time.Now().Format(time.RFC3339), i+1)
			continue
		}
		fmt.Printf("[%s] 等待服务启动 (%d/15)...\n",
			time.Now().Format(time.RFC3339), i+1)
	}
	fmt.Printf("[%s] 服务验证超时 (30s), 状态可能非RUNNING\n", time.Now().Format(time.RFC3339))
}

// selfDelete 通过 cmd /c 延迟删除自身 (升级助手)。
func selfDelete() {
	myPath, err := os.Executable()
	if err != nil {
		return
	}
	// 使用 cmd /c ping 延迟 + del 删除自身
	script := fmt.Sprintf("@echo off\r\nping -n 2 127.0.0.1 >nul\r\ndel /f \"%s\"\r\ndel \"%%~f0\"\r\n", myPath)
	tmp := myPath + ".del.bat"
	os.WriteFile(tmp, []byte(script), 0700)
	exec.Command("cmd", "/c", tmp).Start()
}
