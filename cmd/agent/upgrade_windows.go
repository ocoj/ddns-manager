//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kk/ddns-manager/internal/model"
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

	// Phase 2: v1.6.33 P1 — 验证下载的二进制并写入版本化文件名
	// Linux版有完整 io.Copy → 版本化文件流程, Windows版原只做 os.Stat 验证
	// 缺少版本化文件写入导致升级助手 MoveFileEx 从 .new 替换到目标后无版本化备份
	newBinaryPath := curExe + ".new"
	fi, err := os.Stat(newBinaryPath)
	if err != nil {
		return fmt.Errorf("downloaded binary not found: %w", err)
	}
	if fi.Size() == 0 {
		return fmt.Errorf("downloaded binary is empty: %s", newBinaryPath)
	}
	// v1.6.33 P1: 写入版本化文件 node-agent-v{VERSION}-windows-amd64.exe
	// 保留历史版本便于回滚, 对齐 Linux 版行为
	versionedName := fmt.Sprintf("node-agent-v%s-windows-amd64.exe", version)
	versionedPath := filepath.Join(dir, versionedName)
	if newBinaryPath != versionedPath {
		if err := copyFile(newBinaryPath, versionedPath); err != nil {
			upgradeLogger("写入版本化文件失败: %v (非致命)", err)
		} else {
			upgradeLogger("版本化文件已写入: %s", versionedName)
		}
	}
	upgradeLogger("新二进制已验证: %s (%d bytes, PID=%d)", newBinaryPath, fi.Size(), pid)

	// Phase 3: 写入 upgrade_helper.exe (与 Agent 同目录)
	helperPath := filepath.Join(dir, "upgrade_helper.exe")
	helperExe := findHelperExe()
	if helperExe == "" {
		// 降级: 如果没有 helper exe, 使用旧批处理兜底
		upgradeLogger("未找到 upgrade_helper.exe, 降级到批处理方案")
		return fallbackBatchUpgrade(newBinaryPath, curExe)
	}
	// v1.6.31: helperExe==helperPath时跳过copy(同文件copy会O_TRUNC截断为0)
	if helperExe != helperPath {
		if err := copyFile(helperExe, helperPath); err != nil {
			upgradeLogger("复制 upgrade_helper.exe 失败: %v, 降级到批处理", err)
			return fallbackBatchUpgrade(newBinaryPath, curExe)
		}
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

// fallbackBatchUpgrade v1.6.28+v1.6.30: 旧的批处理升级作为降级兜底。
// 仅在 upgrade_helper.exe 不可用时使用。
// v1.6.30: 增加等待时间 ping -n 3→ping -n 10 (约9秒), 确保旧进程完全退出
// v1.6.42 C2: 修复 Sprintf 位置参数 Bug — Go 不支持 %[1]s, 改为普通 %s
func fallbackBatchUpgrade(newExe, curExe string) error {
	dir := filepath.Dir(curExe)
	agentLog("[upgrade] 降级到批处理升级方案 (helper不可用): new=%s cur=%s", newExe, curExe)

	helperPath := filepath.Join(dir, "upgrade_helper.bat")
	// C2: %s 替代 %[1]s/%[2]s — Go Sprintf 不支持位置参数
	helper := fmt.Sprintf("@echo off\r\n"+
		"rem v1.6.50 M1: 30次ping≈27秒等待 — SCM stop 可能需10-30秒, 9秒不足导致move失败→服务离线\r\n"+
		"ping -n 30 127.0.0.1 >nul\r\n"+
		"move /y \"%s\" \"%s\"\r\n"+
		"if %%ERRORLEVEL%% NEQ 0 (\r\n"+
		"  echo move failed, retrying with copy... >> \"%s.fail\"\r\n"+
		"  copy /y \"%s\" \"%s\"\r\n"+
		"  if %%ERRORLEVEL%% NEQ 0 (\r\n"+
		"    echo copy also failed >> \"%s.fail\"\r\n"+
		"  )\r\n"+
		"  del \"%s\" 2>nul\r\n"+
		")\r\n"+
		"sc config node-agent start= auto\r\n"+
		"sc start node-agent\r\n"+
		"del \"%%~f0\" & exit\r\n",
		newExe, curExe, curExe, newExe, curExe, curExe, newExe)

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

// downloadUpgradeHelper v1.6.30: 从 Manager 下载 upgrade_helper.exe 到安装目录。
// Go原生升级助手上次升级成功后自删除 → 下次升级时 findHelperExe 找不到 → 降级批处理。
// 此函数在 selfUpgrade 中调用, 确保下次升级有 upgrade_helper 可用。
// v1.6.31 C3: 先下载到 .tmp, 成功后原子 rename, 防止下载失败损坏已有的 upgrade_helper.exe
// 下载失败不阻塞升级 (findHelperExe 会回退到 PATH 搜索, replaceRunningBinary 会降级批处理)。
// v1.6.36 C2: 增加重试逻辑 (2次, 1s/2s退避) + manifest 文件名查询兜底, 提升升级可靠性。
func downloadUpgradeHelper(cfg *model.AgentConfig, targetVersion string) {
	helperPath := filepath.Join(agentBaseDir, "upgrade_helper.exe")
	// 如果已有 upgrade_helper.exe 且非零大小, 跳过下载
	if fi, err := os.Stat(helperPath); err == nil && fi.Size() > 0 {
		upgradeLogger("升级助手已存在: %s (%d bytes)", helperPath, fi.Size())
		return
	}

	// C2: 先构造 URL (优先使用与 Agent 同版本的 helper)
	helperURL := fmt.Sprintf("%s/dl/upgrade_helper-v%s-windows-amd64.exe",
		strings.TrimRight(cfg.ManagerURL, "/"), targetVersion)

	// v1.6.42 H6: 3次重试 + 1s/2s/3s 退避, 与 selfUpgrade 下载对齐, 覆盖瞬态网络故障
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
			upgradeLogger("升级助手下载重试 %d/3", attempt+1)
		}

		tmpPath := helperPath + ".dl"
		os.Remove(tmpPath) // 清理上次残留

		hc := newHTTPClient(cfg.VerifySSL, 30*time.Second)
		resp, err := hc.Get(helperURL)
		if err != nil {
			upgradeLogger("下载升级助手失败: %v (attempt=%d)", err, attempt+1)
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			upgradeLogger("下载升级助手 HTTP %d (attempt=%d)", resp.StatusCode, attempt+1)
			continue
		}
		f, err := os.Create(tmpPath)
		if err != nil {
			resp.Body.Close()
			upgradeLogger("创建升级助手临时文件失败: %v (attempt=%d)", err, attempt+1)
			continue
		}
		n, copyErr := io.Copy(f, io.LimitReader(resp.Body, 10<<20))
		f.Close()
		resp.Body.Close()
		if copyErr != nil {
			os.Remove(tmpPath)
			upgradeLogger("写入升级助手失败: %v (attempt=%d)", copyErr, attempt+1)
			continue
		}
		if n == 0 {
			os.Remove(tmpPath)
			upgradeLogger("下载升级助手为空 (attempt=%d)", attempt+1)
			continue
		}

		// 原子 rename: 只有完整下载才替换旧 helper
		if err := os.Rename(tmpPath, helperPath); err != nil {
			os.Remove(tmpPath)
			upgradeLogger("安装升级助手失败: %v (attempt=%d)", err, attempt+1)
			continue
		}
		upgradeLogger("升级助手已预下载: %s (%d bytes)", helperPath, n)
		return
	}
	// 2次重试均失败: 非致命, findHelperExe 会回退到 PATH 搜索
	upgradeLogger("升级助手下载彻底失败(2次重试用尽), 下次升级将回退到 PATH 搜索或批处理")
}
