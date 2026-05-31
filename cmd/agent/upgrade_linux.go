//go:build !windows

package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ocoj/ddns-manager/internal/model"
)

// replaceRunningBinary 用版本化文件名+符号链接替换当前运行的 Agent。
// 写入新二进制 node-agent-v{VERSION}-{os}-{arch} → 更新符号链接 → 删旧版。
// (下载由 selfUpgrade 在调用前完成)
// 符号链接确保 systemd timer 无需改配置即可指向新版本。
//
// v1.5.37: 符号链接原子替换 — 通过 tmpLink + os.Rename 避免 Remove→Symlink
// 之间的窗口期导致 symlink 永久丢失(两个节点 v1.5.34→v1.5.36 离线根因)。
//
// version 参数用于构建正确的版本化文件名（e.g. "1.5.3"）。
// 平台后缀从 runtime.GOOS/runtime.GOARCH 直接获取，不解析旧文件名
// （旧文件名可能含 git describe 多段版本号如 1.5.2-1-ga5565a9，导致拆错）。
func replaceRunningBinary(curExe, newExe, version string) error {
	// 清理上次崩溃可能残留的 .tmp 文件
	os.Remove(curExe + ".tmp")

	src, err := os.Open(newExe)
	if err != nil {
		return err
	}
	defer src.Close()

	dir := filepath.Dir(curExe)
	// 构建版本化文件名: node-agent-v{VERSION}-{os}-{arch}
	// v1.6.10 L2: 增加时间戳兜底, 防止版本号提取失败时生成无效文件名
	var versionedName string
	v := version
	if v == "" || v == "dev" {
		v = filepath.Base(newExe)
		v = strings.TrimSuffix(v, ".new")
		if idx := strings.Index(v, "-v"); idx != -1 {
			rest := v[idx+2:]
			if sep := strings.LastIndex(rest, "-"+runtime.GOOS+"-"); sep != -1 {
				v = rest[:sep]
			}
		}
		// 最终兜底: 提取失败时使用下载时间戳, 避免生成 node-agent-v--linux-amd64
		if v == "" || v == "dev" {
			v = time.Now().Format("20060102.150405")
			log.Printf("[upgrade] 无法从文件名提取版本号, 使用时间戳: %s", v)
		}
	}
	versionedName = fmt.Sprintf("node-agent-v%s-%s-%s", v, runtime.GOOS, runtime.GOARCH)

	versionedPath := filepath.Join(dir, versionedName)
	tmp := versionedPath + ".tmp"

	dst, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(tmp)
		return err
	}
	if err := dst.Sync(); err != nil {
		dst.Close()
		os.Remove(tmp)
		return err
	}
	dst.Close()

	if err := os.Rename(tmp, versionedPath); err != nil {
		os.Remove(tmp)
		return err
	}

	// v1.5.37: 符号链接原子替换 — 先建临时链接, 再 os.Rename 原子切到正式名。
	// os.Rename 在同一文件系统内是原子的: 要么新链接生效, 要么旧链接保持不变。
	// 避免了 v1.5.34-os.Remove(link)→v1.5.34-os.Symlink 中间窗口导致 symlink 裸奔的根因。
	link := filepath.Join(dir, "node-agent")
	tmpLink := link + ".linktmp"
	os.Remove(tmpLink) // 清理上次残留
	if err := os.Symlink(versionedName, tmpLink); err != nil {
		return fmt.Errorf("创建临时符号链接失败: %w", err)
	}
	if err := os.Rename(tmpLink, link); err != nil {
		os.Remove(tmpLink)
		return fmt.Errorf("替换符号链接失败: %w", err)
	}

	// v1.6.51: 清理所有旧版版本化二进制（非当前版本），防止历史版本堆积。
	// 遍历目录中所有 node-agent-v* 文件，删除非当前版本的旧版。
	entries, readErr := os.ReadDir(dir)
	if readErr == nil {
		for _, entry := range entries {
			name := entry.Name()
			// 防误删: 跳过目录、非版本化文件、当前版本
			if entry.IsDir() {
				continue
			}
			if name == versionedName || !strings.HasPrefix(name, "node-agent-v") {
				continue
			}
			if strings.HasSuffix(name, ".sha256") ||
				strings.HasSuffix(name, ".tmp") ||
				strings.HasSuffix(name, ".linktmp") {
				continue
			}
			oldPath := filepath.Join(dir, name)
			if err := os.Remove(oldPath); err != nil && !os.IsNotExist(err) {
				log.Printf("[upgrade] 删除旧版二进制失败: %s (%v)", name, err)
			} else if err == nil {
				log.Printf("[upgrade] 已清理旧版: %s", name)
			}
		}
	}

	// 删除下载的临时文件
	if err := os.Remove(newExe); err != nil && !os.IsNotExist(err) {
		log.Printf("[upgrade] 删除临时文件失败: %s (%v)", newExe, err)
	}
	return nil
}

// restartAgentAfterUpgrade 在自升级完成后立即触发一次心跳，避免 Linux oneshot
// 模式下的 5 分钟 DNS 更新中断。
//
// v1.5.37: 增加 3次重试+错误日志, 避免 v1.5.34→v1.5.36 时 systemctl start 静默失败
// 导致新进程未启动、旧进程已退出、symlink 丢失的离线链式故障。
//
// v1.5.13 修复: 使用 --no-block 防止 systemctl 等待当前进程完成（死锁）。
func restartAgentAfterUpgrade() {
	for i := 0; i < 3; i++ {
		agentLog("[upgrade] systemctl start 第%d次...", i+1)
		cmd := exec.Command("systemctl", "start", "--no-block", "node-agent.service")
		if err := cmd.Run(); err != nil {
			log.Printf("[upgrade] systemctl start 失败(第%d次): %v", i+1, err)
			agentLog("[upgrade] systemctl start 失败(第%d次): %v", i+1, err)
			time.Sleep(2 * time.Second)
			continue
		}
		log.Printf("[upgrade] systemctl start --no-block 成功")
		agentLog("[upgrade] systemctl start --no-block 成功")
		return
	}
	// 3次重试均失败: 不阻塞升级流程, agent timer 会在下次触发时间自动拉起
	log.Printf("[upgrade] systemctl start 3次重试均失败, 依赖 node-agent.timer 下次自动触发")
	agentLog("[upgrade] systemctl start 3次重试均失败, 依赖 node-agent.timer 下次自动触发")
}

// downloadUpgradeHelper Linux 无操作（Windows 实现在 upgrade_windows.go）。
// v1.6.44 H2: 必须保留此桩函数，否则 Go 编译器无法为 Linux 构建 selfUpgrade。
func downloadUpgradeHelper(cfg *model.AgentConfig, targetVersion string) {}
