//go:build !windows

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// replaceRunningBinary 用版本化文件名+符号链接替换当前运行的 Agent。
// 下载 → 写入 node-agent-v{VERSION}-{os}-{arch} → 更新符号链接 → 删旧版。
// 符号链接确保 systemd timer 无需改配置即可指向新版本。
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
	oldName := filepath.Base(curExe) // e.g. "node-agent-v1.5.2-linux-amd64"

	// 构建版本化文件名: node-agent-v{VERSION}-{os}-{arch}
	// 平台后缀直接从运行时获取，不依赖旧文件名解析
	var versionedName string
	v := version
	if v == "" || v == "dev" {
		v = filepath.Base(newExe)
		v = strings.TrimSuffix(v, ".new")
		// 从临时文件名提取版本: node-agent-v1.5.3-linux-amd64.new → 1.5.3
		if idx := strings.Index(v, "-v"); idx != -1 {
			rest := v[idx+2:] // "1.5.3-linux-amd64"
			if sep := strings.LastIndex(rest, "-" + runtime.GOOS + "-"); sep != -1 {
				v = rest[:sep] // "1.5.3"
			}
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

	// 更新符号链接: node-agent → node-agent-v1.5.3-linux-amd64
	link := filepath.Join(dir, "node-agent")
	os.Remove(link)
	if err := os.Symlink(versionedName, link); err != nil {
		return err
	}

	// 清理旧的版本化二进制（当前版本，非新版本）
	// 只删与新版本名不同的旧版本化文件，避免误删
	if versionedName != oldName {
		oldVersionedPath := filepath.Join(dir, oldName)
		os.Remove(oldVersionedPath)
	}

	// 删除下载的临时文件
	os.Remove(newExe)
	return nil
}

// restartAgentAfterUpgrade 在自升级完成后立即触发一次心跳，避免 Linux oneshot
// 模式下的 5 分钟 DNS 更新中断。
//
// v1.5.13 修复: 使用 --no-block 防止 systemctl 等待当前进程完成（死锁）。
// 在 oneshot 模式下调用 systemctl start 自身会因 systemd 等待服务完成而永久阻塞。
// --no-block 使 systemctl 仅排队启动请求后立即返回。
func restartAgentAfterUpgrade() {
	// 触发即时心跳 — 非阻塞（--no-block），失败不影响升级流程
	cmd := exec.Command("systemctl", "start", "--no-block", "node-agent.service")
	if err := cmd.Run(); err != nil {
		// node-agent.service 是 oneshot，可能在退出前已被 timer 触发
		// 失败记录日志但不应该影响升级结果
	}
}
