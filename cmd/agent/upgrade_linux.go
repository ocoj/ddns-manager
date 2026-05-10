//go:build !windows

package main

import (
	"io"
	"os"
	"path/filepath"
)

// replaceRunningBinary 用版本化文件名+符号链接替换当前运行的 Agent。
// 下载 → 写入 node-agent-v{VERSION}-{os}-{arch} → 更新符号链接 → 删旧版。
// 符号链接确保 systemd timer 无需改配置即可指向新版本。
func replaceRunningBinary(curExe, newExe string) error {
	// 清理上次崩溃可能残留的 .tmp 文件
	os.Remove(curExe + ".tmp")

	src, err := os.Open(newExe)
	if err != nil {
		return err
	}
	defer src.Close()

	// 写入到版本化文件名 (如 node-agent-v1.5.3-linux-amd64)，保留在安装目录
	dir := filepath.Dir(curExe)
	versionedName := filepath.Base(newExe)
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
	os.Remove(newExe)
	return nil
}
