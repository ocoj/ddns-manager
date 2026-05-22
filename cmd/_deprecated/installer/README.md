# cmd/_deprecated/installer

旧版安装器代码（v1.0.0 冻结），已于 v1.6.42 归档。

**不再维护**。新安装器位于 `cmd/installer-linux/` 和 `cmd/installer-windows/`，
使用共享逻辑 `internal/installer/`。

旧版与新版的核心差异：
- 旧版含下载功能（从 Manager 拉取 Agent 二进制）→ v1.6.30+ 已移除
- 旧版含独立 ddns-go 检测逻辑 → 新版由 internal/installer 统一处理
- 旧版使用 `node-agent-latest` URL 模式 → 新版使用版本化文件名

如需恢复旧版安装器，将文件移回 `cmd/installer/` 并手动构建。
