# ddns-manager 版本推进开发规范

> v1.5.37 起生效 | 维护者：KK虾 (KK) | 最后更新：2026-05-24

## 1. 版本号规则

### 格式

```
v{Major}.{Minor}.{Patch}

- Major: 架构重设计、API 不兼容变更（本项目尚未进入 v2，暂不触发）
- Minor: 新功能、审计修复批次
- Patch: 单点热修复（保留，实际使用极少）
```

### 唯一真相源

**`VERSION` 文件（项目根目录）是版本号的唯一真相源。**

```
优先级: 环境变量 VERSION > VERSION 文件 > git tag (仅参考，不进入文件名)
```

### 数据库存储

| 位置 | 字段 | 说明 |
|------|------|------|
| `agent_config.json` | `latest_version` | Manager 推送的目标 Agent 版本 |
| `nodes.json` | `status.agent_version` | Agent 上报的当前版本 |
| `agent_manifest.json` | `{platform: filename}` | /bin/ 目录最高版本二进制映射 |

## 2. 版本推进流程（严格执行）

### 2.1 发版前检查清单

```
[ ] VERSION 已递增到目标版本号
[ ] CHANGELOG.md 已添加新版本条目（含修复项、部署状态）
[ ] README.md 版本号已更新
[ ] 全平台编译通过 (bash scripts/build.sh)
[ ] go vet ./... 无警告
[ ] go test ./... 全部通过
[ ] agent_manifest.json 与 /bin/ 目录内容一致（Manager 重启后自动 RebuildManifest）
```

### 2.2 发版操作序列

```bash
# 1. 编码 → 提交
echo "x.y.z" > VERSION
# 编辑 CHANGELOG.md、README.md
git add -A
git commit -m "vx.y.z: 变更摘要"
git tag vx.y.z

# 2. 构建
bash scripts/build.sh

# 3. 部署 Manager
# 将 ddns-manager-vx.y.z-linux-amd64 部署到管理端
# sudo systemctl restart ddns-manager

# 4. 上传二进制到 /bin/
# 将 node-agent-vx.y.z-{平台} 全量上传到管理端 /opt/ddns-manager/data/bin/
# ⚠️ 必须同时上传所有 4 个平台 (linux-amd64/arm/arm64/windows-amd64)

# 5. 设置 Agent 版本
# POST /api/admin/agent-version {"latest_version":"x.y.z"}
# ⚠️ 这步触发全量 UpgradeState 清空 + 重启退避窗口

# 6. 验证
# GET /api/admin/nodes → 确认 agent_version 逐节点升级
# GET /api/admin/agent-binaries → 确认所有平台二进制已在列表中
```

### 2.3 回滚流程

```bash
# 1. 设置 Agent 版本回旧版
POST /api/admin/agent-version {"latest_version":"旧版本号"}

# 2. Manager 二进制回滚（如有需要）
# sudo systemctl stop ddns-manager
# cp ddns-manager.bak ddns-manager
# sudo systemctl start ddns-manager
```

## 3. 版本比较规则

### CompareSemVer (model.go)

```go
// 去除 v 前缀 → 按 . 分段 → 比较 3 段数字
// pre-release 后缀自动忽略 (1.5.10-beta1 → 1.5.10)
// 返回: -1 (a<b), 0 (a==b), 1 (a>b)
func CompareSemVer(a, b string) int
```

### Agent 端降级保护

```go
// selfUpgrade 中: 推送版本 ≤ 当前版本 → 拒绝降级
if model.CompareSemVer(update.Version, version) <= 0 {
    return errDowngradeBlocked
}
```

## 4. /bin/ 目录管理规范

### 4.1 文件命名

```
node-agent-v{M.m.p}-{os}-{arch}[.exe]
node-agent-v{M.m.p}-{os}-{arch}[.exe].sha256   (v1.5.36+ 自动生成)

示例:
  node-agent-v1.5.37-linux-amd64
  node-agent-v1.5.37-linux-amd64.sha256
  node-agent-v1.5.37-windows-amd64.exe
  node-agent-v1.5.37-windows-amd64.exe.sha256
```

### 4.2 清理策略

**Agent 端自动清理 (v1.6.51+):**
- 每次升级成功后，`replaceRunningBinary` 遍历安装目录，删除所有 `node-agent-v*` 非当前版本二进制
- 防误删机制：跳过目录 / 跳过当前版本 / 跳过 .sha256/.tmp/.linktmp / 只匹配 `node-agent-v` 前缀
- Linux: 清理所有 `node-agent-v*`（不含 .sha256/.tmp/.linktmp 后缀）
- Windows: 清理所有 `node-agent-v*.exe`
- ⚠️ v1.6.50→v1.6.51 过渡期：旧版 Agent 代码不含清理逻辑，首次升级后旧版残留需手动删除一次；v1.6.51→v1.6.52 及以后全自动

**管理端 bin/ 清理:**
- RebuildManifest 只保留每个平台**版本号最高**的二进制
- 旧版本二进制由运维手动或通过 API 删除
- `.sha256` 文件与对应二进制同生命期（SaveAgentBinary 写入，DeleteAgentBinary 删除）
- 禁止手动 SCP 二进制到 /bin/（应通过 Web UI 上传，确保 SHA256 文件生成）
- 禁止在 bin/ 存放非二进制文件（install.bat / install.sh / README / Manager 二进制等）

### 4.3 Manifest 重建

```
触发时机:
  - Manager 启动时 (main.go:st.RebuildManifest())
  - 上传二进制后 (SaveAgentBinary)
  - 删除二进制后 (DeleteAgentBinary)

内容格式 (agent_manifest.json):
  {
    "linux-amd64": "node-agent-v1.5.37-linux-amd64",
    "linux-arm": "node-agent-v1.5.37-linux-arm",
    "linux-arm64": "node-agent-v1.5.37-linux-arm64",
    "windows-amd64": "node-agent-v1.5.37-windows-amd64.exe"
  }
```

## 5. 常见陷阱与预防

### 陷阱 1: Manager 版本 ≠ Agent 版本

| 组件 | 版本变量 | 设置方式 |
|------|---------|---------|
| Manager | `main.version` (ldflags) | `VERSION` 文件 → build.sh → `-ldflags` |
| Agent | `main.version` (ldflags) | `VERSION` 文件 → build.sh → `-ldflags` |
| Installer | `main.version` (ldflags) | `INSTALLER_VERSION` 文件 → build.sh → `-ldflags` |

> ⚠️ Manager 和 Agent 共用同名 VERSION，但 Installer 独立版本号（v1.0.0 冻结）。

### 陷阱 2: /bin/ 目录未随 Manager 重启自动更新

- Manager 重启时 RebuildManifest 只扫描磁盘上已有的文件
- 新版本二进制必须在 Manager 重启前或通过 API 上传到 /bin/
- **禁止手动 scp 二进制 + 不重启 Manager**（manifest 不会自动更新）

### 陷阱 3: UpgradeState 未清空导致升级不推送

- 版本变更 (`agent_version` 从 v1.5.36 改为 v1.5.37) → UpgradeState 全量清空
- 同版本重设 (v1.5.37 → v1.5.37) → 仅清理已放弃节点 (RetryCount≥5)
- 退避窗口 10 分钟 → 避免推送风暴

### 陷阱 4: 符号链接在升级中丢失

- v1.5.37 前: `os.Remove(link) → os.Symlink` 两步非原子操作
- v1.5.37+: `os.Symlink(tmpLink) → os.Rename(tmpLink, link)` 原子替换
- 额外保护: `ensureSymlink()` 在 Agent 启动时自动检测并重建

### 陷阱 6: Agent 自动清理的过渡期 (v1.6.51)

- v1.6.51 的新清理代码仅在 v1.6.51 自身执行升级时才生效
- 从 v1.6.50→v1.6.51 的升级由 v1.6.50 代码执行 → 清理不触发 → 旧版残留需手动删除一次
- v1.6.51→v1.6.52 起全自动清理，无需手动干预
- 验证方法：升级后检查 Agent 目录，应仅存在当前版本 + symlink

### 陷阱 5: 只上传了部分平台的二进制

```
错误示范:
  /bin/ 中只有 node-agent-v1.5.37-linux-amd64
  → manifest 只有 linux-amd64 条目
  → Windows 节点收到升级推送时 manifest[windows-amd64] = "" → "二进制缺失"

正确做法:
  ⚠️ 每次发版必须全量上传 4 平台二进制到 /bin/
```

## 6. 部署验证检查表

```
[ ] Manager API /api/ping 返回正确版本号
[ ] /api/admin/agent-binaries 包含所有 4 平台的最新二进制
[ ] /api/admin/agent-version 返回目标版本号
[ ] /api/admin/nodes 显示节点正在升级（已推送/升级中）/已完成
[ ] 所有节点 agent_version 在 30 分钟内收敛到目标版本
[ ] 无节点长时间处于 DOWN 状态
[ ] events.log 中无 "二进制缺失" 警告
```

## 7. 历史教训

| 版本 | 问题 | 教训 |
|------|------|------|
| v1.5.33 | linux-amd64 二进制未上传 → 所有 Linux 节点升级失败 | 发版前全平台二进制必须到位 |
| v1.5.35→v1.5.36 | .30/.37 节点 symlink 丢失 → 离线 5 小时 | replaceRunningBinary 改为原子替换 |
| v1.5.36 | /bin/ 缺少 .sha256 文件 → 升级无完整性校验 | 禁止手动 scp，强制通过 API 上传 |
