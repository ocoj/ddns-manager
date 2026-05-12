# CHANGELOG

## v1.5.8 — 2026-05-12

### 🔐 安全加固 + 性能优化（7 项全量审计修复）

#### 安全
- **节点审批门控** — `NodeRecord.Approved` 字段，心跳处理前检查。未审批节点只更新状态，不推送配置/证书/升级，防止未授权节点获取 DNS Key 和证书
- **/api/ping 限流** — ping 端点独立 1000 req/min 限流，防止 HTTP flood 探测

#### 性能
- **心跳 JSON 内存缓存** — `ManagerStore` 添加 `nodesCache`/`dnsKeysCache`，首次加载后所有心跳读内存（零文件 I/O），写操作 write-through 同步更新缓存

#### 稳健性
- **download-installer ZIP 流式化** — `handleDownloadInstaller` 改用 `io.Copy` 直接流式写入 ZIP，不再全量缓冲二进制到内存（15MB → 0 额外内存）
- **DeleteDNSKey 原子化** — `DeleteDNSKeyAtomic` 持写锁读-删-写，消除并发删除覆盖风险
- **detectPlatform 默认值安全化** — 硬件信息未知时返回空字符串，调用方跳过升级推送
- **IIS 证书指纹提取稳健化** — 改用 `certutil -dump` 提取指纹（格式固定），替代 PowerShell `Write-Host` 字符串匹配
- **证书到期解析确定性修复** — `handleListCerts` 按文件名排序解析 PEM，修复 map 遍历随机导致到期时间偶发错误

#### 功能增强
- **Agent `-dir` flag** — Agent 支持 `-dir /custom/path` 覆盖默认安装目录，解决非标准路径安装时配置找不到的问题
- **ConfigError 回传** — `HeartbeatResp.ConfigError` 字段，配置渲染失败时 Agent 日志可见原因
- **DNS provider 名称校验** — `handleSaveDNSKey` 保存时校验 provider 名称，拒绝未知 DNS 提供商

### 🎨 Web UI 重做

#### 按钮系统
- **表外功能钮** — 34px 高 × ≤4中文82px/超出自适应，白底→悬停#87CEFA→按下#1677FF
- **表内操作钮** — 23px 高 × ≤2中文48px，同上配色
- **证书页「更多」下拉** — 显式详情+删除，下载/PFX/续订隐藏到下拉菜单
- **危险操作** — `.btn-danger` 保留红色系

#### 表格列宽标准化
- 所有表格 `table-layout:fixed` 固定列宽，不再随内容晃动
- 操作列统一 188px 左对齐
- DNS Keys: 名称/提供商/AccessKey 各 100px + AccessKey前6位+***脱敏
- 证书: 名称188px / 到期100px / 剩余90px
- ACME: Email188px / Key100px / 状态90px
- 系统日志: 时间130px / 节点90px / 分类80px
- 已上传二进制: 大小80px / 版本80px
- 节点版本: 节点120px / 状态70px / 当前/目标版本85px / 升级状态100px
- 超长内容 overflow:ellipsis + title 气泡

#### 编译
- **go.mod go 1.25.0** 保持与 ddns-go v6.17.0 依赖一致

#### 🧪 测试
- 新增 `TestNodeApproval_NewRegistrationDefault` — 审批默认值验证
- 新增 `TestDetectPlatform_NilHardware_ReturnsEmpty` — 空硬件边界条件
- 新增 `TestDNSProviderValidation` — DNS provider 名称校验

## v1.5.7 — 2026-05-11

### 🪟 Windows 部署流程重做：一键复制 → ZIP 下载

#### 运行时动态打包
- **`GET /api/admin/download-installer?ver=&os=`** — 服务端实时打包 ZIP，选什么版本就打什么包
  - 安装器用通用 `ddns-installer-windows-amd64.exe`（一个就够了）
  - 客户端按版本拉 `node-agent-v{VERSION}-windows-amd64.exe`
  - install.bat + README.txt 模板占位符运行时替换 + LF→CRLF 转换
- **不再需要预构建 ZIP** — 发新版只需上传 agent + installer 二进制，下载时自动打包

#### 安装向导增强（cmd/installer）
- **Step 0 环境检查**: 自动清理旧版 ddns-manager + ddns-go 冲突检测
  - ddns-go 检测覆盖：Windows 服务 + 程序目录 + 配置文件
  - 冲突时详细说明风险 → 用户确认清除，不同意则退出安装
- **Step 3 指纹预检**: 新增 `GET /api/nodes/{id}/fingerprint` 公开端点
  - 同指纹 → 旧机重装，自动继承配置
  - 不同指纹 → 新机抢名，要求改名
- **Agent 本地优先**: `findLocalAgent()` 扫描同目录 `node-agent*.exe`，不再要求固定名

#### WebUI 改进
- **部署按钮自适应**: Windows 选「下载安装包」→ 打包提示 → blob 下载
- **系统选择持久化**: `deployOs` 变量记住选择，5 秒刷新不丢失
- **网卡下拉始终可见**: 多网卡节点无论选什么获取方式都能看到网卡列表

#### 🐛 修复
- getDeployCmd() 多余 `}` 导致整页 JS 崩溃 → 登录按钮无响应
- install.bat 模板 `%%` 被 `fmt.Sprintf` 误解析 → 改用占位符 + `strings.ReplaceAll`
- installer 死找 `node-agent.exe` 文件名 → 改为扫描 `node-agent*.exe`

---

## v1.5.6 — 2026-05-11

### 🔴 关键 Bug 修复（6 项）

#### 自升级稳定性修复

- **B1 自升级 defer-in-loop 连接泄漏** — `selfUpgrade` 下载重试循环中用闭包包装每次尝试
- **B3 ELF OS/ABI 校验过严** — 接受 0x00/0x03/0x10 的合法 Linux 二进制
- **B4 daemon 模式首次心跳延迟 5 分钟** — `main()` 启动后立即 `go doHeartbeat()`

#### 部署命令修复

- **B2 install.sh 硬编码密码** — 移除 `/api/admin/agent-version` 认证请求
- **B5 installer fallback 名称过期** — 移除非 Go 标准架构名

#### 可观测性修复

- **B6 证书推送失败静默** — `LoadCertBundle` 失败时记录日志

### ⚡ 升级退避增强

- **失败计数 + 永久放弃** — `UpgJob.RetryCount`，推送 ≥5 次未完成 → 永久放弃 + error 日志
- **版本变更自动重置** — `handleSetAgentVersion` 版本变更全量清空退避
- **同版本重设恢复** — 同版本保存时清理已放弃节点（RetryCount≥5），已完成节点保留

### 🎨 Web UI 增强

- **饼图环壁收窄 50%** — `innerR` 0.55→0.78，移动端中心文字空间更大
- **全列表排序** — 仪表盘/节点/DNS/证书/ACME/版本页，点击表头排序，▲/▼ 指示器
- **排序状态保持** — 5 秒自动刷新不丢失排序，切页自动清除
- **侧边栏 + 登录页 logo 高清化** — 引用 128×128 `logo.png` 替代 32×32 `favicon.png`，Retina 显示清晰
- **PWA 图标升级** — `DDNS-Manager.png` 生成 192/512 高清图标，透明背景

### 🧪 测试

- `TestValidateAgentBinaryELFOSABI` — OS/ABI 合法性 (6 子测试)
- `TestSelfUpgradeNoDeferInLoop` — 闭包包装验证
- `TestDaemonModeImmediateHeartbeat` — 首次心跳验证

### 📊 部署

| 服务器 | 版本 | 状态 |
|--------|------|------|
| Manager (10.0.0.1) | v1.5.6 | 🟢 |
| client-a (10.0.0.2) | v1.5.6 | 🟢 DDNS=OK |
| client-b (10.0.0.3) | v1.5.6 | 🟢 DDNS=OK |

---

## v1.5.5 — 2026-05-10/11
- **B4 daemon 模式首次心跳延迟 5 分钟** — `main()` 中 daemon 启动后立即 `go doHeartbeat()`，不等首个 ticker tick，确保 DNS 更新无空窗

#### 部署命令修复

- **B2 install.sh 硬编码密码** — 移除对 `/api/admin/agent-version` 的认证请求（密码已改后必然 401），改为按优先级逐个尝试版本化下载名
- **B5 installer fallback 名称过期** — Go 安装器备选名不再尝试 `node-agent-v2`/`node-agent-linux-x86_64` 等已废弃名称，仅使用 Go 标准架构名

#### 可观测性修复

- **B6 证书推送失败静默** — `handleHeartbeat` 中 `LoadCertBundle` 失败时记录日志（bundle 名 + 错误原因），不再沉默跳过

### 🧪 新增测试

- `TestValidateAgentBinaryELFOSABI` — 验证 ELF OS/ABI 合法性 (0x00/0x03/0x10 接受, 0x09 拒绝, ET_DYN 接受, ARM64 架构匹配)
- `TestSelfUpgradeNoDeferInLoop` — 验证 selfUpgrade 下载循环使用闭包包装
- `TestDaemonModeImmediateHeartbeat` — 验证 daemon 模式启动时立即执行首次心跳

### 📊 部署验证

| 服务器 | 版本 | 状态 |
|--------|------|------|
| Manager (10.0.0.1) | v1.5.6 | 🟢 在线 |
| client-a (10.0.0.2) | v1.5.6 | 🟢 DDNS=OK |
| client-b (10.0.0.3) | → v1.5.6 | 🔄 下次心跳自动升级 |

---

## v1.5.5 — 2026-05-10/11

### 📱 移动端响应式适配

- **侧边栏抽屉化** — 移动端侧边栏改为 fixed 抽屉 (260px)，左滑入 + 半透明遮罩，点遮罩/菜单项关闭
- **汉堡菜单** — Topbar 新增 ☰ 按钮，仅 `≤768px` 显示，桌面端 `display:none` 不受影响
- **表格横滚** — 所有 `<table>` 移动端 `display:block;overflow-x:auto`，无需改 JS
- **统计卡片自适应** — `grid-template-columns:repeat(auto-fit,minmax(140px,1fr))` 自动换行
- **表单折叠** — `form-inline` 加 `flex-wrap:wrap`，`form-group` 移动端满宽
- **触控优化** — `@media(pointer:coarse)` 按钮最小 44px，只在触摸设备生效
- **弹窗适配** — 移动端 `max-width:94vw;padding:16px` 留呼吸空间
- **图表 legend 溢出修复** — canvas 高度从 CSS `!important` 100% 改为 JS 固定 180px，容器 `min-height` 自然扩展

**桌面端影响: NONE** — 所有改动在 `@media(max-width:768px)` 内，桌面像素级不变。

### 🛠️ 部署命令修复 + 客户端质量

- **B1 部署命令版本化命名** — Linux 已装节点升级命令改为下载到版本化文件名 + `ln -sf` 更新符号链接，不再直接覆盖 `node-agent`
- **B2 Windows 部署命令服务等待** — 固定 `Start-Sleep 3` 改为 `sc query` 轮询（最多 30s），与自动升级修复一致
- **B3 Linux 部署命令边界守卫** — `systemctl start` 前加 `&&`，确保下载失败时不会启动损坏的二进制
- **B4 hostname 加引号** — 安装器调用 `"$(hostname)"` 防止含空格主机名被拆词

### ⚡ 升级稳定性增强

- **E1 升级退避** — Manager 侧追踪每节点推送时间，30 分钟内同版本不重复推送 AgentUpdate（防止 864次/天无效下载）
- **E2 批量升级倒计时** — WebUI 等待状态显示剩余秒数 `~287s`，让用户知道还要等多久
- **E3 服务端升级状态** — `UpgradeState` 持久化到 `agent_config.json`，新增 `GET /api/admin/agent-upgrade-state` API，替代浏览器 localStorage

### 🛡️ 防御性编程

- **Q1 Agent 日志时间戳** — `main()` 添加 `log.SetFlags(log.LstdFlags)`
- **Q2 rand.Read 错误处理** — `generatePassword()` 失败时 `log.Fatal` 而非静默
- **Q3 HTTP Client 超时保护** — `newHTTPClient()` timeout=0 自动补为 30s
- **Q4 Walk 深度限制** — `collectCertHashes` 最多扫描 5 层子目录，防止 CertPath 误配导致全系统遍历

### 🧪 测试

- 新增 `TestUpgradeBackoffWithin30Minutes` — 验证退避逻辑 (30分钟阈值)
- 新增 `TestCollectCertHashesDepthLimit` — 验证 Walk 深度限制
- 新增 `TestUpgradeStateCompletionTracking` — 验证完成标记持久化

## v1.5.4 — 2026-05-10

### 🔐 证书 PFX 下载 + IIS 绑定完善

- **PFX 下载端点** — `GET /api/admin/certs/{name}/pfx?password=***`，一次性密码，用于 Windows certlm.msc 手动导入
- **WebUI PFX 按钮** — 证书列表每行新增 PFX 下载按钮，弹窗设密码，自动下载
- **修复取消误报** — 点击取消不弹"密码至少 6 位"错误

## v1.5.3 — 2026-05-10

### 🔐 证书自动更新 + IIS 绑定 (彻底重写)

- **Manager 端 Go 原生 PFX 生成** — 集成 `go-pkcs12`，ACME 签发/手动上传时自动生成 `cert.pfx`，Windows 节点无需 openssl
- **Windows IIS 绑定零依赖** — Agent 走 `importPFXToIIS` 快速路径 (PowerShell 直导)，`importToIIS` 降级为仅旧 bundle 兼容
- **PFX 文件查找修复** — 用实际 bundle 文件名而非 `BundleName+.pfx` 拼接
- **证书部署后服务重载** — Agent 处理 `ReloadServices`，Linux `systemctl reload/restart`，Windows `sc stop/start`
- **IIS 应用池自动回收** — 证书绑定后 `appcmd recycle apppool` (精确) → `iisreset` (兜底)
- **解密失败日志** — 静默 `continue` 改为 `log.Printf("[cert] 解密失败 %s: %v", name, err)`

### 🔴 自升级关键修复

- **Linux 自升级后 DNS 中断 5 分钟** — 新增 `restartAgentAfterUpgrade()`，升级后立即触发 systemd heartbeat，消除 oneshot 模式下的 DNS 更新空窗期
- **版本化文件名 .new 后缀污染** — `replaceRunningBinary` 重写命名逻辑，用 `runtime.GOOS/runtime.GOARCH` 直接构建文件名，不再解析旧文件名（旧名含 git describe 多段版本会拆错）
- **自升级下载无重试** — `selfUpgrade` 添加 3 次重试 + 递增退避 (2s/4s/6s)，防止网络抖动导致 5 分钟等待
- **配置缓存加密失败明文回退** — 移除 `ddns_cache.yaml` 的明文 fallback，加密失败时拒绝写入，下次心跳重试

### 🟠 安全加固

- **心跳请求体无大小限制** — `handleHeartbeat` + `handleSaveNodeConfig` 添加 `MaxBytesReader(1MB)`，防止 OOM
- **DNS Key 配置无校验** — `handleSaveNodeConfig` 校验 DNSKeyName 存在性，防止保存不存在的 key 导致渲染失败

### 🛠️ 构建与部署

- **版本号优先级修正** — `build.sh` 改为 **VERSION 文件 > git describe**，移除 `--dirty`，文件名永为干净语义化版本 `node-agent-v{M.m.p}-{os}-{arch}`
- **VERSION 文件升级** — v1.5.2 → v1.5.3
- **install.sh 架构检测补全** — 新增 armv6l/armv8l/i686 检测，未知架构警告而非退出
- **install.sh 移除无效 fallback** — 管理端 `/bin/` 不提供目录列表，删掉无效的 grep 抓取

### 🪟 Windows 自升级稳健性

- **升级批处理等待逻辑** — 从固定 5 秒 sleep 改为轮询 `sc query` + 30s 超时强制 `taskkill`
- **签名兼容** — `replaceRunningBinary` 统一 3 参数签名 (curExe, newExe, version)

### 🧪 测试

- 新增 `TestReplaceRunningBinaryVersionedNaming` — 验证版本化文件名不含 .new
- 新增 `TestHeartbeatBodySizeLimit` — 验证 2MB 请求被拒绝
- 新增 `TestConfigEncryptionNoPlaintextFallback` — 验证加密失败不写明文

## v1.5.2-audit — 2026-05-10

### 🔴 关键修复 (3 项阻断级)

- **架构命名统一** / **修改密码字段不匹配** / **强制版本字段不匹配**

### 🟠 高危修复 (4 项)

- **页面隔离状态管理器** — 全局方案解决 Web UI 输入框/复选框/下拉框的 5 秒刷新丢失和切页脏数据残留
- **SMTP 通知复选框** / **DNS Key 选择器预选失效** / **设计文档架构名不一致**

### 🟡 中等修复 (4 项) / 📝 日志全面中文化 / 🚀 部署验证

### ✨ Web UI 增强

- **仪表盘 4 看板** — 新增「健康」统计 (DDNS=OK)，排列: 总数/在线/健康/离线
- **节点列表域名列** — 显示配置的 IPv4/IPv6 域名，多域名省略+title 完整展示，列宽合理分配
- **SMTP 智能匹配** — 发件人输入邮箱自动匹配 SMTP 服务器/端口 (13 种邮箱域)
- **SMTP 字段重排** — "用户名"→"发件人"，服务器改为下拉可选+自定义
- **管理端域名字段** — 邮件中可点击链接，留空显示服务器地址
- **邮件模板优化** — 移除高危/警告关键词，格式正式，含管理端链接
- **流量曲线持久化** — `access_buckets.json` 48h环形记录，60s flush，启动恢复，连续时间线0补全
- **时间范围选择器** — 总请求+Top5 IP 曲线支持 60m/2h/5h/24h/48h 切换
- **侧边栏 SVG 图标替换** — 6个菜单图标升级 (仪表盘/节点/DNS/版本/日志/设置)
- **弹窗保护** — 弹窗打开时暂停5秒自动刷新
- **input 事件恢复** — 刷新后手动 dispatchEvent 触发 oninput 绑定
- **证书颁发组织修正** — Issuer 优先 Organization 而非 CommonName
- **CPU 饼图 0% 可绘制** — 去掉 >0 门控
- **PMTP 错误提示优化** — 535 认证失败提示授权码说明

### 🏗️ 架构改进

- **版本管理自动化** — Manager ldflags 注入版本号+`-version` flag；Agent 安装用版本化文件名+符号链接；VERSION 文件后备；git tag 优先；manifest key 统一 `amd64`
- **SMTP 保存/限流日志补全** — handleSaveSMTP/handleSaveRateLimit 加审计日志
- **节点页增加健康列+IP列** — 7→8列布局

## v1.5.2 — 2026-05-10

### 🔒 安全加固 (全量审计 18 项)

- **并发安全** — `DeleteNode` / `PutACMEAccount` / `DeleteACMEAccount` 原子化，消除 TOCTOU 竞态
- **密钥派生升级** — `DeriveKey` 从单次 SHA256 → HKDF-SHA256 (RFC 5869)，加 `purpose` 参数实现域分离（`"cert-transport"` / `"config-cache"`）
- **配置缓存加密** — Agent 端 `ddns_cache.yaml` AES-256-GCM 加密，防止 DNS 凭证明文泄露
- **路径穿隧修复** — `configCachePath` 固定使用 `agentBaseDir`，不再从 `CertPath` 派生
- **升级脚本注入防护** — Windows `replaceRunningBinary` 拒绝含 `&|<>^%` 等元字符的路径
- **写入错误检查** — `sendHeartbeat` / `selfUpgrade` 增加 `io.LimitReader` 和错误处理
- **日志性能优化** — `statusIconMap` 提升为包级常量，消除每次日志事件分配
- **上传大小限制统一** — `MultipartForm` 与 `MaxBytesReader` 使用一致限制
- **DNS 超时保护** — `runDNSUpdateWithTimeout` 包装 2 分钟总超时，防止 DNS API 降级阻塞整个心跳周期

### 🧪 测试

- 新增 `TestDeleteNode` ×3 / `TestPutACMEAccount` ×2 / `TestDeleteACMEAccount` ×2（并发+边界）
- `TestDeriveKey` 新增域分离断言

## v1.5.1 — 2026-05-09

### 💥 不向下兼容变更

- **密钥派生加分隔符** — `DeriveKey` 改用 `sha256(password + "\x00" + fingerprint)` 消除输入边界碰撞风险。⚠️ 所有已部署的加密证书需重新签发
- **Hash 格式统一** — `ConfigHash` 和 `renderDDNSConfig` 均加 `sha256:` 前缀，与证书 hash 格式一致。Manager + Agent 需同步更新

### 代码重构

- **Refactor: Provider 注册表** — `newProvider()` 28 分支 switch → `providerRegistry` map + 工厂函数，`TestProviderRegistryCompleteness` 自动检测缺失/多余
- **Refactor: server.go 拆分** — 1824 行单文件 → 7 文件（最大 464 行），按职责拆分：server/middleware/access_stats/handlers_nodes/handlers_certs/handlers_admin/json_helpers

### Bug 修复

- **Bug: build.sh 缺少 Windows installer 构建** — `build_installer_win` 定义了但从未调用，补回 `build_installer_win amd64`
- **Bug: SaveCertBundle 序列化错误静默忽略** — `json.Marshal`/`json.Unmarshal` 错误现在正确返回
- **Bug: 密码长度用字节数非字符数** — `handleChangePassword` 改用 `utf8.RuneCountInString` 正确计算字符数
- **Perf: 心跳重复 PutNode** — 合并双 `PutNode` 为一次写入，减少心跳 I/O
- **Perf: reloadFromDisk 全量读取** — 日志文件 >2MB 时改用尾部 2MB 读取，避免 50MB+ 全量加载
- **Quality: jsonOK/jsonErr** — 编码错误现在记录日志
- **Quality: fileSHA256** — 读取错误现在记录日志
- **Quality: collectCertHashes** — Walk 遍历错误现在记录日志
- **Quality: ACME 临时文件** — 添加 kill -9 残留风险注释（/tmp tmpfs 缓解）

## v1.5.0 — 2026-05-09

### DNS Key 多账号

- **DNS Key 名称+供应商** — 同一供应商可建多个 Key（如「DNSPod-个人」「DNSPod-公司」），名称自定义
- **向后兼容** — 旧 `dns_keys.json` 自动填充 Name/Provider
- **节点配置** — DNS Key 下拉显示「名称 (供应商)」，存储 `dns_key_name`
- **ACME DNS-01** — 通过 Key 名称查找，读取 Provider 传给 acme.sh

### ACME 证书管理增强

- **UI: 续订按钮** — ACME 证书提供人工强制续签，调用 `POST /api/admin/certs/{name}/renew`
- **UI: 过程日志** — ACME 申请弹窗显示 acme.sh 完整输出，不再黑箱
- **UI: 证书详情** — 弹窗显示 CN/颁发者/有效期/SAN/申请方式/DNS账号/ACME账号
- **Fix: dnspod→dns_tencent** — DNSPod 映射改用腾讯云 API（兼容 AKID 格式）
- **Fix: 申请后清理** — `SaveCertBundle` 后 `os.RemoveAll` 原域名目录，防重复证书

### 版本管理增强

- **UI: 一键部署** — 版本+系统下拉选择，生成智能命令（检测升级/全新安装），Linux/Windows 双平台
- **Fix: 升级状态持久化** — `sessionStorage`→`localStorage`，关闭浏览器后仍保留
- **Fix: Windows 升级** — 批处理脚本加 `sc stop node-agent` 防止文件锁定
- **Fix: 升级状态实时对比** — 比对节点当前版本 vs 触发版本，10→30 分钟超时

### Web UI 增强

- **仪表盘系统资源饼图** — CPU/内存/磁盘环形饼图，管理端自身资源（30s 缓存 API）
- **PWA 支持** — `manifest.json`/`apple-touch-icon`/`theme-color`，可安装为桌面应用
- **证书上传** — DNS & 证书页新增上传按钮+模态框，自动解析到期时间
- **DNS Key 编辑** — 编辑时名称和供应商锁定，只允许改 Key ID/Secret

### 系统资源监控

- **internal/sysinfo** — 跨平台 CPU/内存/磁盘采集
- **StartSysInfoCollector()** — 30s 后台采样，API 即时返回缓存
- **GET /api/admin/system-info** — 管理端资源 API
- **Model: HardwareInfo 扩展** — `cpu_percent`/`memory_*`/`disk_*`

### Bug 修复

- **Bug: handleHeartbeat nil 空指针** — `h == nil` 时局部变量未更新导致 `h.Status` panic
- **Bug: SaveCertBundle 覆盖 ACME 元数据** — 写 meta.json 时合并已有 `acme`/`email`/`ca`/`key_type` 字段
- **Bug: handleChallenge 并发 map 读写** — 新增 `challengeMu sync.RWMutex` 独立锁
- **Bug: Renew() 数据竞争** — 开头 Lock 拷贝 `email`/`acmeShPath`/`renewBefore` 到局部变量
- **Bug: rateLimiter 内存泄漏** — 5 分钟后台 goroutine 清理过期 IP bucket
- **Bug: handleListCerts 证书到期不显示** — `fullchain.pem` 硬编码文件名 → 遍历所有 .pem/.crt 查找
- **Bug: renderDNS certData.certs 无数据** — API 返回数组但前端读 `certData.certs` → `Array.isArray()`
- **Bug: 证书 expiry 字段名不匹配** — 前端 `c.expires` → `c.expiry`
- **Bug: installer Windows cleanup** — `net stop` → `sc stop`，修复清理路径
- **Bug: agent 死代码** — 删除未调用的 `saveConfigTemplate()`
- **Bug: agent AgentConfig 重复** — 改为嵌入 `model.AgentConfig` + `yaml:",inline"`
- **Bug: hash 截断** — `b.Hash[:16]` 含 `sha256:` 前缀 → `strings.TrimPrefix` 后截断

- **Bug: 心跳/节点请求不计入访问统计** — `accessCollector.record` 加入 `rateLimitMiddleware`
- **Bug: 自助复制粘贴 Chromium 不兼容** — `navigator.clipboard` + `execCommand` 双回退
- **Bug: 自动刷新 Toast 刷屏** — `apiJSON` 支持 `{silent:true}` 抑制静默错误提示

### 构建脚本

- **Fix: build.sh** — `build_linux`/`build_installer` 中 `${goarm:+}` 疑难展开改用 if/else
- **Version: 文件名版本号** — 每个平台产出 2 个文件（版本号版 + latest 版），manifest 改为 `platform→filename(versioned)`

## v1.4.0 — 2026-05-08

### ACME 多账号各自续签

- **Functional: 证书归属标记** — `issueCert`/`issueViaAcmeSh` 写入 `meta.json` 增加 `email` 字段，标记证书由哪个 ACME 账号签发
- **Functional: Renew() email 过滤** — 续签时按 meta.json 中的 email 匹配当前 Manager 账号，只续签自己签发的证书
- **Functional: StartAutoRenew()** — `server.go` 新增方法，24h ticker 串行遍历所有 `acmeMgrs` 各自续签，替代 main.go 中仅覆盖第一个账号的旧逻辑
- **Functional: 用户上传证书保护** — `Renew()` 第一关跳过非 `acme:true` 的证书，用户上传的证书永不自动续签
- **Functional: 旧证书兜底** — 无 `email` 字段的旧证书由第一个扫描到的 Manager 负责续签

### DNS Key 使用追踪

- **Functional: TrackDNSKeyUsage** — `store.go` 新增方法，保存节点配置时自动记录 DNS Key 被哪些节点使用
- **Functional: RemoveNodeFromDNSKeys** — `store.go` 新增方法，删除节点时清理所有 DNS Key 引用

### Bug 修复

- **Bug: notify.go TCP 连接泄漏** — `sendSTARTTLS` 增加 `defer conn.Close()`，修复 SMTP 客户端创建失败时 TCP 连接永不释放
- **Bug: server.go detectPlatform 架构缺失** — 补充 `i386` 和 `arm` 架构映射，匹配 installer 中的二进制命名
- **Bug: acme.go 死代码** — 移除 `issueViaAcmeSh` 中构造后从未使用的 `exec.CommandContext`
- **Bug: agent/main.go 错误注释** — 删除引用不存在函数 `saveConfig` 的误导注释

### 性能优化

- **Perf: heartbeat 加密密钥** — `DeriveKey` 从 cert bindings 循环内提到循环外，避免重复派生同一密钥

### 文档更新

- **DESIGN-v2.md §12.3 重写** — 多账号各自续签的功能要求、实现方式、核心代码示例、判定流程图

## v1.3.0 — 2026-05-08

### 代码质量与 Bug 修复

- **Critical: 磁盘空间保护逻辑修复** — `EnsureDiskSpace` 条件从 `usage>10` 改为 `usage>=90`，磁盘使用率≥90%时才开始清理
- **Critical: 证书 hash 一致性问题** — Store/Server 统一使用排序文件名+sha256 确定性算法，添加 `sha256:` 前缀
- **Critical: Agent 证书 hash 上报** — `doHeartbeat` 新增 `collectCertHashes`，解决每次都全量重发证书的问题
- **Critical: bcrypt 错误处理** — `handleRegister`/`handleChangePassword` 不再忽略 bcrypt 错误
- **Critical: Linux 自升级跨文件系统修复** — `replaceRunningBinary` 改用 `io.Copy→tmp→rename` 代替 `os.Rename`
- **Functional: acme DNS-01 路径修复** — 不支持 DNS provider 时返回明确错误，DNS API 映射提取为包级变量
- **Functional: serviceExists Linux 修复** — 从 `systemctl -q` 改为检查 unit 文件是否存在
- **Functional: LoadCertBundle 吞错修复** — 显式检查 ReadDir/ReadFile 错误
- **Functional: 版本号提取完善** — 正则加 `v?`，优先查 manifest
- **Design: AgentConfig 去重** — 提取到 model 共享定义，installer 用类型别名
- **Quality: HTTP Transport 修复** — `newHTTPClient()` 克隆 DefaultTransport 保持 HTTP/2+连接池
- **Quality: go.mod 依赖标注修复**

### 文档重写

- **DESIGN-v2.md 完全重写** — 对齐所有代码实现，删除注释错误、虚构文件和过时设计
- **Web UI 内容移除** — DESIGN-v2.md 不再包含前端内容（参考 docs/WEBUI-DESIGN.md）
- **model.go 注释完善** — v1 兼容字段添加标注

## v1.2.1 — 2026-05-06

### 新功能：交互式安装向导

- **交互式向导** — `-install` 不加参数时逐步提示管理端地址、节点名、安装目录
- **安装目录可配** — `-dir` 参数（默认 `C:\ddns` / `/opt/ddns-manager`）
- **环境检查** — 端口冲突检测 + 旧 ddns-go 清理
- **Agent 自复制** — 安装时复制到安装目录，防删源文件后服务挂
- **Go 原生 zip** — 替代 `unzip` 命令，Windows 零额外依赖

### 新功能：DDNS 健康监控

- **服务状态检测** — 每心跳检查 ddns-go 是否真正在运行
- **日志错误扫描** — 读取 ddns-go 日志，检测 MissingAccessKeyId 等 8 种故障模式
- **日志新鲜度** — 超过 30 分钟未更新 → 上报故障
- **仪表盘健康列** — OK(绿) / ERR(黄,悬停看详情) / DOWN(红) / -(灰)

### 新功能：管理端 WebUI 改进

- **证书下拉选择** — 节点分配时从已上传证书列表下拉，不再手打
- **DNS 下拉仅显示已配密钥** — 只列有密钥的提供商，不是全部 12 个

### 修复：Windows 服务

- **Windows SVC handler** — 使用 `golang.org/x/sys/windows/svc` 标准服务集成
- **`sc start`/`sc stop`** 正常工作，`sc query` 正确显示 RUNNING
- **`sc failure restart/5000`** — 退出后 5 秒自动重启，支持自升级
- **ddns-go 配置文件路径** — 服务命令添加 `-c` 指定正确路径
- **TTL 默认 300** — 日志 5 分钟更新一次，确保健康检测可靠

### 修复：安装向导

- **每步返回结果校验** — 下载/解压/注册/服务启动全部检查返回值
- **下载失败自动重试 3 次** — 递增退避
- **服务启动重试 3 次** — 含 RUNNING 状态验证
- **重名节点智能处理** — 同服务器(指纹匹配)→跳过注册，不同服务器→提示改名
- **stepWait 进度条** — 逐步显示 [1/5]~[5/5]，自动过渡
- **ASCII 安全** — 所有 emoji 替换为 [OK]/[FAIL]/[!] 兼容 PowerShell
- **chcp 65001** — Windows 控制台 UTF-8 编码

### 修复：管理端

- **证书 hash 匹配** — deployPath + 全 hash 遍历，防止每次心跳重发
- **PE 二进制上传** — 管理端可上传 Windows agent
- **节点认证日志** — 失败日志标注正确 nodeID
- **差异化速率限制** — 全局 300/min，登录/注册 10/min
- **优雅关闭** — SIGTERM → http.Server.Shutdown(15s)
- **ACME 可控退出** — Ticker + channel

### 文档

- **DESIGN.md 重写** — 400 行，含数据流图、边界条件、不可改原因、交互流程
- **API 路由表补全** — SMTP、日志文件列表等

## v1.2.0 — 2026-05-06

### 邮件通知系统

- SMTP 配置、测试发送、证书到期告警、高危事件通知
- Dashboard 告警栏、差异化速率限制

## v1.1.0 — 2026-05-06

### Windows 客户端合规

- 内置 daemon、统一目录、无痕卸载、VERSIONINFO、自动信任、代码签名预留

## v0.1.0 — 2026-05-02

### 首次发布
