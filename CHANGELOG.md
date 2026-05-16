# CHANGELOG

## v1.6.27 — 2026-05-16 夜间

### 暗色模式 + DNS Key测试修复
- 设置页新增"外观"卡片: 自动/明亮/暗色三种切换
- CSS变量覆盖: body.dark + prefers-color-scheme媒体查询
- 暗色输入框/按钮反色处理
- DNS Key测试增加AddUpdateDomainRecords触发真实API验证

## v1.6.26 — 2026-05-16 下午

### 移动端全页面卡片布局适配
- 日志页: 表格→flex卡片, 筛选折叠, 日期+节点+内容全宽
- 版本管理: 节点/二进制表→flex卡片, 隐藏次要列
- DNS&证书: 三表→flex卡片, 操作按钮右对齐
- 节点页: flex三行卡片, 系统/指纹隐藏
- 仪表盘: 节点表+事件列表→flex卡片, 独立卡片分隔
- 最近事件max-height移除, 全展开

## v1.6.25 — 2026-05-16

### Agent日志时区统一
- DNS日志时间统一UTC+UTC后缀
- 前端normalizeEvents保留ISO格式供fmtTime转换

## v1.6.19-v1.6.24 — 2026-05-16

### Web UI刷新机制重写 + 时区修复
- 全页5s刷新→仅数据静默更新, 自动/手动切换
- 日志页增量prepend, 最新在顶
- 时区转换修复: normalizeEvents+fmtTime双重转换问题
- certutil错误日志消除GBK乱码
- IIS扫描条件: 证书目录有内容才扫描
- GetType修复: normalizeGetType支持netinterface→netInterface

## v1.6.18 — 2026-05-16

### certutil错误日志消除中文GBK乱码
- certutil在中文Windows输出GBK编码, 直接log出现乱码
- certutilErrorCode() 提取hex错误码(0x80070056)替代原始输出

## v1.6.17 — 2026-05-16

### IIS扫描条件修正 — 证书已部署为准
- v1.6.16用cfg.IISCertBindings判断, 与Manager侧cert_bindings语义不同
- 改为os.ReadDir(cfg.CertPath) — 证书目录有内容才扫描

## v1.6.16 — 2026-05-16

### IIS扫描/证书收集按配置对齐
- scanIISBindingsIfNeeded / collectCertHashesIfNeeded
- Win10(无证书): 跳过PowerShell调用, 无IIS日志

## v1.6.15 — 2026-05-16

### C7: 回滚 netsh 文本解析, 恢复 WebAdministration API
- **教训**: v1.6.14 的 netsh 文本解析重蹈 v1.6.1-1.6.5 覆辙
- SYSTEM locale 输出中文标签 (IP:端口/证书哈希), 英文正则失效
- 恢复 v1.6.7 的 WebAdministration PowerShell API + 优雅降级
- 新增 `docs/windows-dev-notes.md` — Windows 静默执行开发规范

## v1.6.x — 2026-05-15

### 🔴 第十次审计修复：证书部署全链路重构

借鉴 win-acme 成熟设计，重构 Windows 证书部署流程。核心突破：WebAdministration
PowerShell API 替代 netsh 文本解析，彻底解决 SYSTEM 权限和中文 locale 问题。

#### v1.6.10 — 第十一次审计修复：全量代码审计 (2026-05-16)
- **C1**: dns_updater.go — 多段DnsConf 时状态赋值移到循环外，防止中间状态覆盖
- **C2**: handlers_nodes.go — DDNS健康判定增加 `!Running+LastOK` 分支，不误标 DOWN
- **C4**: upgrade_windows.go — 批处理回退后显式 goto，消除隐式 fallthrough
- **H1**: dns_updater.go — 多段错误独立记录为 LastErrorDetail，循环外拼接
- **H2**: main.go — DNS 日志恢复时写入正确缓冲区 (dnsUpdater.logBuf)
- **H3**: upgrade_linux.go — 旧版二进制删除失败记录日志，防止静默堆积
- **H4**: dns_updater.go — DNS 更新结果持久化到 agent_events.log (crash-safe)
- **H5**: handlers_admin.go — testDNSKeyOnline 增加 ctx 监听，防止 goroutine 泄漏
- **H6**: server.go — 心跳检测器增加 diff/time 日志，便于时区一致性验证
- **M1**: dns_updater.go — DNS 操作日志补全到 agent_events.log
- **M2**: handlers_nodes.go — 证书 hash 匹配改为值遍历兜底，不依赖 key 名称
- **M3**: main.go — 心跳失败时恢复已 drain 日志，避免重试循环丢失
- **M4**: handlers_nodes.go — Completed 标记增加防误判，推送后等真实升级再标记
- **M6**: main.go/svc_windows.go — ensureSymlink 行为注释明确 (Windows no-op)
- **L1**: main.go — agentEventsFile 写文件改为持锁读指针后解锁写，防阻塞
- **L2**: upgrade_linux.go — 版本号提取失败时用时间戳兜底
- **L3**: store.go — nodesCache/dnsKeysCache 独立 loaded 标志，消除并发竞态
- **L4**: VERSION 1.6.9→1.6.10, CHANGELOG 补全

#### v1.6.9 — 漏写版本 (VERSION 与 CHANGELOG 不一致时产生)

#### v1.6.8 — IPAddress 序列化修复
- **bug**: PowerShell `ConvertTo-Json` 将 `$_.IPAddress` 序列化为嵌套对象
  `{"Address":0,"AddressFamily":2,...}` 而非字符串 "0.0.0.0"
- **fix**: `[string]$_.IPAddress` 强制转换为字符串
- **结果**: Win2022 IIS 扫描成功 → 1个SSL绑定 0.0.0.0:443 thumb=2f0823ab...

#### v1.6.7 — WebAdministration API 替代 netsh
- **突破**: 用 `Get-ChildItem IIS:\SSLBindings` 替代 netsh 文本解析
- JSON 输出直接 `json.Unmarshal` → 中英文通吃, 不依赖 chcp
- 处理单对象/数组 JSON 兼容 (`{...}` vs `[{...}]`)

#### v1.6.6 — PowerShell 调用 + 中英文标签匹配
- netsh 在 SYSTEM 下必须通过 `chcp 437 >nul &&` 前缀调用
- `cutAnyPrefix()` 同时匹配中英文标签 (IP:port / IP:端口)

#### v1.6.5 — 根因定位：SYSTEM locale 中文输出
- raw dump 发现 SYSTEM 下 netsh 输出中文标签(IP:端口/证书哈希)
- 解析代码只匹配英文 → 0个SSL绑定

#### v1.6.4 — siteMap 修复（PowerShell appcmd）
- `appcmd list sites` 也需通过 PowerShell 调用
- siteMap 从 0 恢复到 2 个站点

#### v1.6.3 — PowerShell 包装 netsh/appcmd
- Go 直接 `exec.Command("netsh")` 在 SYSTEM 下失败 → 改用 `exec.Command("powershell", "-Command", "netsh ...")`

#### v1.6.1-6.2 — IIS 扫描尝试验证
- v1.6.1: `scanIISBindings` 初次部署 → 0个SSL绑定
- v1.6.2: 全路径 `C:\Windows\System32\netsh.exe` → 仍0绑定

#### v1.6.0 — 核心重构

##### 🟢 win-acme 设计借鉴
- **fitsBinding()**: 三级 hostname 匹配 (精确=100 / 泛域名=50 / 默认=10)
- **证书按 BundleName 分子目录**: `CertPath/{BundleName}/cert.pfx` 多站点不覆盖
- **collectCertHashes 磁盘扫描**: 无 .cert_hash 文件也能从磁盘文件计算 hash 上报
- **IIS 绑定快照**: `iis_bound_sites` 字段上报到 Manager
- **强制推送 API**: `POST /api/admin/certs/{name}/push/{id}` 用于测试验证

##### 🧪 测试方法
- `docs/cert-deploy-test.md` — 6 项测试用例 (强制推送/IIS快照/Fits匹配/多站点/重复推送/密码兜底)

##### 📄 版本推进规范
- `docs/VERSIONING.md` — 发版流程、/bin/管理、历史教训

#### 🧪 部署状态
- Manager (10.0.0.1): v1.6.0 ✅
- Win2022 (10.0.0.3): v1.6.8 ✅ IIS扫描1个SSL绑定
- sp.example.com: v1.5.41 → 待心跳升级

---

## v1.5.37 — 2026-05-15

### 🔴 根治修复：符号链接原子替换 + 自愈 + 版本推进规范

基于 v1.5.36 部署后 .30/.37 两个节点因 symlink 丢失离线 5 小时的根因分析。

#### 🔴 根因修复（3 项）

- **replaceRunningBinary 符号链接原子替换** — `os.Remove(link)` → `os.Symlink(tmpLink)` →
  `os.Rename(tmpLink, link)` 三步原子化。`os.Rename` 在同一文件系统内是原子的，
  避免了 Remove→Symlink 窗口期中 symlink 裸奔导致永久离线的链式故障。
- **restartAgentAfterUpgrade 增加 3 次重试 + 错误日志** — v1.5.34→v1.5.36 升级时
  systemctl start 静默失败（无日志、无重试），导致新进程未启动、旧进程已退出。
  修复：3 次重试间隔 2s，每次失败写 `log.Printf`，最终失败依赖 timer 自动恢复。
- **ensureSymlink 启动时符号链接自愈** — Agent 启动时检测 `node-agent` 符号链接是否存在，
  丢失则扫描安装目录中版本号最高的 `node-agent-v*-{os}-{arch}` 二进制自动重建。

#### 📄 版本推进开发规范

- **docs/VERSIONING.md** — 建立完整的版本推进开发规范（发版检查清单、操作序列、/bin/ 管理、
  历史教训），防止版本推进跑偏。

#### 🧪 部署状态
- Manager (10.0.0.1): v1.5.37 ✅
- All Agent nodes: v1.5.36 → 心跳自动升级到 v1.5.37 (已推送+含SHA256)

---

## v1.5.36 — 2026-05-15

### 🔴 第九次审计修复（6 项）：PFX密码覆盖 + DNS Key假验证 + Checksum死代码 + 日志恢复

基于 v1.5.35 全量逐行审计 (DeepSeek V4 Pro thinking=high)，重点修复：ACME续签覆盖自定义PFX密码、
DNS Key在线验证不触发真实API、Agent二进制下载无完整性校验、DNS日志丢失。

#### 🔴 Critical（3 项）

- **C1 ACME 自动续签后 PFX 密码被硬编码 "ddns" 覆盖** — `UpdateCertMeta()` 生成双 PFX 文件时
  硬编码密码 `"ddns"`，忽略用户通过 Web UI 设置的 `CertBundle.PFXPassword`。
  修复：`UpdateCertMeta` 从 `meta.json` 读取 `pfx_password` 字段传入 `GeneratePFX`
- **C2 testDNSKeyOnline 不设域名时可能不做真实 API 调用** — v1.5.34 M7 将 `Domains` 设为 `nil`
  以避免域名不存在混淆，但 Cloudflare/Porkbun 等 provider 在无域名时不发起任何 API 请求。
  修复：支持 `?domain=xxx` 查询参数指定测试域名，未指定时用 `"@"` 根域名触发真实 API
- **C3 AgentUpdate.Checksum 从未填充 — 下载完整性校验死代码** — Manager 推送升级时
  `Checksum` 字段永远为 `""`，Agent 侧 `if update.Checksum != ""` 分支永不执行。
  修复：`SaveAgentBinary` 自动计算 SHA256 并保存 `.sha256` 文件；
  `GetAgentBinarySHA256` 读取校验和；`handleHeartbeat` 填充 `AgentUpdate.Checksum`

#### 🟠 High（2 项）

- **H2 心跳失败时 DNS 更新日志丢失** — `req.Logs` (DNS更新日志) 未像 `req.AgentLogs` 一样
  在心跳失败时回写缓冲，连续两次心跳失败时第一批 DNS 日志可能被覆盖。
  修复：心跳失败时将 `req.Logs` 写回 `agentLogBuf`
- **M2 DNSUpdater.Run() log.SetOutput 无 defer 恢复** — `provider.Init()` 若 panic，
  `log.SetOutput` 不被恢复，后续所有日志输出被重定向到已销毁的 `bytes.Buffer`。
  修复：`defer log.SetOutput(origWriter)` 紧随设置之后

#### 🟢 Low（1 项）

- **L3 parseAuth base64 解码无长度限制** — 恶意请求可发送超长 Authorization header。
  修复：限制 header 长度 ≤ 2048 字节

#### 🧪 部署状态
- Manager (10.0.0.1): v1.5.36 ✅
- Client A Linux (10.0.0.2): v1.5.36 ✅ (手动部署)
- Client B Windows (10.0.0.3): v1.5.35 → 等待心跳自动升级到 v1.5.36

---

## v1.5.35 — 2026-05-15

### 🔴 第八次审计修复（13 项）：数据竞争 + 日志持久化 + 认证核验 + 降级保护

基于 v1.5.34 全量逐行审计，重点修复：ACME 数据竞争、LastErrorDetail
误报、Agent 操作日志丢失、DNS Key 认证核验漏报、version 比较发散。

#### 🔴 Critical（4 项）

- **C3 RenewByName 多处 lastRenewErr 写操作未加锁** — 5 处写入未持 `m.mu.Lock()`，与
  `LastError()` 的锁读形成数据竞争。修复：统一 `setLastErr()` 闭包加锁写入
- **C4 RenewByName 返回 true 但 UpdateCertMeta 失败静默** — PFX 重新生成失败时
  bundle hash 未更新 → Manager 检测不到变更 → Agent 永收不到新证书。
  修复：`UpdateCertMeta` 失败时返回 false + 设置 `lastRenewErr`
- **C1 selfUpgrade 拒绝降级后返回 nil** — Manager 侧 RetryCount 持续递增，
  运维无法区分"Agent 正确拒绝降级"与"升级下载失败"。
  修复：返回 `errDowngradeBlocked` sentinel error，`doHeartbeat` 中单独处理
- **H1 LastErrorDetail 误捕非错误日志行** — 匹配 `"Message"`/`"Code"`/`"400"`
  等宽泛关键词，ddns-go 成功日志也被捕获。
  修复：精确匹配 `level=error` + JSON 错误码模式 + 已知错误码

#### 🟠 High（5 项）

- **H2 两个 compareSemVer 实现发散** — agent/main.go 和 store/store.go 各有一套，
  pre-release 处理不同。修复：提取 `model.CompareSemVer` 公共实现，双向引用
- **H3 Agent 操作日志仅内存缓冲** — `agentLog` 仅写 `agentLogBuf` 内存，Agent
  crash 所有未发送日志丢失。修复：增加 `agent_events.log` 文件持久化 (10MB 轮转)
- **H5 testDNSKeyOnline 错误关键词覆盖不全** — 仅 9 个关键词，Cloudflare/Porkbun
  等提供商错误漏报。修复：扩展到 20+ 关键词 + 输出完整捕获日志
- **H6 sendHeartbeat 不区分失败原因** — 返回 nil 无法区分网络/认证/解析失败。
  修复：改为 `(*model.HeartbeatResp, error)` 返回，日志含具体错误
- **M5 心跳失败不记录 Manager 响应体** — 非 JSON 响应时解析失败无法诊断。
  修复：解析失败时截取前 200 字符 body 写入错误

#### 🟡 Medium（4 项）

- **M1 ddns_errors.log 无轮转** — 长期运行可能写满磁盘。修复：10MB 轮转保留 3 个
- **M3 scheduleManagerRestart 硬编码 /opt/ddns-manager** — 修复：`os.Executable()` 动态获取
- **M4 Windows 批处理 taskkill 后无进程验证** — fallthrough 到文件替换可能因锁失败。
  修复：增加 `tasklist` 验证进程已终止
- **M7 testDNSKeyOnline 用虚拟域名 test.example.com** — 修复：不设域名，Init 环节已验证凭证

#### 🧪 部署状态
- Manager (10.0.0.1): v1.5.35 ✅
- Client A Linux (10.0.0.2): v1.5.35 ✅ (心跳自动升级)
- Client B Windows (10.0.0.3): v1.5.34 → 等待心跳自动升级到 v1.5.35

---

## v1.5.33 — 2026-05-15

### 🟢 功能增强（3 项）：详细错误上报 + DNS Key 核验 + 邮件美化

#### 改进1: ddns-go API 详细错误上报
- **问题**: DNS 更新失败时 Manager 只看到"DNS更新失败: client-a.example.com"，无法诊断原因
- **修复**: `DNSUpdater.Run()` 中 log 截获 ddns-go 的 API 错误输出 → 填充 `LastErrorDetail` 字段 →
  心跳上报 `DDNSHealth.LastErrorDetail` → Manager 日志含完整 API 响应原文
  （如 `Code=InvalidAccessKeyId.NotFound Message=Specified access key is not found.`）
- **影响**: 管理端可直接看到错误原因，无需登录 Agent 查 agent.log

#### 改进2: DNS Key 在线核验 + 定时检测
- **实时核验**: `POST /api/admin/dns-keys/{name}/test` — 调用 DNS 提供商真实 API 验证 Key 有效性，
  30s 超时，返回 `{valid: true/false, detail: "..."}`。仅提示不阻止保存
- **定时检测**: `StartDNSKeyChecker` 每 6 小时自动检测所有 DNS Key → 无效时记录审计日志 → 发送邮件通知
- **支持**: 28 个 DNS 提供商全覆盖 (与 ddns-go v6.17.0 对齐)

#### 改进3: 邮件美化
- **发件人**: `DDNS-Manager <user@domain.com>` (替代裸邮箱名)
- **HTML 邮件**: 带 Logo (🦐 DDNS-Manager)、蓝色顶栏、灰色页脚、自适应宽度
- **内容格式**: 纯文本自动转 HTML (`\n` → `<br>`)

### 🔴 Bug 修复（3 项）：IPv6网卡保存 + Agent旧目录 + PFX certutil导入 + 部署路径

#### 🔴 Bug 1: IPv6 获取方式改"网卡"无法保存

- **根因**: 前端选项值 `netInterface` (camelCase)，v1.5.30 新增 `validateIPConfig`
  只匹配全小写 `netinterface` → default 分支返回 400
- **修复**: `validateIPConfig` + `renderDDNSConfig` normalize getType to lowercase

#### 🔴 Bug 2: Linux 节点从 v1.5.29 升级到 v1.5.30+ 后离线

- **根因**: 默认安装目录从 `/opt/ddns-manager` → `/opt/ddns-agent`，旧节点二进制升级后
  `init()` 设 `agentConfigPath` 为新路径，找不到 `agent.yaml`
- **修复**: 新增 `detectInstallDir()` — 默认路径不存在时回退到二进制所在目录

#### 🔴 Bug 3: Windows PFX 证书导入失败（Modern+Legacy+OpenSSL 三种路径全挂）

- **根因**: `X509Certificate2.Import()` 在不同 PowerShell/.NET 版本下行为不一致，
  `DefaultKeySet` 对机器级证书可能无效
- **修复**: `importPFXToIIS` + `importToIIS` 用 `certutil -importpfx -enterprise` 替代
  PowerShell，certutil 全版本一致、无执行策略依赖

#### 🟡 部署路径从客户端获取真实 CertPath

- **修复**: `handleHeartbeat` 中 `TargetPath` 为空时取 `req.Status.CertPath`
  （Agent 上报的 agent.yaml 中 CertPath），保证 Manager/Agent 路径对齐

#### 🔴 Bug 4: Linux 节点在线升级失败（降级+二进制缺失）
- **根因**: (1) v1.5.33 linux-amd64 二进制未上传到 Manager data/bin/
  (2) manifest 残留 v1.5.32 条目 → Manager 推送错误版本 URL
  (3) Agent 无降级保护 → v1.5.33→v1.5.32 照单全收
- **修复**:
  - 上传全平台 v1.5.33 二进制到 data/bin/ + 更新 manifest 所有平台条目
  - `selfUpgrade` 增加 `compareSemVer` 版本比较 — 推送版本 ≤ 当前 → 拒绝降级并记录日志

#### 🧪 部署状态
- Manager (10.0.0.1): v1.5.33 ✅
- Client A Linux (10.0.0.2): v1.5.33 ✅
- Client B Windows (10.0.0.3): v1.5.33 已推送 ✅ (修复 Win10 START_PENDING 卡死)

---

## v1.5.31 (补丁) — 2026-05-15

### 🔴 第七次审计修复（7 项）：CertErrors存储链路 + 多ACM超时 + Agent日志轮转 + DNS持久化 + 续签验证

基于 v1.5.30 全量逐行再审计，重点修复：CertErrors 上报后 Manager 不存储不展示、
StartAutoRenew 多账号共享超时、Agent agent.log 无轮转、DNS日志缓冲区崩溃丢失、
续签不验证真实更新、URL逗号分隔未逐段校验、agentLog 无调用位置。

#### 🔴 Critical（1 项）

- **C1 CertErrors 上报后 Manager 不存储不展示** — Agent 通过 `Status.CertErrors` 上报证书部署错误，
  但 `handleHeartbeat` 只复制了 `CertHashes` 未复制 `CertErrors`，结构化数据静默丢弃。
  修复：追加 `rec.Status.CertErrors = req.Status.CertErrors`，
  心跳 detail 附加 `cert_errs=N` 计数

#### 🟠 High（3 项）

- **H1 StartAutoRenew 多 ACME 账号共享超时** — 所有 mgr 串行续签共用 5分钟 context，
  第1个账号占满时间后后续账号无机会续签。修复：每个 mgr 独立创建 context(5min)
- **H2 Agent agent.log 无轮转** — `O_APPEND` 追加写入永不轮转，daemon模式数周可达 GB 级。
  修复：10MB 阈值轮转 `agent-YYYY-MM-DD.log`，保留最近 3 个
- **H3 DNS 更新日志缓冲区无持久化** — `logBuf` 仅内存环形缓冲，Agent 崩溃时所有 DNS 历史丢失。
  修复：失败域名同步追加写入 `ddns_errors.log`

#### 🟡 Medium（3 项）

- **M1 handleRenewCert 不验证是否真实续签** — acme.sh 可能报告成功但未实际更新文件。
  修复：续签前记录 `fullchain.pem` mtime，续签后对比，未变化记WARNING
- **M2 URL 逗号分隔列表未逐段校验** — 只检查整个字符串前缀，`http://good,evil` 通过校验。
  修复：`strings.Split(url, ",")` 后逐段 TrimSpace + 前缀检查
- **M3 agentLog 不含调用位置** — 排查 Agent 端问题时无从定位代码。
  修复：`log.SetFlags(log.LstdFlags | log.Lshortfile)`

#### 🧪 测试环境部署
- Manager (10.0.0.1): v1.5.31 ✅
- Client A Linux (10.0.0.2): v1.5.31 ✅ 心跳正常 DDNS=OK
- Client B Windows (10.0.0.3): v1.5.30 → 升级推送已下发，等待心跳自动升级

---

## v1.5.30 (补丁) — 2026-05-15

### 🔴 第六次审计修复（7 项）：输入验证 + 证书续签一致性 + 日志链路补全

基于 v1.5.29 全量逐行审计，重点修复：renderDDNSConfig 输入验证缺失、
ACME 手动续签 CertBundle 未重新加载、certErrors 不上报、CertBindings 路径穿越、
多 DnsConf 失败域名被覆盖、PFX 密码 PowerShell 转义、Windows 升级回滚验证。

#### 🔴 Critical（3 项）

- **C1 renderDDNSConfig 输入验证缺失** — 域名格式/TTL/URL/GetType/NetInterface 全不校验。
  修复：新增 `validateNodeConfig()` + `validateDomains()` + `validateIPConfig()` 三层校验，
  在 `handleSaveNodeConfig` 中 JSON 反序列化后、Marshal 前调用，违规返回 400+具体错误
- **C2 ACME 手动续签后 CertBundle 未重新加载** — `handleRenewCert` 续签成功后直接返回 JSON，
  不调 `LoadCertBundle`+`SaveCertBundle` 更新 store 中的 hash。修复：对齐 `StartAutoRenew` 流程，
  续签成功后重新加载 bundle 并回存
- **C3 Windows 升级批处理回滚无二次验证** — 回滚 `move BAK→OLD` 失败后仍启动服务。
  修复：`:start_service` 前增加 `%OLD%` 存在性 + 大小验证，失败时跳过服务启动

#### 🟠 High（4 项）

- **H1 多 ACME 账号续签遍历效率低** — `handleRenewCert` 从 mgr[0] 开始 O(n) 遍历，不作 email 匹配。
  修复：先读 meta.json 获取 email → 遍历中 skip 不匹配的 mgr
- **H2 certErrors 不上报 Status.CertErrors** — 证书部署失败只写 AgentLog（category=agent 日志），
  Manager 无结构化解析。修复：新增 `lastCertErrors` 全局缓存，下个心跳填充 `Status.CertErrors` 字段
- **H3 CertBindings DeployPath 路径穿越** — `handleSaveNodeConfig` 不验证 `DeployPath`，
  可含 `..`/绝对路径。修复：新增 `validateCertBinding()`，拒绝路径穿越
- **H4 DNSUpdater 多 DnsConf 段失败域名被覆盖** — `failedDomains` 在内层 for 循环重新初始化，
  多段时只保留最后一段的失败列表。修复：`allOK` + `allFailedDomains` 提到循环外层累积

#### 🟡 Medium（2 项）

- **M1 Windows 升级日志双文件不统一** — 批处理写 `ddns_upgrade.log`，Go 写 `ddns_upgrade_agent.log`。
  修复：`upgradeLogger` 改为写入 `ddns_upgrade.log`，与批处理统一
- **M2 PFX 密码单引号导致 PowerShell 语法错误** — `importPFXToIIS` 未对 `pfxPassword` 做单引号转义，
  密码含 `'` 时 PowerShell 命令解析失败。修复：`strings.ReplaceAll(pfxPassword, "'", "''")`

#### 🧪 测试环境部署
- Manager (10.0.0.1): v1.5.30 ✅
- Client A Linux (10.0.0.2): v1.5.30 ✅ 心跳正常
- Client B Windows (10.0.0.3): v1.5.29 → 由心跳自动升级到 v1.5.30

---

## v1.5.29 (补丁) — 2026-05-15

### 🟠 持续修复（7 项）

- **installer: 安装器与 Agent 版本解耦** — 安装器独立版本 v1.0.0 (`INSTALLER_VERSION`)，
  文件名 `ddns-installer-linux-${arch}` 不再带 Agent 版本号
- **installer: 统一安装入口** — install.sh 移除升级快捷路径，新装/重装都由 installer 处理；
  重装时先显示旧配置信息，用户可选保留升级或清除重装
- **installer: Agent 默认目录改为 `/opt/ddns-agent`** — 与 Manager (`/opt/ddns-manager`) 分离
- **installer: ddns-go 误报修复** — `systemctl is-active` 改用 exit code 判断 (exit 4=unknown 不再误报)
- **installer: 三重安全保护** — 只删 `agent.yaml`/`node-agent`/`ddns_cache.yaml` 具体文件；
  `cleanAgentBinaries` 检查 agent.yaml 存在才清理；永远不用 `os.RemoveAll(dir)`
- **installer: readLine 中文乱码修复** — 逐字节读取改 rune 级读取，中文输入正常显示
- **manager: LoadCertBundle 未设 Name 导致 PFX密码保存后变回 ddns** — 新增 `b.Name = name`，
  确保 SaveCertBundle 写入正确子目录
- **manager: ConfigHash 双方为空时永不推送首次配置** — 新增 `|| rec.ConfigHash == ""` 强制推送
- **docs: 安装接口规范 v1.0** — 冻结的三方接口契约（安装器/Agent/Manager），定义 8 章接口约束
- **api: 上传二进制自动部署** — 从文件名提取版本号 → 自动设置 AgentVersion → Manager 二进制自动重启

---

## v1.5.29 — 2026-05-14

### 🔴 第五次审计修复（12 项）：日志链路 + 一键部署 + DNS 错误上报

基于 v1.5.28 逐行审计，重点修复：AgentLogs 上报时序错误、Manager 日志处理缺失、
install.sh 版本硬编码/无校验、DNS 失败域名丢失、ACME 空续签日志回归。

#### 🔴 Critical（3 项）

- **C1 AgentLogs 赋值时序错误（数据丢失）** — `doHeartbeat` 中 `agentLogBuf.Drain()` 在 `sendHeartbeat()` 之后调用，
  导致 Agent 操作日志写入已废弃的局部变量，永不到达 Manager。修复：Drain 移到 sendHeartbeat 之前，
  心跳失败时恢复日志到缓冲防止丢失
- **C2 Manager 完全不处理 AgentLogs / Logs** — `handleHeartbeat` 从未读取 `req.Logs`/`req.AgentLogs`。
  修复：DNS 更新日志写入 category=dns-update，Agent 操作日志写入 category=agent，各限制 20 条
- **C3 install.sh 版本硬编码 + 无下载校验** — 硬编码 `VER="1.5.27"` 每次发版需手动更新；下载后无 SHA256 校验。
  修复：移除硬编码，改为从 `/api/ping` 动态获取（失败时退出并提示）；增加 .sha256 文件校验

#### 🟠 High（5 项）

- **H1 DNS 更新失败原因丢失具体域名** — `LastError` 只有笼统的"部分域名更新失败"。
  修复：`DNSStatus` 新增 `FailedDomains []string`，`LastError` 包含具体失败域名列表
- **H2 ACME 自动续签空结果无日志（v1.5.19 C4 回归）** — Renew 返回空 renewals 时无审计日志。
  修复：`StartAutoRenew` 增加空结果判断 + `countExpiringCerts()` 辅助函数
- **H3 配置变更触发的 DNS 更新结果被丢弃** — `go func()` 调用 `runDNSUpdateWithTimeout` 结果被忽略。
  修复：捕获结果写 agentLog，失败时记录具体错误
- **H4 install.sh 版本检测依赖非标准工具** — `grep -o | cut` 精简系统可能缺失。
  修复：改用 POSIX 标准的 `sed` 单工具解析
- **H5 证书部署失败原因不上报 Manager** — 解密/写入/IIS 失败只写本地 log。
  修复：`applyCertUpdates` 返回 `certErrors []string`，通过 AgentLogs 上报

#### 🟡 Medium（4 项）

- **M1 DNSUpdater.Run() 多 DNS 配置段 IP 覆盖** — 多 DNSConf 时后面覆盖前面的 IP。
  修复：取第一个非空 IP
- **M2 Daemon shutdown 时 DNS goroutine 泄漏** — shutdown 不等待 DNS 更新完成。
  修复：等待 `dnsUpdateRunning` 变为 false（最多 30 秒）
- **M3 心跳日志不含 DDNS 错误详情** — 只显示 `ddns=ERR` 不含 LastError。
  修复：ERR/DOWN 时附加 `err=...` 和 `failed=...`
- **M4 VERSION 升级 + 全平台构建** — VERSION → v1.5.29，
  生成 10 个 .sha256 校验文件供 install.sh 使用

#### 🧪 测试环境部署
- Manager (10.0.0.1): v1.5.29 ✅
- Client A Linux (10.0.0.2): v1.5.29 ✅ 心跳正常
- Client B Windows (10.0.0.3): v1.5.28 → 由心跳自动升级到 v1.5.29

---

## v1.5.26 — 2026-05-14

### 🟢 全平台二进制补齐 + Windows 自动升级实机验证

- **全平台 Agent**: linux-amd64 / linux-arm / linux-arm64 / windows-amd64 四架构 v1.5.26 二进制已上传
- **Windows 自动升级实测**: 3 台 Windows 节点收到推送后 2-3 秒内完成升级，DDNS 不掉线
- 升级日志增加 `v1.5.26+` 版本标记

---

## v1.5.25 — 2026-05-14

### 🔴 Windows 自升级死锁修复（重写 upgrade_windows.go）

**根因**: Go 进程内调用 `sc stop self` 触发 SCM → handler 返回 → `svc.Run` 退出 → `main` 返回 → 进程在批次脚本写出前被 OS 杀死。v1.5.11~v1.5.24 所有 Windows 自升级均在此处静默失败。

**修复**: 重写 `replaceRunningBinary` — Go 不再调 `sc stop`。批次脚本作为独立分离进程托管停服→替换→启动全流程，新增 `sc config start= disabled` 防 SCM 自动重启旧二进制。

**方案对比**: 详见 `docs/audits/2026-05-14-windows-upgrade-deadlock.md`

#### 批次脚本流程
```
sc config start= disabled → sc stop → 轮询 STOPPED(60s超时) →
move 旧→.bak → move 新→node-agent.exe → 验证>1KB →
sc config start= auto → sc start
```

---

## v1.5.24 — 2026-05-14

### 🟠 Windows 自升级首次修复尝试（upgrading 标志 — 失败）

**尝试**: 在 `svc_windows.go` handler 中使用 `upgrading atomic.Bool` 阻止 stop 信号时退出。
**结果**: 死锁 — handler 等 upgrading=false, upgrading 等 stopServiceSync 返回, stopServiceSync 等服务标记 STOPPED, SCM 等 handler 返回才标记 STOPPED。30s 超时 taskkill。

---

## v1.5.23 — 2026-05-14

### 🔴 第四次全量审计修复（15 项）

基于 v1.5.22 逐行代码审计 (DeepSeek V4 Pro thinking=high)。重点修复: Windows 证书部署错误处理、配置缓存写入验证、goroutine 堆积防护、服务重载可靠性、升级退避窗口。

#### 🔴 Critical（4 项）

- **C2 applyCertUpdates 证书文件写入错误被忽略** — `os.WriteFile`/`os.Rename` 失败时记录日志并 `continue`，防止磁盘满时 IIS 绑定使用不存在文件
- **C3 configCache 写入错误静默丢弃** — `os.MkdirAll` + `os.WriteFile` 结果检查，失败时输出 `agentLog` 警告磁盘可能已满
- **C4 dnsUpdateRunning atomic.Bool 从未使用** — `doHeartbeat` 中 DNS 重新更新前使用 `CompareAndSwap` 去重，goroutine 退出时 `Store(false)`
- **C5 reloadService Windows sc stop 失败被忽略** — `sc stop` 结果检查并记录日志，stop 失败时仍尝试 start（服务可能已停止）

#### 🟠 High（6 项）

- **H1 升级退避窗口 30min → 10min** — 覆盖 ≥2 个心跳周期，减少升级延迟
- **H2 心跳失败时 agentLogBuf 被 Clear 丢失操作日志** — 新增 `heartbeatFailed atomic.Bool` 标记 + `LogBuffer.Drain()`/`Len()` 方法，失败时保留日志下次发送
- **H3 PFXPassword 为空时无日志提示** — Agent 回退到默认密码时输出 `agentLog` 警告；Manager 下发空密码时记录审计日志
- **H4 handleListNodes 使用 `time.Now()` 而非 `s.nowInTZ()`** — 统一时间源，防止时区不一致导致节点错误标记 DOWN
- **H5 CertBindings 清空与 ConfigYAML 不同步** — 增加注释说明 CertBindings 优先于 ConfigYAML 的证书推送判定
- **H6 handleDownloadInstaller ZIP Close 错误被忽略** — 移除 `defer zw.Close()`，显式检查 Close 错误并记录审计日志

#### 🟡 Medium（5 项）

- **M1 certHashMap 清理代码死路径** — 正常路径 (iisOK=true) 也写入 certHashMap，清理逻辑现在生效
- **M2 下载大小验证阈值 80% → 95%** — 防止截断二进制通过验证（15MB 下载 12MB 原可通过）
- **M3 Logger rotateIfNeeded 无 debounce** — 增加 5 分钟 debounce，防止 `os.Rename` 失败时连续轮转
- **M4 collectCertHashes 超时后 race** — 增加 `sync.Mutex` 保护 result map 并发写入
- **M5 PFX 硬编码默认密码无日志** — 回退到 "ddns" 时输出 agentLog 提醒管理员设置密码

#### 📝 设计说明

- **C1（非 bug）**: 升级日志写入安装目录而非 `%TEMP%` 是故意设计 — 1) 软件未通过微软审核，安装目录已设 AV 排除路径 2) `%TEMP%` 在部分系统环境变量异常时不可访问。已在 `upgrade_windows.go` 添加设计说明注释。

### 🧪 新增测试
- `TestLogBufferDrainAndLen` — H2: Drain/Len 方法验证
- `TestDNSUpdateRunningGuard` — C4: atomic.Bool 去重验证
- `TestCertWriteErrorHandling` — C2: 证书写入失败错误处理

---

## v1.5.20 (Build 2) — 2026-05-14

### 🔴 三次全量审计修复（18 项）

基于 v1.5.19 逐行代码审计 + CHANGELOG 对照验证。重点修复：Windows证书部署后服务重载、Windows自升级批处理、心跳重试、审计日志缺口。

#### 🔴 Critical（3 项）

- **C1 handleHeartbeat 不传播 ReloadServices** — `CertUpdate` 构建时添加 `ReloadServices: binding.ReloadServices,`。修复前证书部署后 nginx/IIS 等服务永不自动重载（v1.5.12 C1 修复回归）
- **C2 Windows 批处理缺 `setlocal enabledelayedexpansion`** — 批处理模板 `@echo off` 后添加该行，`!NEWSIZE!` 延时变量正确展开，二进制验证不再失败
- **C3 Windows 批处理 `>nul 2>&1` 静默丢弃日志** — 所有 move 操作改为 `>>%TEMP%\ddns_upgrade.log 2>&1`，升级失败可诊断

#### 🟠 High（5 项）

- **H1 Windows daemon 心跳失败快速重试** — `svc_windows.go` 新增 30s×3 重试 + `select+stopCh` 可中断，对齐 Linux daemon
- **H1b Linux daemon 心跳失败快速重试** — `main.go` daemon 模式新增同 H1 重试逻辑，心跳失败不再中断 DNS 5 分钟
- **H2 Windows Service Stop 中 `time.Sleep(3s)` 不可中断** — 改为 `select { case <-time.After(3s): case <-s.stopCh: }`
- **H3 Logger `rotateIfNeeded` 中 `file.Close()` 错误被忽略** — 检查 Close 错误并 log.Printf
- **H4 `handleSetAgentVersion` 正常版本设置无审计日志** — `jsonOK` 返回前添加日志含 ver + clientIP
- **H5 `handleDownloadCert` 证书下载无审计日志** — 函数开头添加日志含 name + clientIP
- **H5b `handleLogsDownload` 日志下载无审计日志** — 函数开头添加日志含 clientIP

#### 🟡 Medium（5 项）

- **M1 `RenewByName` 中 `lastRenewErr=nil` 未加锁** — 添加 `mu.Lock()`/`mu.Unlock()` 包围
- **M2 心跳失败时 `agentLogBuf` 不清理** — 心跳失败 return 前先 `agentLogBuf.Clear()`
- **M3 `handleUploadAgentBinary` 成功上传无审计日志** — 添加日志含文件名+大小
- **M4 `handleDownloadInstaller` 无审计日志** — 函数开头添加日志含 ver + os + clientIP
- **M5 ACME `issueCert` 中 `os.Create` 错误静默忽略** — 检查 `os.Create` 和 `pem.Encode` 错误

#### 🟢 Low（3 项）

- **L1 `extractCNFromPFX` + `extractThumbprintCertutil` 重复执行 certutil** — 合并为 `extractPFXInfo` 一次调用同时返回 thumb + CN
- **L2 Windows 上 HardwareInfo.OS 为 `windows/amd64`** — 新增 `osname_windows.go` 读注册表 `ProductName`，展示友好名称
- **L3 `collectCertHashes` 超时后 goroutine 继续执行** — 已有 `select ctx.Done()` 回调内检查，标记为已知 Go WalkDir 限制

#### 🧪 测试（2 项）
- `TestReloadServices_Propagation` — C1: CertUpdate 包含 ReloadServices（正常/nil/空切片）
- `TestWindowsUpgrade_BatchExpansion` — C2/C3: 批处理关键词验证（setlocal/日志重定向/回滚）

---

## v1.5.19 — 2026-05-14

### 🔴 二次全量审计修复（23 项）

基于 v1.5.18 逐行审计，重点覆盖：Windows证书自动续签、自升级、管理端日志覆盖。

#### 🔴 Critical（5 项）

- **C1 Windows证书部署IIS失败仍写`.cert_hash`** — `applyCertUpdates` else分支不再写入`.cert_hash`/`certHashMap`，IIS绑定失败时保留旧hash，下次心跳重试（违背v1.5.11 H5声称的修复）
- **C2 ACME `Renew()`只续签首个域名** — 改为传递全部域名到`acme.sh --renew -d`，确保多域名SAN证书完整续签（违背v1.5.15 C2修复声称）
- **C3 ACME `RenewByName()`只续签首个域名** — 同C2，手动续签也传递全部`-d domain`参数
- **C4 `LastError()`数据竞争** — `LastError()`和`Renew()`/`RenewByName()`中`lastRenewErr`操作加`mu.Lock`保护（违背v1.5.15 M4修复声称）
- **C5 Windows升级子进程零错误输出** — `upgradeExecMode`写入`%TEMP%\ddns_upgrade.log`，`replaceRunningBinary`增加`agentLog`调用

#### 🟠 High（8 项）

- **H1 升级退避窗口过短** — 2min→10min，覆盖≥2个心跳周期，减少重复下载
- **H2 Logger旋转阻塞写操作** — `rotateIfNeeded`移入独立`rotateMu`，`fileMu`仅保护实际写入
- **H3 Admin中间件bcrypt CPU DoS** — bcrypt回退前增加轻量限流(5 req/min per IP)
- **H4 升级二进制缺失无日志** — `os.Stat`失败else分支记录审计日志
- **H5 DNS更新goroutine堆积** — 使用`atomic.Bool`防止重复启动
- **H6 `certHashMap`永不清理** — `applyCertUpdates`末尾清理不再推送的bundle条目
- **H7 Windows Service重试sleep不响应停止信号** — `time.Sleep`改为`select+stopCh`可中断
- **H8 `writeIdx`估算不可靠** — 改为使用实际读取的事件数

#### 🟡 Medium（7 项）

- **M1 Windows升级零agentLog** — `replaceRunningBinary`增加agentLog
- **M2 ACME Renew无汇总日志** — 末尾添加"已续签N个证书"
- **M3 下载安装器ZIP无Content-Length** — 预计算文件大小设置Content-Length
- **M4 `reloadService`错误被忽略** — 返回bool，调用方收集失败服务
- **M5 config缓存写入不检查错误** — `os.WriteFile`结果检查并agentLog
- **M6 `CertBindings`判断`len>0`** — 改为`!=nil`（nil=保留，[]=清空）
- **M7 certHashMap跳过deploy时不更新** — path为空时也更新certHashMap防重复推送

#### 🟢 Low（3 项）

- **L2 `agentLogBuf`心跳后不清空** — 添加`LogBuffer.Clear()`方法，心跳后调用
- **L3 `collectCertHashes`goroutine泄漏** — `filepath.Walk`→`WalkDir`+context取消
- **H8 并入（writeIdx修正）**

### 🧪 测试
- `TestCertDeploy_IISFailKeepsOldHash` — C1: IIS失败后`.cert_hash`不变
- `TestACME_RenewAllDomains` — C2: 多域名传参验证
- `TestWindowsUpgrade_LogFile` — C5: 升级子进程日志文件写入

---

## v1.5.15 — 2026-05-13

### 🔴 深度安全审计修复（17 项全量修复）

#### 🔴 Critical（4 项）

- **C1 Windows 升级批处理无限等待** — 批处理轮询 STOPPED 增加 60s 超时（30次×2s），超时后记录 ERROR 日志退出，防止 SCM STOP_PENDING 永久挂起时 cmd.exe 不可见驻留
- **C2 ACME Renew() 只续签首个域名** — Renew()/RenewByName() 改为传递全部域名到 acme.sh `--renew -d` 参数，确保多域名证书 SAN 完整
- **C3 selfUpgrade 下载验证在重试循环外** — validateAgentBinary() 移入每次成功下载后立即验证，损坏二进制触发即时重试而非浪费全部 3 次下载
- **C4 ACME 自动续签失败静默** — StartAutoRenew 中 Renew 返回空列表时记录审计日志（失败/跳过），避免证书悄悄过期

#### 🟠 High（5 项）

- **H1 logger.go writeIdx 溢出防护** — QueryByTime/CountByTime 增加 overflow guard，防止 int 极值时减法溢出
- **H2 handleHeartbeat 升级推送无二进制存在日志** — 二进制缺失时记录审计日志，便于运维排查"管理员未上传"问题
- **H3 detectPlatform 非标准架构处理** — 未知架构名保留原值（非空），manifest 自然不匹配→跳过升级
- **H4 collectCertHashes goroutine 泄漏** — done channel 已有 buffer=1（v1.5.12已修复，审计确认）
- **H5 StartAutoRenew 并发修改风险** — C4 修复中间接解决（email 提前捕获），低风险

#### 🟡 Medium（5 项）

- **M1 Windows Service 心跳失败无快速重试** — svc_windows.go 新增 30s×3 次快速重试，与 Linux daemon H3 对齐
- **M2 logger.logEvent 终端输出交错** — 终端 log.Printf 移入 mu 锁内执行，防止多 goroutine 输出交错
- **M3 RebuildManifest 锁保护** — 分析后确认：SaveAgentManifest 持写锁写文件确保原子性，读目录竞态低概率且下次自动修正；已加注释说明
- **M4 acme.go LastError() 数据竞争** — LastError() 加 mu.Lock 保护，与 Renew() 写入串行化
- **M5 handleGetLogs total 语义不准确** — 全量查询时使用 Stats().total_events 获取真实总数

#### 🟢 Low（保留）

- **L1 DeriveKey panic** — 理论上不可达（SHA256+32B key = always full read），保留 panic 减少不必要的错误处理扩散
- **L2 Symlink 跨文件系统** — 同分区安装不触发，低概率
- **L3 sc query 大小写** — 非英文 Windows sc query 仍输出英文 "STOPPED"，不受影响

#### 🧪 测试
- `TestUpgradeBatchTimeout` — C1: 批处理超时关键词验证 + 路径安全检查
- `TestUpgradeBatchRollback` — 回滚机制关键词验证
- `TestRenewAllDomains_MultiDomain` — C2: 多域名传参验证（正常/边界/空域名）
- `TestRenewByNameAllDomains_MultiDomain` — C2: RenewByName 多域名 --force 验证
- `TestACMEAutoRenewEmptyDir` — C4: 空目录续签 + LastError 线程安全
- `TestSelfUpgradeEarlyValidation` — C3: 验证循环内检查 + 空文件/损坏/PE/错误架构
- `TestSelfUpgradeRetryPattern` — C3: 重试模式验证（继续/一次成功/全部失败）

## v1.5.14 — 2026-05-13

### 🔴 指纹算法重写: PowerShell → Go原生注册表

**根因**: 安装器 `generateFingerprint()` 使用 `powershell (Get-CimInstance Win32_ComputerSystemProduct).UUID` 获取机器标识。
PowerShell 不同版本/执行上下文对 UUID 输出的尾随字符处理不一致（`\r\n` vs `\n` vs 无），导致同一台机器产生不同指纹，
"指纹匹配=旧机重装"逻辑失效。

**修复**:
- Windows: 改为读取注册表 `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`
  - 纯 Go 实现 (`golang.org/x/sys/windows/registry`)，零外部依赖
  - MachineGuid 是 Windows 安装时生成的标准 GUID，永不变
  - 所有 Windows 版本通用 (XP/7/8/10/11, Server 2003~2025)
- Linux: 保持 `/etc/machine-id`（不变）
- 新增 `getMachineID()` 函数，平台文件分离 (`machineid_windows.go` / `machineid_unix.go`)
- `getMachineID()` 失败时退化为纯 hostname 指纹

### 🧪 验证测试
- `TestFingerprintMachineGuid_Format` — 正常: 格式/一致性/防换行符污染 (3 检查)
- `TestFingerprintMachineID_Boundary` — 边界: getMachineID 返回值合法, 平台差异处理
- `TestFingerprintMachineID_Fallback` — 异常: getMachineID 失败时退化指纹有效

### ⚠️ 向后不兼容
- Windows 机器指纹会变化 (MachineGuid ≠ SMBIOS UUID)
- 所有 Windows 节点需**重新注册**以更新指纹
- 软件未正式发行，无兼容要求

## v1.5.13 — 2026-05-13

### 🔴 Windows 自升级架构重写 (Critical Bug Fix)

**根因**: v1.5.11 引入的 `stopServiceSync` 机制在 Windows Service 上有致命缺陷：
- `sc stop` → `Execute()` handler 返回 → `svc.Run()` → `os.Exit(0)` → **Go 进程在写批处理脚本之前就退出了**
- 导致批处理从未执行，二进制从不替换，服务永久停止
- 此外 v1.5.11 批处理脚本缺少 `setlocal enabledelayedexpansion`，`!NEWSIZE!` 被当字面值永远回滚

**v1.5.13 修复**: 重写 `upgrade_windows.go:replaceRunningBinary`
1. **先写批处理 + 启动为 detached process**（在 Go 进程退出之前）
2. Go `os.Exit(0)` → SCM 标记 STOPPED
3. 批处理轮询 `sc query` 直到 STOPPED → 安全替换 → 启动服务
4. 批处理增加 `sc start` 最多 3 次重试
5. 增加 `setlocal enabledelayedexpansion` 确保变量正确展开
6. 增加 `DETACHED_PROCESS` 标志确保批处理完全独立于父进程

### 🔧 v1.5.12 修复继承（全部包含）

#### 🔴 Critical (3): C1 ReloadServices / C2 批处理日志 / C3 ACME续签路径
#### 🟠 High (4): H1 时间源 / H2 CertBindings / H3 心跳重试 / H4 DNS Key追踪
#### 🟡 Medium (5): M1 索引估算 / M3 PFX清理 / M4 临时文件 / M5 版本校验

*完整清单见 v1.5.12 条目*

## v1.5.12 — 2026-05-13

### 🔐 深度安全审计修复（12 项全量修复）

#### 🔴 Critical（3 项）

- **C1 证书部署ReloadServices字段从未填充** — `CertBinding` 新增 `ReloadServices` 字段，`handleHeartbeat` 构建 `CertUpdate` 时传播该字段。修复后 Linux 节点证书部署后 nginx/apache 自动 reload，Windows 自定义服务也会收到重启通知
- **C2 Windows升级批处理静默失败无日志** — 批处理脚本重写：所有操作写入 `%TEMP%\ddns_upgrade.log`，备份/移动/启动每步记录 stdout+stderr，`sc start` 失败显式报 WARNING
- **C3 ACME续签不传输出路径** — `Renew()` 和 `RenewByName()` 续签时显式传递 `--cert-file`/`--key-file`/`--fullchain-file`，续签后验证 fullchain.pem mtime 是否更新并记录 WARNING

#### 🟠 High（4 项）

- **H1 handleListNodes 时间源不一致** — `time.Now()` → `s.nowInTZ()`，与心跳 `LastSeen` 时间源一致
- **H2 CertBindings 空数组清空歧义** — `len(req.CertBindings) > 0` → `req.CertBindings != nil`：nil=保留现有绑定，[]=主动清空
- **H3 心跳失败无快速重试** — daemon 模式心跳失败后 30s 重试 3 次再回 5min 周期，网络抖动时 DNS 不会中断 5 分钟
- **H4 DNS Key 追踪回退失效** — DnsProvider 回退时按 provider 字段查找实际 Key name，而非用 provider 名直接当 key

#### 🟡 Medium（5 项）

- **M1 Logger 尾部读取索引估算不精确** — 事件大小估算从 200→256 字节 + 溢出保护
- **M2 Recent() int 溢出（理论）** — 在 64 位系统上无影响，代码文档已说明
- **M3 PFX 写入失败继续执行** — `UpdateCertMeta` 中 PFX 生成失败时删除旧 PFX 文件，防止 hash 与实际文件不一致
- **M4 证书临时文件可能互相覆盖** — `applyCertUpdates` 临时文件名加 bundle 名前缀 `{bundle}-{filename}.new`
- **M5 handleDownloadInstaller ver 参数** — 新增语义化版本号正则校验

#### 📄 文档对齐
- `model/model.go` — `CertBinding` 新增 `ReloadServices` 字段及注释
- `CHANGELOG.md` — 本条目
- `VERSION` — 升级到 v1.5.12

## v1.5.11 — 2026-05-13

### 🔐 全量安全审计 + 持续修复（23+ 项）

#### 🔴 Critical（4 项）

- **C1 ACME自动续签后证书永不推送到Agent** — `acme.go:Renew()`/`RenewByName()` 续签成功后新增 `UpdateCertMeta()` 调用，重新计算 bundle hash 并更新 meta.json，确保下次心跳检测到变更并下发新证书
- **C2 ACME续签后PFX未重新生成** — `UpdateCertMeta()` 自动检测 cert+key PEM 文件，续签成功后调用 `GeneratePFX()` 重新生成 `cert.pfx`，Windows Agent 收到最新 PFX 文件
- **C3 Windows Agent升级竞态条件** — `upgrade_windows.go:replaceRunningBinary` 重写：阶段1 同步停服 (`stopServiceSync` 轮询 STOPPED 状态)，阶段2 批量脚本执行 move+验证+启动，消除 Go 进程退出 vs SCM 重启的竞态
- **C4 管理端日志覆盖严重不足** — 12处缺失审计日志补全：删除Agent二进制、心跳认证失败（含IP追踪）、证书下发成功、DNSPKey/节点/升级状态/Acme等操作

#### 🟠 High（5 项）

- **H1 心跳证书下发成功无审计日志** — `handleHeartbeat` 证书推送追加 `s.logMgr.LogWithNode("cert", "证书已下发", ...)`，对齐配置下发日志
- **H2 handleGetLogs total 字段语义错误** — 新增 `logger.CountByTime()` 方法返回过滤后真实匹配数，替换原 `len(events)` 的错误统计
- **H3 手动续签不更新bundle hash** — 合并到 C1 修复，`RenewByName()` 成功后调用 `UpdateCertMeta()`
- **H4 心跳认证失败无暴力破解防护** — 未知节点/密码错误/指纹不匹配均记录审计日志（含 clientIP），可追踪探测行为
- **H5 cert_hash先写后验证** — `applyCertUpdates` 重构：证书文件写入后先执行 IIS 导入 → 成功才写 `.cert_hash`，失败保留旧 hash 下次心跳重试

#### 🟡 Medium（6 项）

- **M1 configCacheKey每心跳重复派生** — 新增 `getConfigCacheKey()` 使用 `sync.Once` 缓存 HKDF 派生结果
- **M2 证书到期解析按文件名排序误选CA证书** — `handleListCerts` PEM 排序改为语义优先级（fullchain.pem/cert.pem 优先于 ca.pem）
- **M3 Windows升级批处理无错误回滚** — 批处理脚本新增：备份旧二进制→move新→验证文件大小>1KB→启动服务，失败则回滚旧二进制
- **M4-M6** — IIS绑定/路径穿越/跨平台兼容：见下方详细

#### 🟢 Low（3 项）

- **L1 华为云DNS API缺少HUAWEICLOUD_DomainID** — `dnsAPIMapping` 新增 `extraEnv` 字段，华为云自动设置 `HUAWEICLOUD_DomainID` 环境变量
- **L2-L3** — 纯Go HTTP-01续签路径已移除（acme.sh优先），批处理中文输出优化

#### 🔧 其他 + 后续修复
- **M5 handlerBinFile 路径穿越防护强化** — 新增绝对路径/反斜杠/null字节检查 + `filepath.Clean` 二次防护 + `HasPrefix` 验证
- **handleDeleteAgentBinary 自动 RebuildManifest** — 删除二进制后重建 manifest，防止已删二进制仍被推送
- **importPFXToIIS/importToIIS 返回 bool** — 支持 H5 条件写入 `.cert_hash`
- **心跳日志增加 IPv6** — `收到心跳` 日志从 `ipv4=xxx` 扩展到 `ipv4=xxx ipv6=xxx`
- **SMTP 密码保护** — `handleSaveSMTP` + `isMaskedPassword` 检测掩码值（全`****`/部分`PP****pY`），保留已有授权码不被覆盖
- **PFX 双格式全链路修复** — ① `UpdateCertMeta` 先生成双PFX再算hash（修复续签后不下发）② Agent Modern失败正确降级Legacy（修复Win2016 IIS导入失败）③ `handleDownloadPFX` 默认返回ZIP双格式+README
- **Logo 高清化** — 矢量源 2460×2468 RGBA 替换旧版，所有尺寸 LANCZOS 缩放
- **文档对齐** — `docs/架构与实现.md` 更新 Windows 升级流程、ACME续签后UpdateCertMeta说明、审计日志API补全、PFX双格式说明；`docs/前端设计.md` 更新日志API返回格式

#### 🐛 后续修复（v1.5.11 持续）

- **PFX 双格式全链路修复** — ① `UpdateCertMeta` 先生成双PFX再算hash（修复续签后不下发）② Agent Modern失败正确降级Legacy（修复Win2016 IIS导入失败）③ `handleDownloadPFX` 默认返回ZIP双格式+README ④ 前端检测Content-Type选扩展名
- **节点配置证书绑定下拉为空** — `cr.data.certs` → `cr.data`（API返回数组非对象）
- **证书绑定路径提示** — placeholder改为"部署路径 (Windows留空, Linux填实际路径)"，按钮下方增加灰色说明
- **节点名显示计算机名** — `normalizeNode` 改用用户自定义节点ID，计算机名移到系统列（hostname · OS / arch）
- **保存配置自动审批** — `handleSaveNodeConfig` 设置 `Approved=true`，编辑配置即审批
- **节点列表在线状态口径统一** — `handleListNodes` 新增超时检测（LastSeen>5min→DOWN），与仪表盘一致
- **DNSUpdater空配置明确报错** — 无配置时返回 `"等待管理端下发DNS配置（节点可能未审批）"`
- **StartAutoRenew增强** — 续签成功后记审计日志 + 重载bundle确保缓存一致

## v1.5.10 — 2026-05-12

### 🕐 时区一致性修复（6 项）

**问题**：日志/Web UI/邮件时间戳使用硬编码 UTC，不符合本地用户习惯。设置页时区选择器对日志展示、心跳时间戳、邮件时间未生效。

#### 🔴 Logger 事件时间标准化
- **事件存储统一 UTC** — `logEvent()` 使用 `time.Now().UTC()`，保证跨时区比较/排序正确
- **展示时区转换** — 新增 `DisplayTime(t)`/`FormatEventInTZ(e)` 方法，使用 `m.tz` 转换为配置时区
- **日志 API 转换** — `handleGetLogs` 返回事件前将 `time.Time` 从 UTC `In(tz)` 到配置时区，前端显示本地时间

#### 🟠 心跳/节点/证书时间戳
- **handlers_nodes.go** — `LastSeen`/`Timestamp`/`ConfigSentAt`/`UpgradeState.now` 从 `time.Now().UTC()` 改为 `s.nowInTZ()`
- **handlers_admin.go** — 节点注册 `CreatedAt`、DNS Key `UpdatedAt` 改用配置时区
- **handlers_certs.go** — ACME 账号 `Updated` 改用配置时区
- **cmd/manager/main.go** — ACME 引导时间戳改用配置时区

#### 🟡 时区同步链路完善
- **server.go** — 添加 `timezone` 缓存字段 + `GetTimezone()`/`SetTimezone()`/`nowInTZ()` 统一接口
- **handleSaveTimezone** — 调用 `s.SetTimezone(loc)` 同步更新 Server 缓存 + accessCollector + logger（此前仅更新 accessCollector）
- **handleSaveTimezone** — 同步刷新 SMTP 配置中的时区，确保邮件时间戳与设置一致
- **handleLogsCleanup** — 使用 Server 缓存的时区计算日期边界，消除重复 `LoadTimezoneConfig` 调用

#### 🔧 冗余消除
- 移除 `handleGetLogs` 和 `handleLogsCleanup` 中重复的 `LoadTimezoneConfig()` 调用，统一走 Server 缓存

#### 🧪 测试
- 新增 `TestTimezone_DisplayConversion` — UTC→CST 转换验证
- 新增 `TestTimezone_UTCStorage` — Logger UTC 存储验证
- 新增 `TestTimezone_BoundaryDST` — 夏令时边界跨时区转换
- 新增 `TestTimezone_RFC3339Formatting` — RFC3339 格式含时区偏移
- 新增 `TestTimezone_DefaultFallback` — 无配置时默认 Asia/Shanghai

### 🔧 自动升级修复（3 项）

#### 🔴 审批门控误拦升级
- **handlers_nodes.go** — 升级推送（仅含二进制 URL）移到审批门控之前，未审批节点也能接收升级
- 配置/证书推送仍在审批之后（含 DNS Key 等机密）

#### 🔴 升级闭包跨锁死锁
- **handlers_nodes.go** — `LoadAgentManifest()` 从 `UpdateAgentConfigAtomic` 闭包内移到闭包外，消除 `store.mu` Lock→RLock 同 goroutine 死锁

#### 🟠 升级完成标记不到达
- **handlers_nodes.go** — 完成标记移到版本匹配 `return` 之前（已升级节点走到版本匹配即 return，永远标记不了完成）
- 升级完成时增加 `[upgrade] 升级已完成` 日志

### 🎨 Web UI 修复（2 项）

#### 密码卡片对齐
- **设置页** — 密码输入框改为 2 列布局，两个输入框并排 flex，总宽与上方时区下拉框对齐，保存按钮对齐

#### 证书「更多」下拉裁切
- **`.card` overflow** — `hidden` → 移除，下拉菜单不再被卡片边界裁切
- **`toggleMore()`** — 增加视口检测，下方空间不足时自动向上展开

### 🔐 PFX 证书修复（2 项）

#### PFX 下载私钥检测
- **handleDownloadPFX** — 私钥检测从仅扩展名 `.key` → 扩展名 + 内容含 `PRIVATE KEY`（适配 acme.sh 输出的 `privkey.pem`）
- **handleUploadCert** — 上传时 PFX 自动生成同步修复
- **handleACMEIssue** — ACME 签发后 PFX 自动生成同步修复

#### PFX 缺失证书链
- **crypto/pkcs12.go** — 解析全部 PEM 块，叶子证书 + 中间 CA 链完整打包到 PFX
- Windows 导入后正确显示信任链（不再仅显示 `E7`）

### ⏱️ ACME 响应超时修复
- **cmd/manager/main.go** — `WriteTimeout: 30s → 120s`，acme.sh DNS-01 签发耗时 30-60s，响应必须在超时前写回

---

## v1.5.9 — 2026-05-12

### 🏗️ 激进重构（9 项全量审计修复 + 架构增强 + 版本管理完善）

#### 🏷️ 版本管理
- **侧边栏版本动态化** — `/api/ping` 新增 `version` 字段，WebUI 通过 `fetchSideVersion()` 拉取真实 Manager 版本，不再硬编码 HTML
- **版本传播链路** — VERSION 文件 → ldflags → Manager `/api/ping` + Agent 心跳，单一真相源

#### 🔴 Critical
- **C1 selfUpgrade 重试循环修复** — HTTP 非 200 错误由 `return` 改为 `continue`，每次迭代独立闭包确保 defer 零泄漏。修复 HTTP 5xx 时 3 次重试形同虚设的 bug

#### 🟠 High
- **H1 initACMEManagers 跨锁死锁修复** — 拆分为两阶段：阶段1持 `acmeMu` 构建 mgr 列表后释放，阶段2不持锁启动后台 goroutine，彻底消除 `acmeMu`→`store.mu` 与 `store.mu`→`acmeMu` 反序死锁
- **H2 handleSaveNodeConfig 错误处理** — `json.Marshal` 失败不再静默清空配置；返回 500 + 记录审计日志
- **H3 handleUploadAgentBinary 错误处理** — `Open()`/`ReadAll()` 失败跳过文件并记录警告日志；0 字节文件拒绝写入；上传后自动 `RebuildManifest()`

#### 🟡 Medium
- **M1 心跳 UpgradeState TOCTOU 消除** — 升级推送+完成标记改用 `UpdateAgentConfigAtomic` 持写锁原子更新，消除两个并发心跳互相覆盖的竞态
- **M2 版本号对比健壮化** — `compareVer` 从 `fmt.Sscanf` 改为 `strconv.Atoi` 严格解析，非数字段返回 0（不可比较）不再静默误判；支持更多段比较（非固定 3 段）
- **M3 handleDownloadInstaller ver 参数校验** — 最大 32 字符 + 特殊字符黑名单，防止超长/非法版本号
- **M4 collectCertHashes 超时保护** — 通过 goroutine+channel 实现 30s 超时，NFS 挂载卡住时不再永久阻塞心跳

#### 🟢 Low
- **L1 detectPlatform 架构归一化** — 新增 `x86_64`→`amd64`、`aarch64`→`arm64`、`armv6l/armv7l/armv8l/armhf`→`arm`、`i686/i386`→`i386` 映射，确保所有 deb 命名架构正确匹配 manifest

#### 🤖 测试
- `TestDetectPlatform_ArchNormalization` — 15 子测试覆盖 deb→Go 命名映射
- `TestCompareVer_SemanticComparison` — 20 子测试覆盖版本比较边界（v前缀/不等长/非数字/空值）
- `TestCompareVer_RealWorldVersions` — 6 子测试模拟实际心跳版本比较
- `TestSelfUpgradeRetryLoop_*` — 3 测试覆盖重试成功/全部失败/首次成功

---

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
- **全局输入框** — 38px → 34px，统一高度

#### 表格列宽标准化
- 所有表格 `table-layout:fixed` 固定列宽，不再随内容晃动
- 操作列统一 188px 左对齐
- DNS Keys: 名称/提供商/AccessKey 各 100px + AccessKey前6位+***脱敏
- 证书: 名称188px / 到期100px / 剩余90px
- ACME: Email188px / Key100px / 状态90px
- 仪表盘: 节点120px / IP域名各50%
- 节点管理: 节点名称120px / IP系统域名三等分
- 系统日志: 时间130px / 节点90px / 分类80px + 筛选框34px
- 已上传二进制: 大小80px / 版本80px
- 节点版本: 节点120px / 状态70px / 版本85px / 升级状态100px
- 版本管理: 强制版本/版本/系统下拉框34px

#### 🆕 时区设置
- **设置页时区选择器** — 15 个常用时区，默认 Asia/Shanghai
- **API** — `GET/POST /api/admin/timezone`
- **生效范围** — 仪表盘图表时间轴、流量统计时间桶

#### 🔧 修复
- **manifest 自动维护** — `RebuildManifest()` 上传/删除/启动三触发，扫描 `/bin/` 取最高版本
- **批量升级状态显示空** — `_upgState` API 调用前预填 pending
- **证书到期解析随机** — map 遍历改文件名排序
- **accessStats 递归死锁** — `record()`/`snapshot()` 持锁调 `nowInTZ()` 导致登录/注册/心跳全部超时，拆 `nowInTZLocked`

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
