# ddns-manager 使用说明书

> **版本**: v1.6.59  
> **适用**: Manager + Agent 全平台部署与运维

---

## 目录

1. [系统概述](#1-系统概述)
2. [部署 Manager](#2-部署-manager)
3. [Web 管理后台](#3-web-管理后台)
4. [DNS Key 管理](#4-dns-key-管理)
5. [Agent 节点管理](#5-agent-节点管理)
6. [DDNS 配置](#6-ddns-配置)
7. [SSL 证书管理](#7-ssl-证书管理)
8. [版本管理](#8-版本管理)
9. [SMTP 邮件通知](#9-smtp-邮件通知)
10. [日志与监控](#10-日志与监控)
11. [系统设置](#11-系统设置)
12. [常见问题](#12-常见问题)

---

## 1. 系统概述

ddns-manager 采用 **Manager + Agent** 架构：

```
┌─────────────────────────────────────────────┐
│           Manager (管理端 :9877)               │
│  Web UI │ REST API │ 配置引擎 │ 持久化       │
└────────────────┬────────────────────────────┘
                 │ HTTPS + Bearer Token
                 │ 每 5 分钟心跳
    ┌────────────┼────────────┐
    ▼            ▼            ▼
┌────────┐  ┌────────┐  ┌────────┐
│ Agent  │  │ Agent  │  │ Agent  │
│ Linux  │  │  Win   │  │  ...   │
└────────┘  └────────┘  └────────┘
```

**Manager** 负责：
- Web 管理后台（单页应用 SPA）
- 存储 DNS Key / 节点信息 / 证书
- 响应 Agent 心跳，下发配置、证书、升级指令

**Agent** 负责：
- 内嵌 ddns-go DNS provider 库（支持 32+ DNS 平台）
- 定时上报心跳（每 5 分钟）
- 按 Manager 下发的配置执行 DDNS 更新
- 接收并部署 SSL 证书
- 自升级（接收 Manager 推送的版本号）

---

## 2. 部署 Manager

### 2.1 Docker 部署（推荐）

```bash
# 拉取镜像
docker pull ghcr.io/ocoj/ddns-manager:1.6.59

# 启动
docker run -d \
  --name ddns-manager \
  -p 9877:9877 \
  -v /opt/ddns-manager/data:/data \
  ghcr.io/ocoj/ddns-manager:1.6.59

# 查看日志
docker logs -f ddns-manager
```

**端口说明**：
- `9877` — Manager Web UI + Agent API（必开）

### 2.2 手动部署

```bash
# 1. 构建二进制
bash scripts/build.sh

# 2. 部署到目标服务器（示例，请替换为实际地址）
DEPLOY_HOST=192.0.2.1 DEPLOY_USER=your-username bash scripts/release.sh

# 3. 创建 systemd 服务（示例）
sudo tee /etc/systemd/system/ddns-manager.service << 'EOF'
[Unit]
Description=ddns-manager
After=network.target

[Service]
Type=simple
ExecStart=/opt/ddns-manager/ddns-manager -data-dir /opt/ddns-manager/data
Restart=always
RestartSec=10
# ⚠️ 必须显式提供这两项（见 §2.4 "acme.sh 安装与 home 约定"）：
#    systemd 默认不设置 HOME ⇒ acme.sh 会把自己的 home 推导成 /.acme.sh，
#    导致证书续期时"找不到既有配置"并在非预期目录写入凭据。
Environment=HOME=/root
Environment=LE_WORKING_DIR=/root/.acme.sh

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now ddns-manager
```

### 2.4 acme.sh 安装与 home 约定

Manager 通过调用 **acme.sh**（同进程外的独立脚本）完成证书签发与续期，因此必须让
Manager 与 acme.sh 对"home 目录"有完全一致的认识。

#### 为什么必须显式指定

acme.sh 以 `$HOME/.acme.sh` **推导**自己的 home。systemd 服务默认**不设置** `HOME`，
于是 home 会变成 `/.acme.sh`：

- acme.sh 读不到既有域名的配置 ⇒ 续期时报"安装到 `<bundle 之外的目录>` 失败"；
- 更严重：acme.sh 会在该目录创建 `account.conf` 并写入**明文 DNS 凭据**。

Manager 自身也做了防护（代码会显式固定 home，缺失 `HOME` 时自动补为 home 的父目录，
并在无法确定 home 时**拒绝执行** acme.sh），但**部署层仍应显式声明**，二者构成纵深防御。

#### 推荐配置

```ini
# /etc/systemd/system/ddns-manager.service 的 [Service] 段
Environment=HOME=/root
Environment=LE_WORKING_DIR=/root/.acme.sh
```

- `LE_WORKING_DIR` 是 acme.sh v3.1.4 实际读取的变量（**不是** `ACME_HOME`）。
- 自定义安装位置时，把 `LE_WORKING_DIR` 指向该 home，并在 `manager.yaml` 中同步
  `cert.provider`（见下）。

#### `cert.provider` 的语义

```yaml
cert:
  provider: /usr/local/bin/acme.sh   # acme.sh 可执行文件的路径（绝对路径）
```

- 该值**优先**于 `PATH` 查找；若路径不存在/不可执行，会回退 `PATH` 查找并记录告警。
- 留空则不读取配置，直接使用 `PATH` 查找。
- 注意：该值指向**可执行文件**，其 home 由 Manager 依序解析
  （`LE_WORKING_DIR` → 解析符号链接后的脚本所在目录 → `$HOME/.acme.sh`），
  并要求目标目录是**已初始化的 acme home**（含 `account.conf` 或 `ca/`）。

#### 自检与排错

- 启动时会在事件日志中输出 `[acme] ACME home 已固定: <路径>` 与逐候选的解析轨迹；
- 若出现 `acme.sh home 解析失败（已拒绝执行 acme.sh）`，说明所有候选都不可用
  —— 此时**不会有任何 acme.sh 调用被发出**（fail-fast，属保护行为），
  请按提示的候选解析结果修正 `LE_WORKING_DIR` / `cert.provider` / `HOME`。
- **排查入口（推荐）**：

  ```bash
  journalctl -u ddns-manager | grep -E "home 解析|ACME home"   # 逐候选轨迹 + 最终固定值
  systemctl show ddns-manager -p Environment                   # 是否已显式声明 LE_WORKING_DIR
  ```

  期望看到 `ACME home 已固定: <路径>`。若轨迹显示的是 `[binary-dir]`（**启发式**）而非
  `[env:LE_WORKING_DIR]`（**显式**），说明未显式声明：该启发式依赖「`cert.provider` 指向的脚本路径
  **能解析到真实 home**」，一旦该脚本被替换为 wrapper／多级软链，解析即失败并 **fail-fast**
  ⇒ **生产环境建议显式声明**（见上文"推荐配置"），以获得确定性与可观测性。
- 不要手工执行 `acme.sh --renew` 来"绕过"本管理端：手工执行缺少 Manager 注入的
  DNS 凭据，会与 `account.conf` 中保存的历史凭据混用，产生难以排查的问题。

#### 2.4.1 运维约束（P7 / R-E：home 的落点必须可信）

ACME home 是 acme.sh 存放**账号凭据（`account.conf`，含 DNS/CA 密钥）与证书**的目录。
Manager 启动时会按 §2.4 顺序解析 home，并对候选做**位置体检**：

| 形态 | 判据 | 结果 |
|---|---|---|
| 路径层含**他人所有**符号链接 | `Lstat` 逐层 + `uid ≠ 本进程` | **拒绝**（防凭据写入他人可控路径） |
| 路径层含**自有**符号链接、且**解析后**落在公共可写前缀（`/tmp`、`/var/tmp`、`/dev/shm`、`/run`） | `EvalSymlinks` 结果前缀命中 | **拒绝**（显式来源）/ 跳过（启发式来源） |
| **字面**路径落在公共可写前缀 | 前缀比对 | 采用 + **强告警**（`/tmp` 类目录通常 sticky，风险受限） |
| 祖先目录对 group/other 可写 | 逐层 `mode & 0o022` | **仅显式来源**附加强告警（不改判定） |

**运维要求**：不要把 ACME home（或指向它的符号链接）放在公共可写目录；推荐本例：

```
/root/.acme.sh            属主 root、0700、无符号链接
/root/.acme.sh/ca/        账号与 CA 数据（acme.sh 自动创建）
/root/.acme.sh/account.conf  600，含 SAVED_* 凭据
```

> 若必须放在自定义路径（如 `/opt/acme/.acme.sh`），请确保：目录属主为本进程、`0700`、
> 祖先链无可被同组替换的层，并通过 `LE_WORKING_DIR`（**显式来源**）指定。

### 2.3 首次登录

打开浏览器访问 `http://<服务器IP>:9877`，使用默认密码登录：

```
密码: Admin12345
```

> ⚠️ **请立即修改密码**：登录后进入"系统设置" → 修改管理员密码。

---

## 3. Web 管理后台

### 3.1 界面总览

登录后主界面包含：

| 区域 | 说明 |
|------|------|
| **仪表盘** | 节点总数、在线/离线状态、最近事件 |
| **节点管理** | 节点列表、心跳状态、IP、版本 |
| **DNS 管理** | DNS Key 增删、DDNS 配置、域名管理 |
| **证书管理** | SSL 证书列表、签发、续期、部署 |
| **日志** | 事件日志列表、按类型/时间筛选 |
| **版本管理** | Agent 版本推送、强制版本设置 |
| **系统设置** | 密码修改、SMTP 配置、服务管理 |

### 3.2 导航

左侧栏提供所有功能入口，点击展开子菜单。移动端会自动收缩为汉堡菜单。

---

## 4. DNS Key 管理

### 4.1 添加 DNS Key

支持以下 DNS 平台（完整列表见 ddns-go 文档）：

**阿里云**：
```
AccessKey ID: xxxxxxxxxxxxxxxx
AccessKey Secret: xxxxxxxxxxxxxxxxxxxxxxxx
```

**Cloudflare**：
```
API Token: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**其他平台**：参考各平台 API Key 获取方式。

### 4.2 操作步骤

1. 进入 **DNS 管理** → **DNS Key**
2. 点击 **[+ 添加]**
3. 选择 DNS 平台
4. 填写 Key 信息
5. 点击 **[测试]** 按钮验证 Key 可用性
6. 保存

### 4.3 测试功能

每个 DNS Key 提供 **[测试]** 按钮，会调用真实 API 验证：
- 是否可正常认证
- 是否有域名管理权限
- 返回可用域名列表

---

## 5. Agent 节点管理

### 5.1 一键安装 Agent

在 **节点管理** 页面点击 **[+ 注册节点]**，获取安装命令：

```bash
# Linux
bash -c "$(curl -fsSL https://manager.example.com:30443/bin/install.sh)"

# Windows（以管理员身份运行 PowerShell）
. { iwr -UseBasicParsing https://manager.example.com:30443/bin/install.bat } | iex
```

安装脚本自动完成：
1. 下载对应平台 Agent 二进制
2. 生成节点指纹（设备唯一标识）
3. 自动注册到 Manager
4. 创建 systemd 服务（Linux）或 Windows Service（Windows）

### 5.2 节点状态

| 状态 | 含义 |
|------|------|
| 🟢 在线 | 最近 5 分钟内有心跳 |
| 🔴 离线 | 超过 5 分钟无心跳 |
| 🟡 待审批 | 新注册，等待管理员批准 |

### 5.3 节点详情

点击节点名称查看详情：
- **基本信息**：主机名、操作系统、IP 地址（IPv4/IPv6）
- **版本信息**：当前 Agent 版本、已运行时间
- **证书状态**：当前部署的证书列表、有效期
- **DDNS 状态**：DNS 更新记录、成功/失败次数

### 5.4 管理操作

- **批准/拒绝**：首次注册的节点需要管理员审批
- **推送版本**：在"版本管理"中设置强制版本后自动推送
- **推送证书**：签发证书后选择目标节点推送
- **下线处理**：节点离线或重置后自动清理旧凭据

---

## 6. DDNS 配置

### 6.1 配置流程

1. **添加 DNS Key**（见第 4 章）
2. **进入 DNS 管理** → **域名配置**
3. 选择 DNS Key
4. 添加需要动态解析的域名
5. 选择获取 IP 的方式

### 6.2 IP 获取方式

| 方式 | 说明 | 适用场景 |
|------|------|----------|
| **网卡获取** | 从指定网卡读取 IPv4/IPv6 | 有公网 IP 的设备 |
| **在线获取** | 通过 HTTP API 获取出口 IP | 内网 NAT 环境 |
| **手动输入** | 手动指定 IP 地址 | 固定 IP 场景 |

### 6.3 IPv6 支持

支持以下 IPv6 获取方式：
- 网卡 IPv6 地址
- 在线 IPv6 检测 API
- IPv6 前缀 + MAC 地址组合（EUI-64）

---

## 7. SSL 证书管理

### 7.1 ACME 证书签发

支持以下 ACME CA：

| CA | 说明 |
|----|------|
| **Let's Encrypt** | 免费，90 天有效期（推荐） |
| **ZeroSSL** | 免费/付费，90 天 |
| **Google Trust** | 免费，90 天 |

**签发步骤**：

1. 进入 **证书管理** → **ACME 账户**
2. 创建 ACME 账户（输入邮箱 + 选择 CA + 密钥类型 EC256/RSA2048）
3. 进入 **证书管理** → **[+ 签发证书]**
4. 选择 DNS Key（用于 DNS-01 验证）
5. 添加域名（支持通配符 `*.example.com`）
6. 点击签发
7. Manager 自动完成 DNS-01 验证 → 签发 → 保存证书

### 7.2 证书部署

签发成功后，将证书部署到 Agent 节点：

1. 在证书列表点击 **部署**（或自动部署）
2. 选择目标节点
3. Manager 加密证书 → 通过心跳下发 → Agent 自动部署到指定路径

**PFX 导出**：支持导出为 PKCS#12 PFX 格式，用于 IIS 等 Windows 服务。默认密码 `ddns`。

### 7.3 自动续期

- 证书到期前 30 天自动触发续期
- 续期成功后自动推送至所有已部署节点
- 无需手动干预

### 7.4 证书查看

证书详情页显示：
- 域名列表
- 签发时间 / 到期时间
- 部署状态（已部署节点列表）
- 证书链 / 指纹

---

## 8. 版本管理

### 8.1 Agent 版本推送

Manager 可以统一管理所有 Agent 的版本：

1. 进入 **版本管理**
2. 设置 **强制版本**（如 `1.6.59`）
3. Manager 在下一次心跳时将版本号下发给 Agent
4. Agent 自动下载新版本、校验 SHA256、替换二进制、重启

**升级流程**：
```
Manager 设强制版本 → Agent 心跳时收到 → 下载新二进制
→ SHA256 校验 → 替换旧文件 → 重启 → 汇报新版本号
```

### 8.2 回滚

Agent 使用**符号链接安装**机制，旧版本保留在本地：
```bash
# 手动回滚示例
ln -sf /opt/ddns-agent/node-agent-v1.6.35 /opt/ddns-agent/node-agent
systemctl restart ddns-agent
```

---

## 9. SMTP 邮件通知

### 9.1 配置

进入 **系统设置** → **SMTP 配置**：

| 字段 | 说明 |
|------|------|
| SMTP 服务器 | 如 `smtp.example.com` |
| 端口 | 通常 587（TLS）或 465（SSL） |
| 用户名 | SMTP 登录用户名 |
| 密码 | SMTP 登录密码 |
| 收件人 | 通知接收邮箱 |

### 9.2 通知类型

| 事件 | 触发条件 |
|------|----------|
| 节点离线 | Agent 超过 5 分钟无心跳 |
| 节点上线 | 离线节点恢复心跳 |
| 证书即将到期 | 证书剩余有效期 < 30 天 |
| 证书续期成功/失败 | 自动续期结果 |
| DNS 更新失败 | DNS provider API 异常 |

---

## 10. 日志与监控

### 10.1 事件日志

**日志** 页面展示系统事件：

- 节点注册 / 上线 / 离线
- 证书签发 / 续期 / 部署
- DNS 更新成功 / 失败
- 配置变更
- 错误告警

支持按**时间范围**和**事件类型**筛选。

### 10.2 仪表盘监控

主仪表盘提供：

- **节点概览**：在线/离线/总数
- **最近事件**：最新 20 条事件流
- **证书状态**：即将到期的证书预警

---

## 11. 系统设置

### 11.1 修改密码

**系统设置** → **修改密码** → 输入旧密码 + 新密码 → 保存。

> 密码使用 bcrypt 哈希存储，不可逆。

### 11.2 服务管理

在 **系统设置** 中可进行：

- **重启服务**：重启 Manager 进程
- **备份数据**：导出 `data/` 目录
- **NPM 受信代理**：配置 Nginx Proxy Manager 反代时，设置受信代理 IP（Manager 将从 `X-Forwarded-For` 头获取真实客户端 IP）

### 11.3 暗色模式

Web 界面支持三种外观模式（**系统设置** → **外观**）：
- 自动（跟随系统）
- 明亮
- 暗色

---

## 12. 常见问题

### Q: Agent 安装后一直显示"待审批"

进入 **节点管理**，点击新节点 → **[批准]**。首次注册需要管理员手动审批。

### Q: DNS 更新失败

1. 检查 DNS Key 是否有效（点击 [测试] 按钮）
2. 确认域名在 DNS Key 对应平台的管理范围内
3. 查看日志页面中的具体错误信息

### Q: 证书续期失败

1. 确认 DNS Key 有效且域名在管理范围内
2. 确认 ACME 账户状态正常
3. 查看日志获取具体错误（常见：ACME API 限频、DNS 验证超时）

### Q: 如何修改 Manager 端口

启动参数指定：
```bash
ddns-manager -port 8080 -data-dir /data
```

### Q: 数据如何备份

备份 `data/` 目录即可：
```bash
tar czf ddns-backup-$(date +%Y%m%d).tar.gz /opt/ddns-manager/data/
```

恢复：
```bash
tar xzf ddns-backup-20260731.tar.gz -C /opt/ddns-manager/
docker restart ddns-manager
```

### Q: 忘记管理员密码

删除 `data/admin.json` 后重启 Manager，将重新生成默认密码 `Admin12345`。

```bash
rm /opt/ddns-manager/data/admin.json
docker restart ddns-manager
# 然后立即登录修改密码
```

---

## 附录 A. 证书退役流程（P8）

退役一张证书（不再签发/分发/续期）请**按序**执行，避免节点上残留旧证书：

| 步 | 动作 | 说明 |
|:--:|---|---|
| **1** | 在节点侧**解除绑定** | IIS/nginx 等先切到新证书，确认新证书生效（浏览器/`certutil` 指纹核对） |
| **2** | **手动删除证书 bundle** | ⚠️ **ACME 托管的证书不能用 UI/API 删除**（删除接口按设计**无条件拒绝**：返回 `不能删除 ACME 管理的证书`）。手动路径：**(a) 先做引用检查** —— `data/nodes.json`（各节点 `cert_bindings`）、`dns_keys.json`、`agent_config.json`+`agent_manifest.json` 中**均无**该 bundle；**(b)** 删除 `data/certs/acme-<主域名>/` 目录 |
| **3** | 清理 acme.sh 侧残留 | **先打印当前生效 home**（见 §2.4：`journalctl -u ddns-manager \| grep "home 解析"`，或直接读 `LE_WORKING_DIR`），再用**同一个** home 执行 `acme.sh --remove -d <主域名>`；确认 **`$LE_WORKING_DIR/<主域名>_ecc/`** 已移除。**不要把路径写死为 `~/.acme.sh`**（home 可能被显式指定到别处） |
| **4** | **删除后跟进（观察一次续期 tick 与推送）** | 期望：**仅一条预期审计**（如 `自动续期`/`无到期证书`）、**无 error 级噪音**、推送日志中无该 bundle 报错。出现 error ⇒ 回到第 2 步复查引用检查是否漏项 |

**两种删除保护（勿混淆）**：

- **绑定保护（400，可解绑后删）**：bundle 仍绑定到节点 ⇒ 返回 400 并拒绝删除 ⇒ **先做第 1 步**，
  避免"节点仍在用、中心已删"的悬空状态；
- **ACME 托管保护（一律拒绝）**：`acme-` 前缀的 ACME 托管证书 ⇒ 删除接口在**任何绑定检查之前无条件拒绝**
  ⇒ **只能走第 2 步的手动路径**（旧版本文档曾写"UI 删除"，对 ACME 证书**不可行**）。

**退役前自检**：`acme.sh --list` 应不再列出该域名；`certs/acme-<域名>/` 目录应不存在；
**`$LE_WORKING_DIR/<主域名>_ecc/`** 应不存在；节点上报的 `status.cert_hashes` 中不再含该 bundle 的哈希。


---

## 附录 B. 为什么会出现「PEM 与 PFX 不同源」（G-1 结论）

**结论**：本项目历史上存在**两个并行的 acme home**，外部 acme.sh 会把新证书装到其中一个、
而 Manager 从另一个读取 ⇒ 同一 bundle 内 `fullchain.pem`（新）与 `cert.pfx`（旧）**不是同一张证书**，
进而把**旧证书**推送到节点（IIS 重新绑定旧证书）。

**取证要点**（只读取证，未输出任何凭据值）：

- 孤儿 home（`/.acme.sh`，已退役）在 **≥2026-05-09 至 2026-09-16** 期间被实际使用；
  其中 `*.lanxun.pro` / `*.noxen.pro` / `oof.noxen.pro` 于 **2026-07-16** 在该 home 内签发并安装
  ⇒ 与历史「PEM 于 7-16 被外部写入」的观测**吻合**，即**外部写入者的来源**。
- 另有一组「已轮换但未禁用」的旧 DNS 凭据残留在该 home 的 `account.conf` 中，是续期失败（`InvalidAccessKeyId.Inactive`）的直接原因。

**Manager 的自愈与检测（v1.6.70+）**：

1. **审计信号**：一致性巡检在 `detail` 中标注「**疑似外部写入（PEM/PFX 不同源）**」⇒ 可据此定位外部写入者；
2. **推送前自愈**（S9）：推送前判定四路（`fullchain.pem`/`cert.pem`/`cert.pfx`/`cert-modern.pfx`）叶证书是否同源，
   不同源则**按磁盘 `fullchain.pem` 重建双 PFX** 后再推送（避免把旧证书推出去）；
3. **安装路径固定**（R3/R4）：签发后统一 `--install-cert` 到 **bundle 目录**，并让 acme.sh 的 home **显式固定**，
   避免"签发写 home A、续期读 home B"；
4. **凭据按调用注入**（R1）：DNS 凭据不再依赖 `account.conf` 中的历史值，而是**每次调用注入**。

**运维建议**：只保留**一个** acme home；若曾存在第二 home，按附录 A 流程退役其域名并清理目录；
证书类异常优先看 `events.log` 中的「证书一致性」与「疑似外部写入」两条线索。
