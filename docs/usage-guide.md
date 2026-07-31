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

# 2. 部署到目标服务器
DEPLOY_HOST=10.0.0.1 DEPLOY_USER=admin bash scripts/release.sh

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

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now ddns-manager
```

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
