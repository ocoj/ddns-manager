# ddns-manager v2

内嵌 [ddns-go](https://github.com/jeessy2/ddns-go) DNS 引擎的集中管理平台。Manager 统一管控 DNS Key、SSL 证书、Agent 版本，Agent 内嵌 ddns-go DNS provider 直接更新记录（无独立进程）。

## 文档

- **[DESIGN-v2.md](DESIGN-v2.md)** — 后端架构与实现（唯一真相源，含目录、数据模型、API、安全、部署）
- **[docs/WEBUI-DESIGN.md](docs/WEBUI-DESIGN.md)** — Web 前端设计规范（含布局、色彩、组件、API 对照）
- **[CHANGELOG.md](CHANGELOG.md)** — 版本变更日志

## 特性

- **集中管理** — Web 仪表盘统一查看所有节点状态、IP、版本、健康
- **配置推送** — DNS 配置 + Key 注入 → Agent 热加载，无需写盘重启
- **证书分发** — SSL 证书 AES-256-GCM 加密后推送，Agent 自动部署
- **双因子认证** — 密码 + 系统指纹(hostname+machine-id)双重校验
- **内嵌 DNS 引擎** — Agent 同进程运行 ddns-go DNS provider，无需管理独立二进制
- **跨平台** — Linux (systemd) + Windows 7+ (Windows Service)

## 快速开始

### 管理端

```bash
# 下载二进制
curl -L https://github.com/you/ddns-manager/releases/latest/download/ddns-manager-linux-amd64 -o /usr/local/bin/ddns-manager
chmod +x /usr/local/bin/ddns-manager

# 初始化
ddns-manager -l :9877 -data-dir /opt/ddns-manager/data

# 安装为服务
ddns-manager service install
```

打开 `https://your-server:9877` 登录管理面板（默认密码 Admin12345）。

### 节点端

```bash
# 方法1: 一键安装脚本 (推荐)
curl -fsSL https://manager:9877/bin/install.sh | sh -s -- -m https://manager:9877 -n node-01

# 方法2: 手动下载安装器
curl -o /tmp/installer https://manager:9877/bin/ddns-installer-linux-amd64
chmod +x /tmp/installer && /tmp/installer -manager-url https://manager:9877 -name node-01

# 安装目录: /opt/ddns-manager/
# 卸载: ddns-installer -uninstall
```

## 架构

详见 [DESIGN-v2.md](DESIGN-v2.md)。

```
Manager (管理端 :9877)              Node Agents (各服务器)
┌──────────────────────┐           ┌──────────────────────┐
│ Web UI (SPA)          │◄─────────│ node-01 (Linux)       │
│ REST API              │  HTTPS   │  ┌──────────────────┐│
│ 配置引擎              │  心跳     │  │ DNSUpdater       ││
│  └─ JSON→YAML 渲染    │           │  │ (内嵌ddns-go)    ││
│ Cert Store            │           │  │ IP检测→DNS API   ││
│ DNS Key Vault         │           │  ├──────────────────┤│
└──────────────────────┘           │  │ Cert Deploy      ││
                                    │  │ Self Upgrade     ││
                                    │  └──────────────────┘│
                                    └──────────────────────┘
```

## API

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/heartbeat` | 节点心跳 (认证+配置下发) |
| POST | `/api/register` | 节点注册 |
| GET | `/api/ping` | 健康检查 |
| GET | `/api/admin/nodes` | 节点列表 |
| POST | `/api/admin/nodes/:id/approve` | 审批节点 |
| PUT | `/api/admin/nodes/:id/config` | 保存节点配置 |
| DELETE | `/api/admin/nodes/:id` | 删除节点 |
| GET/POST | `/api/admin/dns-keys` | DNS Key 管理 |
| GET/POST/DELETE | `/api/admin/certs` | 证书管理 |
| POST | `/api/admin/acme/issue` | ACME 签发证书 |

完整 API 列表见 [WEBUI-DESIGN.md §8](docs/WEBUI-DESIGN.md#8-api-端点)。

## 安全

- **认证**: Bearer Token (node_id:password base64) + bcrypt 持久化
- **指纹**: SHA256(hostname + machine-id) 双重校验
- **加密**: AES-256-GCM, 密钥=HKDF-SHA256(password+fingerprint+purpose) 域分离 (RFC 5869)
- **传输**: HTTPS + 应用层加密双重保护
- **管理端**: bcrypt 哈希，constant-time 比对

## 项目结构

```
ddns-manager/
├── cmd/manager/main.go        # 管理端
├── cmd/agent/                 # 节点端
│   ├── main.go                #   心跳+配置缓存+自升级
│   ├── dns_updater.go         #   内嵌DNS引擎 (ddns-go)
│   ├── svc_windows.go         #   Windows Service
│   ├── upgrade_linux.go       #   Linux 自升级
│   ├── upgrade_windows.go     #   Windows 自升级
│   └── dns_updater_test.go    #   DNS 引擎测试
├── cmd/installer/main.go      # 交互式安装向导
├── internal/
│   ├── model/model.go         #   数据模型
│   ├── server/                #   REST API (7 文件)
│   ├── store/store.go         #   文件存储 (JSON + 二进制)
│   ├── config/config.go       #   配置加载
│   ├── crypto/aes.go          #   AES-256-GCM 加密
│   ├── acme/acme.go           #   ACME 证书管理
│   ├── logger/logger.go       #   审计日志
│   ├── sysinfo/               #   系统资源采集
│   └── notify/notify.go       #   邮件通知
├── scripts/build.sh           #   跨平台构建
├── docs/WEBUI-DESIGN.md       #   Web UI 设计文档
├── DESIGN-v2.md               #   架构设计文档
├── CHANGELOG.md               #   变更日志
└── README.md                  #   本文件
```

## 构建

```bash
VERSION=v2.x.x bash scripts/build.sh
# 输出: build/
#   ddns-manager-linux-amd64
#   node-agent-linux-amd64, node-agent-linux-arm64
#   node-agent-windows-amd64.exe
#   ddns-installer-linux-amd64
```

---

> **当前版本**: v1.5.2 — 全量审计 21 项修复 + 版本管理自动化 + 页面隔离状态管理器 + 流量持久化 + Web UI 增强
