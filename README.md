# ddns-manager v2

内嵌 [ddns-go](https://github.com/jeessy2/ddns-go) DNS 引擎的集中管理平台。Manager 统一管控 DNS Key、SSL 证书、Agent 版本，Agent 内嵌 ddns-go DNS provider 直接更新记录。

## 文档

| 文档 | 说明 |
|------|------|
| **[docs/架构与实现.md](docs/架构与实现.md)** | 后端架构与实现（数据模型、API、配置引擎、安全、部署） |
| **[docs/前端设计.md](docs/前端设计.md)** | Web 前端设计规范（布局、色彩、组件、API 对照） |
| **[CHANGELOG.md](CHANGELOG.md)** | 版本变更日志 |
| **[docs/audits/2026-05-10.md](docs/audits/2026-05-10.md)** | 全量代码审计报告 |

## 特性

- **集中管理** — Web 仪表盘统一查看节点状态、IP、版本、健康
- **配置推送** — DNS 配置 + Key 注入 → Agent 热加载
- **证书分发** — SSL 证书 AES-256-GCM 加密推送，Agent 自动部署
- **内嵌 DNS 引擎** — Agent 同进程运行 ddns-go DNS provider
- **跨平台** — Linux (systemd) + Windows 7+ (Windows Service)
- **版本管理** — Git tag 驱动 + 符号链接安装 + 一键回滚

## 快速开始

```bash
# 构建
VERSION=$(cat VERSION) bash scripts/build.sh

# 部署管理端
scp build/ddns-manager-linux-amd64 user@server:/opt/ddns-manager/
ssh user@server "systemctl restart ddns-manager"

# 部署节点 (一键安装)
curl -fsSL https://MANAGER:9877/bin/install.sh | sh -s -- -m https://MANAGER:9877 -n my-node
```

## 技术栈

- Go 1.25+ / gorilla/mux / ddns-go v6
- 单文件 SPA (go:embed)
- JSON 文件持久化 / AES-256-GCM 加密 / HKDF-SHA256 密钥派生
- ACME (Let's Encrypt / ZeroSSL / Google Trust) / SMTP 邮件通知

> **当前版本**: v1.5.8 — 独立 git repo + git tag + 7 项全量审计修复
