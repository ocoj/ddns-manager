# ddns-manager v2

内嵌 [ddns-go](https://github.com/jeessy2/ddns-go) DNS 引擎的集中管理平台。Manager 统一管控 DNS Key、SSL 证书、Agent 版本，Agent 内嵌 ddns-go DNS provider 直接更新记录。

## 📚 文档索引

| 文档 | 说明 |
|------|------|
| **[变更日志](CHANGELOG.md)** | 版本变更日志 |

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
bash scripts/build.sh

# 一键部署到管理端（构建物检查 → 清理旧版 → 上传 → 校验）
bash scripts/deploy.sh

# 部署节点 (一键安装)
bash -c "$(curl -fsSL https://your-manager.example.com:30443/bin/install.sh)"
```

## 技术栈

- Go 1.25+ / gorilla/mux / ddns-go v6.17.0
- 单文件 SPA (go:embed) + PWA 支持
- JSON 文件持久化 / AES-256-GCM 加密 / HKDF-SHA256 密钥派生
- PKCS#12 PFX 证书生成 (go-pkcs12, 纯 Go)
- ACME (Let's Encrypt / ZeroSSL / Google Trust) / acme.sh + 纯 Go 双路径
- SMTP 邮件通知 / YAML 配置解析 (gopkg.in/yaml.v3)
- 跨平台 systemd/Windows Service 集成 (golang.org/x/sys)

## 版本

| 项目 | 版本号 | 说明 |
|------|--------|------|
| ddns-manager | **v1.6.56** | 全量安全审计 + 16 项修复 |
| 安装器 | **v1.0.0** | 独立版本，与 Agent 解耦 |
| ddns-go (内嵌) | v6.17.0 | DNS provider library |

> **注意**: 本项目处于开发测试阶段，从未正式发布。v1、v2 仅为开发过程中的自然版本演进标识。部署更新时需全新部署，不保证与旧版本数据格式兼容。
