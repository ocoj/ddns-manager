# ddns-manager 文档

> 公开文档入口。内部开发文档见 `internal-docs/`（本地查看）。

## 快速导航

| 文档 | 说明 |
|------|------|
| [使用说明书](usage-guide.md) | 完整部署与使用指南 |
| [部署指南](deployment-guide.html) | 部署架构与运维参考 |
| [图标资源](图标/) | 系统图标库 |

## 项目概述

ddns-manager 是一个 DDNS 集中管理平台，内嵌 [ddns-go](https://github.com/jeessy2/ddns-go) DNS 引擎。

**核心功能**：

- **DNS Key 管理** — 统一管理阿里云、Cloudflare 等多平台 DNS 密钥
- **SSL 证书** — ACME 自动签发，AES-256-GCM 加密分发至 Agent
- **Agent 管理** — 节点注册、心跳监控、版本推送、一键升级
- **Web 仪表盘** — SPA 单页应用，响应式设计，支持 PWA

**技术栈**：Go 1.25+ / gorilla/mux / ddns-go v6.17.4 / 单文件 SPA / JSON 持久化
