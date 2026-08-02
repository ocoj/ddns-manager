<div align="center" style="background:linear-gradient(135deg,#6366f1 0%,#38bdf8 100%);border-radius:18px;padding:36px 24px 26px;margin:0 0 22px;">
  <img src="docs/logo.png" alt="DDNS-Manager Logo" width="110" style="border-radius:22px;box-shadow:0 10px 30px rgba(15,23,42,.25);"/>
  <h1 style="color:#ffffff;font-size:2.4em;margin:.5em 0 .2em;">DDNS-Manager</h1>
  <p style="color:#eef2ff;font-size:1.1em;margin:0 0 .3em;">内嵌 <a href="https://github.com/jeessy2/ddns-go" style="color:#ffffff;font-weight:600;">ddns-go</a> DNS 引擎的集中管理平台</p>
  <p style="color:#e0e7ff;margin:0;">统一管控 <b>DNS Key</b> · <b>SSL 证书</b> · <b>Agent 版本</b></p>
  <p style="margin:18px 0 0;">
    <a href="https://github.com/ocoj/ddns-manager/releases"><img src="https://img.shields.io/github/v/release/ocoj/ddns-manager?style=for-the-badge&color=4f46e5" alt="Version"/></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPLv3-for_the_badge?style=for-the-badge&color=0ea5e9" alt="License"/></a>
    <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.25%2B-for_the_badge?style=for-the-badge&color=14b8a6" alt="Go"/></a>
    <a href="https://github.com/ocoj/ddns-manager/actions"><img src="https://img.shields.io/github/actions/workflow/status/ocoj/ddns-manager/build.yml?branch=main&style=for-the-badge&color=22d3ee" alt="CI"/></a>
  </p>
</div>

<h2 style="color:#4f46e5;border-bottom:3px solid #c7d2fe;padding-bottom:8px;">📖 简介</h2>

Manager 集中管控 DNS Key、SSL 证书与 Agent 版本；Agent 内嵌 ddns-go DNS provider 直接更新 DNS 记录，实现分布式 DDNS 集中管理。

<h2 style="color:#0284c7;border-bottom:3px solid #bae6fd;padding-bottom:8px;">📚 文档索引</h2>

| 文档 | 说明 |
|------|------|
| **[变更日志](CHANGELOG.md)** | 版本变更日志 |

<h2 style="color:#7c3aed;border-bottom:3px solid #ddd6fe;padding-bottom:8px;">✨ 特性</h2>

<table>
  <tr>
    <td align="center" style="background:#eef2ff;border:2px solid #c7d2fe;border-radius:14px;padding:18px 14px;"><b style="font-size:1.05em;">🗂️ 集中管理</b><br/><span style="color:#475569;font-size:.9em;">Web 仪表盘统一查看节点状态、IP、版本、健康</span></td>
    <td align="center" style="background:#ecfeff;border:2px solid #a5f3fc;border-radius:14px;padding:18px 14px;"><b style="font-size:1.05em;">📡 配置推送</b><br/><span style="color:#475569;font-size:.9em;">DNS 配置 + Key 注入 → Agent 热加载</span></td>
  </tr>
  <tr>
    <td align="center" style="background:#f5f3ff;border:2px solid #ddd6fe;border-radius:14px;padding:18px 14px;"><b style="font-size:1.05em;">🔐 证书分发</b><br/><span style="color:#475569;font-size:.9em;">SSL 证书 AES-256-GCM 加密推送，Agent 自动部署</span></td>
    <td align="center" style="background:#fff7ed;border:2px solid #fed7aa;border-radius:14px;padding:18px 14px;"><b style="font-size:1.05em;">⚙️ 内嵌 DNS 引擎</b><br/><span style="color:#475569;font-size:.9em;">Agent 同进程运行 ddns-go DNS provider</span></td>
  </tr>
  <tr>
    <td align="center" style="background:#f0fdf4;border:2px solid #bbf7d0;border-radius:14px;padding:18px 14px;"><b style="font-size:1.05em;">🖥️ 跨平台</b><br/><span style="color:#475569;font-size:.9em;">Linux (systemd) + Windows 7+ (Windows Service)</span></td>
    <td align="center" style="background:#fefce8;border:2px solid #fde68a;border-radius:14px;padding:18px 14px;"><b style="font-size:1.05em;">🔄 版本管理</b><br/><span style="color:#475569;font-size:.9em;">Git tag 驱动 + 符号链接安装 + 一键回滚</span></td>
  </tr>
</table>

<h2 style="color:#0f766e;border-bottom:3px solid #99f6e4;padding-bottom:8px;">🏗️ 架构</h2>

<img src="docs/architecture.svg" alt="DDNS-Manager 架构图"/>

<h2 style="color:#0891b2;border-bottom:3px solid #a5f3fc;padding-bottom:8px;">📸 界面预览</h2>

<p align="center">
  <img src="docs/screenshots/login.png" alt="登录页" style="border-radius:14px;box-shadow:0 10px 30px rgba(15,23,42,.15);max-width:100%;"/>
</p>
<p align="center" style="color:#64748b;font-size:.9em;">· 登录页 ·</p>
<p align="center">
  <img src="docs/screenshots/dashboard.png" alt="仪表盘" style="border-radius:14px;box-shadow:0 10px 30px rgba(15,23,42,.15);max-width:100%;"/>
</p>
<p align="center" style="color:#64748b;font-size:.9em;">· 仪表盘 ·</p>

<h2 style="color:#b45309;border-bottom:3px solid #fde68a;padding-bottom:8px;">快速开始</h2>

### Docker 部署（推荐）

```bash
# 拉取镜像
docker pull ghcr.io/ocoj/ddns-manager:latest

# 启动
docker run -d \
  --name ddns-manager \
  -p 9877:9877 \
  -v /opt/ddns-manager/data:/data \
  ghcr.io/ocoj/ddns-manager:latest
```

> 首次启动会生成默认管理员密码 `Admin12345`，请立即登录 Web UI 修改。

### 手动部署

```bash
# 构建
bash scripts/build.sh

# 一键部署到管理端（构建物检查 → 清理旧版 → 上传 → 校验）
bash scripts/deploy.sh

# 部署节点 (一键安装)
bash -c "$(curl -fsSL https://your-manager.example.com:30443/bin/install.sh)"
```

<h2 style="color:#1d4ed8;border-bottom:3px solid #bfdbfe;padding-bottom:8px;">🛠️ 技术栈</h2>

| 类别 | 说明 |
|------|------|
| 语言 | Go 1.25+ |
| Web | gorilla/mux · 单文件 SPA (go:embed) · PWA 支持 |
| DNS 引擎 | ddns-go v6.17.4（内嵌 DNS provider） |
| 持久化 | JSON 文件 · AES-256-GCM 加密 · HKDF-SHA256 密钥派生 |
| 证书 | go-pkcs12 纯 Go PFX 生成 · ACME (Let's Encrypt / ZeroSSL / Google Trust) 双路径 |
| 配置 | YAML 解析 (gopkg.in/yaml.v3) |
| 通知 | SMTP 邮件通知 |
| 平台 | Linux systemd · Windows 7+ Service (golang.org/x/sys) |
| 分发 | Docker 镜像 (ghcr.io/ocoj/ddns-manager) |

<h2 style="color:#475569;border-bottom:3px solid #cbd5e1;padding-bottom:8px;">版本</h2>

| 项目 | 版本号 | 说明 |
|------|--------|------|
| ddns-manager | **v1.6.64** | DNS Key 全局版本号持久化比对（方案B） |
| 安装器 | **v1.0.0** | 独立版本，与 Agent 解耦 |
| ddns-go (内嵌) | v6.17.4 | DNS provider library |

<h2 style="color:#be123c;border-bottom:3px solid #fecdd3;padding-bottom:8px;">致谢</h2>

本项目 DNS 更新引擎采用 [ddns-go](https://github.com/jeessy2/ddns-go) (v6.17.4) 的 DNS provider 库。

引用方式：

- `internal/provider/registry.go` — 28 个 DNS 提供商注册表，直接引用 `github.com/jeessy2/ddns-go/v6/dns`
- `cmd/agent/dns_updater.go` — 内嵌 ddns-go DNS provider，同进程执行 DNS 记录更新
- Agent 二进制通过 `go mod` 声明依赖 `github.com/jeessy2/ddns-go/v6`

感谢 [jeessy2](https://github.com/jeessy2) 和所有 ddns-go 贡献者提供的高质量 DNS 引擎。
