#!/bin/sh
# ddns-manager Linux 一键安装
#   VERSION=1.6.30 MANAGER_URL=https://your-server.com:30443 bash -c "$(curl -fsSL https://your-server.com:30443/bin/install.sh)"
#   MANAGER_URL=https://your-server.com:30443 bash -c "$(curl -fsSL https://your-server.com:30443/bin/install.sh)"  # 自动选最新版
set -e

MANAGER="${MANAGER_URL:-https://your-server.com:30443}"
MANAGER="${MANAGER%/}"

# ── 平台检测 ──
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64)      ARCH="arm64" ;;
    armv7l|armv6l|armv8l|arm) ARCH="arm" ;;
    *)            ARCH="amd64" ;;
esac
echo "ddns-manager | arch=$ARCH"

# ── 版本检测 ──
# 优先级: VERSION env > agent_version (/api/ping) > version (/api/ping) > 报错
detect_version() {
    if [ -n "${VERSION:-}" ]; then
        echo "$VERSION"
        return
    fi
    local json=$(curl -fsSL --connect-timeout 10 "$MANAGER/api/ping" 2>/dev/null || true)
    local v=$(echo "$json" | sed -n 's/.*"agent_version":"\([^"]*\)".*/\1/p')
    if [ -n "$v" ]; then
        echo "$v"
        return
    fi
    v=$(echo "$json" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
    if [ -n "$v" ]; then
        echo "$v"
        return
    fi
    echo "[!] 无法从管理端获取版本号 ($MANAGER/api/ping)" >&2
    exit 1
}

# ── 权限检查 ──
if [ "$(id -u)" -ne 0 ]; then
    echo "需要 root 权限:" >&2
    echo "  sudo bash -c \"\$(curl -fsSL $MANAGER/bin/install.sh)\"" >&2
    exit 1
fi

VER=$(detect_version)
echo "  版本: v$VER"

# ── 下载安装器 (固定版本 v1.5.0) ──
INST="ddns-installer-v1.5.0-linux-${ARCH}"
echo "  下载安装器: $INST ..."
curl -fsSL --connect-timeout 30 "$MANAGER/bin/$INST" -o /tmp/ddns-installer || {
    echo "[!] 安装器下载失败" >&2
    exit 1
}
chmod +x /tmp/ddns-installer

# ── 下载 Agent (版本化, 文件存在于 /bin/) ──
AGENT="node-agent-v${VER}-linux-${ARCH}"
echo "  下载 Agent: $AGENT ..."
curl -fsSL --connect-timeout 60 "$MANAGER/bin/$AGENT" -o "/tmp/$AGENT" || {
    echo "[!] Agent 下载失败: /bin/$AGENT" >&2
    rm -f /tmp/ddns-installer
    exit 1
}
chmod +x "/tmp/$AGENT"

# ── 启动安装器 (Agent 路径通过 -agent-file 传入) ──
exec /tmp/ddns-installer \
    -manager-url "$MANAGER" \
    -agent-file "/tmp/$AGENT"
