#!/bin/sh
# ddns-manager Linux 一键安装
#   VERSION=1.6.30 bash -c "\$(curl -fsSL https://your-server.com:30443/bin/install.sh)"
#   bash -c "\$(curl -fsSL https://your-server.com:30443/bin/install.sh)"       # 自动选最新版
#   MANAGER_URL 由 Manager 在下载时自动替换为请求的 Host, 无需手动填写
set -e

MANAGER="${MANAGER_URL:-__MANAGER_URL__}"
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
    # v1.6.58: 用 grep+cut 替代 sed 正则解析 JSON, 更稳健
    local v=$(echo "$json" | grep -o '"agent_version":"[^"]*"' | cut -d'"' -f4)
    if [ -n "$v" ] && [ "$v" != "-" ]; then
        echo "$v"
        return
    fi
    v=$(echo "$json" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
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
INST="ddns-installer-__INSTALLER_VERSION__-linux-${ARCH}"
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

# ── 下载 Agent SHA256 校验文件 ──
echo "  下载校验文件: $AGENT.sha256 ..."
curl -fsSL --connect-timeout 30 "$MANAGER/bin/$AGENT.sha256" -o "/tmp/$AGENT.sha256" || {
    echo "[!] 校验文件下载失败: /bin/$AGENT.sha256" >&2
    rm -f /tmp/ddns-installer "/tmp/$AGENT"
    exit 1
}
CHECKSUM=$(cut -d' ' -f1 "/tmp/$AGENT.sha256")
if [ -z "$CHECKSUM" ]; then
    echo "[!] 校验文件内容无效" >&2
    rm -f /tmp/ddns-installer "/tmp/$AGENT" "/tmp/$AGENT.sha256"
    exit 1
fi

# ── 启动安装器 (Agent 路径通过 -agent-file 传入) ──
exec /tmp/ddns-installer \
    -manager-url "$MANAGER" \
    -agent-file "/tmp/$AGENT" \
    -checksum "$CHECKSUM"
