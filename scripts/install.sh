#!/bin/sh
# ddns-manager — 一键部署
# bash -c "$(curl -fsSL https://manager.example.com:30443/bin/install.sh)"
# 选版本: VERSION=x.y.z bash -c "$(curl -fsSL https://manager.example.com:30443/bin/install.sh)"
# 需 sudo 权限
set -e

MANAGER="${MANAGER_URL:-https://manager.example.com:30443}"
MANAGER="${MANAGER%/}"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64)      ARCH="arm64" ;;
    armv7l|armv6l|armv8l|arm) ARCH="arm" ;;
    i686|i386)    ARCH="386"  ;;
    *)            ARCH="amd64" ;;
esac

echo "ddns-manager | arch=$ARCH"

# ── 版本检测 (v1.5.29 H4: 用 sed 替代 grep/cut, POSIX 兼容) ──
detect_version() {
    local ver="${VERSION:-}"
    if [ -z "$ver" ]; then
        ver=$(curl -fsSL --connect-timeout 10 "$MANAGER/api/ping" 2>/dev/null | sed -n 's/.*"version":"\([^"]*\)".*/\1/p' || true)
    fi
    if [ -z "$ver" ]; then
        echo "[!] 无法从管理端获取版本号 ($MANAGER/api/ping)" >&2
        echo "    请手动指定: VERSION=x.y.z bash -c \"\$(curl -fsSL $MANAGER/bin/install.sh)\"" >&2
        exit 1
    fi
    echo "  管理端版本: v$ver" >&2
    echo "$ver"
}

# ── 下载并校验 SHA256 (v1.5.29 C3) ──
download_and_verify() {
    local url="$1"
    local out="$2"
    local sha_url="${url}.sha256"

    echo "  下载 $url ..."
    if ! curl -fsSL --connect-timeout 30 "$url" -o "$out"; then
        return 1
    fi

    if curl -fsSL --connect-timeout 10 "$sha_url" -o "${out}.sha256" 2>/dev/null; then
        local expected=$(cut -d' ' -f1 "${out}.sha256" 2>/dev/null)
        local actual=$(sha256sum "$out" 2>/dev/null | cut -d' ' -f1)
        if [ -n "$expected" ] && [ "$expected" != "$actual" ]; then
            echo "  [错误] SHA256 校验失败!"
            echo "    期望: $expected"
            echo "    实际: $actual"
            rm -f "$out" "${out}.sha256"
            return 1
        fi
        echo "  SHA256 校验通过"
    fi
    rm -f "${out}.sha256"
    return 0
}

VER=$(detect_version)

# ── 统一流程: 始终下载安装器，由其判断新装/重装 ──
if [ "$(id -u)" -ne 0 ]; then
    echo "需要 root 权限, 请用 sudo 运行"
    echo "  sudo bash -c \"\$(curl -fsSL $MANAGER/bin/install.sh)\""
    exit 1
fi

BIN="ddns-installer-linux-${ARCH}"
TMP="/tmp/ddns-installer-$$"
rm -f /tmp/ddns-installer /tmp/ddns-installer-* 2>/dev/null || true

if ! download_and_verify "$MANAGER/bin/$BIN" "$TMP"; then
    echo "[!] 安装器下载失败，请检查管理端 /bin/ 目录"
    exit 1
fi
chmod +x "$TMP"
exec "$TMP" -manager-url "$MANAGER"
