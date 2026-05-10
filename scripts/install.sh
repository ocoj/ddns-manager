#!/bin/sh
# ddns-manager v2 — 一键安装脚本
# 用法:
#   curl -fsSL http://MANAGER_IP:9877/bin/install.sh | sh -s -- --manager http://MANAGER_IP:9877 --name my-node
# 或:
#   curl -fsSL http://MANAGER_IP:9877/bin/install.sh | sh -s -- -m http://MANAGER_IP:9877 -n my-node
#
# 参数:
#   -m, --manager URL       管理端地址 (必填，如 http://192.168.1.100:9877)
#   -n, --name NAME         节点名称 (可选，不填则交互式输入)
#   -d, --dir PATH          安装目录 (可选，默认 /opt/ddns-manager)
#   -k, --insecure          跳过 TLS 验证
#   -v, --version VERSION   指定版本 (可选，默认自动匹配)
set -e

MANAGER=""
NAME=""
DIR=""
INSECURE=""
VERSION=""

while [ $# -gt 0 ]; do
    case "$1" in
        -m|--manager) MANAGER="$2"; shift 2 ;;
        -n|--name)    NAME="$2"; shift 2 ;;
        -d|--dir)     DIR="$2"; shift 2 ;;
        -k|--insecure) INSECURE="-insecure"; shift ;;
        -v|--version) VERSION="$2"; shift 2 ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
done

if [ -z "$MANAGER" ]; then
    echo "用法: $0 -m http://MANAGER_IP:9877 [-n node-name] [-d /install/path]"
    exit 1
fi

MANAGER="${MANAGER%/}"

# 检测系统架构，归一化为 Go 标准命名 (amd64/arm64/arm)
# 取消 x86_64 映射——构建脚本产出文件名使用 amd64
OS="linux"
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)  GOARCH="amd64" ;;
    aarch64)       GOARCH="arm64" ;;
    armv7l)        GOARCH="arm"  ;;
    *) echo "不支持的架构: $ARCH"; exit 1 ;;
esac

echo "============================================"
echo " ddns-manager v2 一键安装"
echo " 管理端: $MANAGER"
echo " 系统: $OS/$GOARCH"
echo "============================================"

# 测试管理端连通性
echo "测试管理端连接..."
if ! curl -fsS --connect-timeout 5 "$MANAGER/api/ping" >/dev/null 2>&1; then
    echo "[FAIL] 无法连接管理端: $MANAGER"
    echo "请检查地址和网络连通性"
    exit 1
fi
echo "[OK] 管理端可达"

# 下载 ddns-installer (安装向导) — 不是 node-agent (守护进程)
# installer 集成安装/卸载功能，agent 仅负责心跳+DDNS
TMP_INSTALLER="/tmp/ddns-installer"

if [ -z "$VERSION" ]; then
    echo "下载 ddns-installer-linux-${GOARCH} ..."
    INSTALLER_NAME="ddns-installer-linux-${GOARCH}"
    if ! curl -fsSL --connect-timeout 30 -o "$TMP_INSTALLER" "$MANAGER/bin/$INSTALLER_NAME" 2>/dev/null; then
        # fallback: try versioned name
        echo "尝试版本化名称..."
        FALLBACK=$(curl -fsS "$MANAGER/bin/" 2>/dev/null | grep -o 'ddns-installer[^"]*-linux-amd64' | head -1 || true)
        if [ -n "$FALLBACK" ]; then
            curl -fsSL --connect-timeout 30 -o "$TMP_INSTALLER" "$MANAGER/bin/$FALLBACK"
        fi
    fi
else
    curl -fsSL --connect-timeout 30 -o "$TMP_INSTALLER" "$MANAGER/bin/ddns-installer-$VERSION-$OS-$GOARCH"
fi

if [ ! -s "$TMP_INSTALLER" ]; then
    # last resort: try common patterns
    echo "尝试备选名称..."
    for pattern in \
        "ddns-installer-linux-amd64" \
        "ddns-installer-linux-x86_64" \
        "ddns-installer-latest"; do
        if curl -fsSL --connect-timeout 30 -o "$TMP_INSTALLER" "$MANAGER/bin/$pattern" 2>/dev/null; then
            [ -s "$TMP_INSTALLER" ] && break
        fi
    done
fi

if [ ! -s "$TMP_INSTALLER" ]; then
    echo "[FAIL] 无法下载安装器二进制"
    echo "请确认管理端 /bin/ 目录下存在 ddns-installer-linux-${GOARCH}"
    exit 1
fi

chmod +x "$TMP_INSTALLER"
echo "[OK] 安装器下载完成 ($(du -h "$TMP_INSTALLER" | cut -f1))"

# 运行安装向导
echo ""
ARGS=""
[ -n "$MANAGER" ] && ARGS="$ARGS -manager-url $MANAGER"
[ -n "$NAME" ] && ARGS="$ARGS -name $NAME"
[ -n "$DIR" ] && ARGS="$ARGS -dir $DIR"
[ -n "$INSECURE" ] && ARGS="$ARGS $INSECURE"

echo "运行安装向导..."
exec "$TMP_INSTALLER" $ARGS
