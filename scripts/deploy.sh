#!/bin/bash
# ddns-manager 一键部署脚本
# 用法: bash scripts/deploy.sh
# 功能: 构建物完整性检查 → 清理旧版 → 上传服务端 → 远端校验
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"

# ── 服务端配置 ──
SERVER_HOST="${DEPLOY_HOST:-your-server-ip}"
SERVER_USER="${DEPLOY_USER:-your-username}"
SERVER_BIN="${DEPLOY_BIN:-/opt/ddns-manager/data/bin}"
SERVER_OPT="${DEPLOY_OPT:-/opt/ddns-manager}"
TMPDIR="/tmp/ddns-deploy-$$"

# ── 版本号 ──
VERSION="$(cat "$PROJECT_DIR/VERSION" 2>/dev/null || echo "")"
INSTALLER_VERSION="$(cat "$PROJECT_DIR/INSTALLER_VERSION" 2>/dev/null || echo "1.0.0")"
if [ -z "$VERSION" ]; then
    echo "[ERROR] 未找到 VERSION 文件，请先确认项目根目录存在 VERSION 文件"
    exit 1
fi
VER_NUM="${VERSION#v}"
INV="v${INSTALLER_VERSION}"

# ── 颜色 ──
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()  { echo -e "${GREEN}  ✅${NC} $1"; }
warn(){ echo -e "${YELLOW}  ⚠️${NC}  $1"; }
err() { echo -e "${RED}  ❌${NC} $1"; }

echo "============================================"
echo " ddns-manager 一键部署"
echo " Version:       v${VER_NUM}"
echo " Installer:     ${INV}"
echo " Target:        ${SERVER_USER}@${SERVER_HOST}:${SERVER_BIN}"
echo "============================================"

# ══════════════════════════════════════════════
# 1. 构建完整性检查
# ══════════════════════════════════════════════

declare -A REQUIRED=(
    ["node-agent-v${VER_NUM}-linux-amd64"]=""
    ["node-agent-v${VER_NUM}-linux-arm64"]=""
    ["node-agent-v${VER_NUM}-linux-arm"]=""
    ["node-agent-v${VER_NUM}-windows-amd64.exe"]=""
    ["ddns-installer-${INV}-linux-amd64"]=""
    ["ddns-installer-${INV}-linux-arm64"]=""
    ["ddns-installer-${INV}-windows-amd64.exe"]=""
    ["upgrade_helper-v${VER_NUM}-windows-amd64.exe"]=""
)

echo ""
echo "[1/5] 构建完整性检查"

missing=0
for f in "${!REQUIRED[@]}"; do
    path="$BUILD_DIR/$f"
    if [ ! -f "$path" ]; then
        err "缺失: $f"
        missing=1
    fi
done

# Manager 二进制（不纳入 data/bin/ 上传，但需验证已构建）
MANAGER_BIN="ddns-manager-v${VER_NUM}-linux-amd64"
if [ ! -f "$BUILD_DIR/$MANAGER_BIN" ]; then
    err "缺失 Manager: $MANAGER_BIN"
    missing=1
fi

# install.sh（在 scripts/ 不在 build/）
INSTALL_SH="$PROJECT_DIR/scripts/install.sh"
if [ ! -f "$INSTALL_SH" ]; then
    err "缺失: scripts/install.sh"
    missing=1
fi

if [ "$missing" -eq 1 ]; then
    echo ""
    echo "[ERROR] 构建产物不完整，请先运行: bash scripts/build.sh"
    exit 1
fi
ok "所有构建产物就绪"

# ══════════════════════════════════════════════
# 2. 清理 build/ 旧版本
# ══════════════════════════════════════════════

echo ""
echo "[2/5] 清理 build/ 旧版本残留"

cleaned=0
for f in "$BUILD_DIR"/node-agent-v* "$BUILD_DIR"/ddns-manager-v* \
         "$BUILD_DIR"/upgrade_helper-v* "$BUILD_DIR"/ddns-installer-v*; do
    [ -f "$f" ] || continue
    fname="$(basename "$f")"
    if echo "$fname" | grep -q "v${VER_NUM}"; then continue; fi
    if echo "$fname" | grep -q "v${INSTALLER_VERSION}"; then continue; fi
    rm -f "$f"
    cleaned=$((cleaned + 1))
done

for z in "$BUILD_DIR"/ddns-manager-install-*.zip; do
    [ -f "$z" ] || continue
    rm -f "$z"
    cleaned=$((cleaned + 1))
done

if [ "$cleaned" -gt 0 ]; then
    ok "已清理 $cleaned 个旧版本文件"
else
    ok "无旧版本文件需要清理"
fi

# ══════════════════════════════════════════════
# 3. SSH 连通性检查
# ══════════════════════════════════════════════

echo ""
echo "[3/5] SSH 连通性检查"

if ! ssh -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=accept-new "${SERVER_USER}@${SERVER_HOST}" "echo ok" &>/dev/null; then
    err "无法 SSH 连接到 ${SERVER_USER}@${SERVER_HOST}"
    echo "   请确认 SSH Key 已配置或设置环境变量:"
    echo "   DEPLOY_HOST=your-server DEPLOY_USER=your-user bash scripts/deploy.sh"
    echo "   首次部署前请手动建立 known_hosts: ssh-keyscan your-server >> ~/.ssh/known_hosts"
    exit 1
fi
ok "SSH 连接正常"

# ══════════════════════════════════════════════
# 4. 上传到服务端
# ══════════════════════════════════════════════

echo ""
echo "[4/5] 上传文件到服务端"

mkdir -p "$TMPDIR"

FILES_TO_UPLOAD=(
    "node-agent-v${VER_NUM}-linux-amd64"
    "node-agent-v${VER_NUM}-linux-amd64.sha256"
    "node-agent-v${VER_NUM}-linux-arm64"
    "node-agent-v${VER_NUM}-linux-arm64.sha256"
    "node-agent-v${VER_NUM}-linux-arm"
    "node-agent-v${VER_NUM}-linux-arm.sha256"
    "node-agent-v${VER_NUM}-windows-amd64.exe"
    "node-agent-v${VER_NUM}-windows-amd64.exe.sha256"
    "ddns-installer-${INV}-linux-amd64"
    "ddns-installer-${INV}-linux-arm64"
    "ddns-installer-${INV}-windows-amd64.exe"
    "upgrade_helper-v${VER_NUM}-windows-amd64.exe"
    "upgrade_helper-v${VER_NUM}-windows-amd64.exe.sha256"
)

# Agent/Installer/Helper → data/bin/
for f in "${FILES_TO_UPLOAD[@]}"; do
    if [ -f "$BUILD_DIR/$f" ]; then
        cp "$BUILD_DIR/$f" "$TMPDIR/"
    else
        warn "跳过缺失文件: $f"
    fi
done

# install.sh → data/bin/
cp "$INSTALL_SH" "$TMPDIR/install.sh"

uploaded=0
for f in "$TMPDIR"/*; do
    fname="$(basename "$f")"
    scp -q "$f" "${SERVER_USER}@${SERVER_HOST}:${SERVER_BIN}/" && {
        uploaded=$((uploaded + 1))
    } || {
        err "上传失败: $fname"
    }
done

# 设置权限
ssh "${SERVER_USER}@${SERVER_HOST}" "chmod 644 ${SERVER_BIN}/*.sha256 ${SERVER_BIN}/install.sh 2>/dev/null; chmod 755 ${SERVER_BIN}/node-agent-v* ${SERVER_BIN}/ddns-installer-* ${SERVER_BIN}/upgrade_helper-* 2>/dev/null; chown ${SERVER_USER}:${SERVER_USER} ${SERVER_BIN}/* 2>/dev/null; true"

# Manager 二进制 → /tmp/（不在 data/bin/）
scp -q "$BUILD_DIR/$MANAGER_BIN" "${SERVER_USER}@${SERVER_HOST}:/tmp/" && {
    ssh "${SERVER_USER}@${SERVER_HOST}" "chmod 755 /tmp/$MANAGER_BIN"
} || {
    warn "Manager 上传失败"
}

rm -rf "$TMPDIR"
ok "已上传 $uploaded 个文件到 ${SERVER_BIN}/"
ok "Manager 已上传到 /tmp/${MANAGER_BIN}"

# ══════════════════════════════════════════════
# 5. 远端校验 (HTTP)
# ══════════════════════════════════════════════

echo ""
echo "[5/5] 远端校验 (HTTP 200 检查)"

VERIFY_FILES=(
    "bin/node-agent-v${VER_NUM}-linux-amd64"
    "bin/node-agent-v${VER_NUM}-linux-arm64"
    "bin/node-agent-v${VER_NUM}-linux-arm"
    "bin/node-agent-v${VER_NUM}-windows-amd64.exe"
    "bin/ddns-installer-${INV}-linux-amd64"
    "bin/ddns-installer-${INV}-linux-arm64"
    "bin/ddns-installer-${INV}-windows-amd64.exe"
    "bin/upgrade_helper-v${VER_NUM}-windows-amd64.exe"
    "bin/install.sh"
)

verify_failed=0
for path in "${VERIFY_FILES[@]}"; do
    code=$(ssh "${SERVER_USER}@${SERVER_HOST}" \
        "curl -s -o /dev/null -w '%{http_code}' http://localhost:9877/${path}" 2>/dev/null || echo "000")
    if [ "$code" = "200" ]; then
        ok "$path"
    else
        err "$path → HTTP $code"
        verify_failed=1
    fi
done

echo ""
if [ "$verify_failed" -eq 0 ]; then
    ok "全部文件校验通过"
else
    warn "部分文件校验失败，请检查服务端 ${SERVER_BIN}/ 目录"
fi

# ══════════════════════════════════════════════
# 后续步骤提示
# ══════════════════════════════════════════════

echo ""
echo "============================================"
echo " 部署完成"
echo "============================================"
echo ""
echo "后续手动步骤:"
echo ""
echo "  1. 重启 Manager (需 sudo):"
echo "     sudo systemctl stop ddns-manager"
echo "     sudo cp /tmp/${MANAGER_BIN} ${SERVER_OPT}/"
echo "     sudo ln -sf ${MANAGER_BIN} ${SERVER_OPT}/ddns-manager"
echo "     sudo systemctl start ddns-manager"
echo ""
echo "  2. 在 Web UI 设置 Agent 目标版本:"
echo "     POST /api/admin/agent-version {\"latest_version\":\"${VER_NUM}\"}"
echo ""
echo "  3. 客户端一键安装:"
echo "     VERSION=${VER_NUM} bash -c \"\$(curl -fsSL https://your-manager.example.com:30443/bin/install.sh)\""
echo ""
