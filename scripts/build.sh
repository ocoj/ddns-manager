#!/bin/bash
# ddns-manager build script
# Generates versioned binaries with Windows resource embedding and prepares for code signing.
#
# Prerequisites:
#   go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
#
# Code signing (Windows):
#   After obtaining an EV Code Signing Certificate from a trusted CA,
#   set SIGNCERT_* env vars and the script will auto-sign Windows binaries.
#   Without a cert, the build still succeeds but SmartScreen will warn users.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
# 版本号优先级: 环境变量 VERSION > git tag > VERSION 文件 > 兜底
# git tag: v1.5.2 → "v1.5.2"
# git describe (tag后有提交): v1.5.2-3-gabc1234-dirty
# VERSION 文件: 无 git 时后备
VERSION="${VERSION:-$(git -C "$PROJECT_DIR" describe --tags --match 'v*' --dirty 2>/dev/null || (cat "$PROJECT_DIR/VERSION" 2>/dev/null) || echo "dev")}"
# VER_NUM 去掉 v 前缀用于文件名 (v1.5.2 → 1.5.2)
VER_NUM="${VERSION#v}"

# signing config (set via env or leave empty to skip)
SIGNCERT_FILE="${SIGNCERT_FILE:-}"
SIGNCERT_PASSWORD="${SIGNCERT_PASSWORD:-}"
TIMESTAMP_URL="${TIMESTAMP_URL:-http://timestamp.digicert.com}"
SIGNTOOL="${SIGNTOOL:-signtool}"

LDFLAGS="-s -w -X main.version=${VER_NUM}"

echo "============================================"
echo " ddns-manager Build"
echo " Version:  $VERSION"
echo " Publisher: Lanxun CO.,Ltd."
echo "============================================"

mkdir -p "$BUILD_DIR"

# ── Windows Agent ──

build_windows() {
    local arch="$1"  # amd64 or arm64
    echo ""
    echo "── Building Windows Agent ($arch) ──"

    cd "$PROJECT_DIR/cmd/agent"

    # generate Windows version resource (.syso)
    if command -v goversioninfo &>/dev/null; then
        echo "  → goversioninfo: embedding version resource..."
        goversioninfo -64 -o resource.syso versioninfo.json
        trap 'rm -f resource.syso' EXIT
    else
        echo "  ⚠️  goversioninfo not found — install with:"
        echo "     go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest"
        echo "     (build continues without version resource)"
    fi

    out="$BUILD_DIR/node-agent-windows-${arch}.exe"
    GOOS=windows GOARCH="$arch" CGO_ENABLED=0 \
        go build -trimpath -ldflags "$LDFLAGS" -o "$out" .

    # versioned copy: node-agent-v{VERSION}-windows-amd64.exe
    ver_out="$BUILD_DIR/node-agent-v${VER_NUM}-windows-${arch}.exe"
    cp "$out" "$ver_out"

    echo "  ✅ $out ($(du -h "$out" | cut -f1))"
    echo "  ✅ $ver_out (versioned)"

    # code signing
    if [ -n "$SIGNCERT_FILE" ] && [ -f "$SIGNCERT_FILE" ]; then
        echo "  → 代码签名..."
        "$SIGNTOOL" sign \
            /fd SHA256 \
            /f "$SIGNCERT_FILE" \
            /p "$SIGNCERT_PASSWORD" \
            /tr "$TIMESTAMP_URL" \
            /td SHA256 \
            /d "ddns-manager Node Agent" \
            /du "https://github.com/kk/ddns-manager" \
            "$out"
        echo "  ✅ 已签名"
    else
        echo "  ℹ️  未签名（设置 SIGNCERT_FILE 环境变量以启用签名）"
    fi
}

# ── Linux Agent ──

build_linux() {
    local arch="$1"
    local goarch="$arch"
    local goarm=""
    # map arch names to Go toolchain values (normalize armv7 → arm)
    case "$arch" in
        armv7|arm) goarch="arm"; goarm="7"; arch="arm" ;;
    esac
    echo ""
    echo "── Building Linux Agent ($arch) ──"

    cd "$PROJECT_DIR/cmd/agent"

    out="$BUILD_DIR/node-agent-linux-${arch}"
    if [ -n "$goarm" ]; then
        GOOS=linux GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$out" .
    else
        GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$out" .
    fi

    # versioned copy: node-agent-v{VERSION}-linux-amd64
    ver_out="$BUILD_DIR/node-agent-v${VER_NUM}-linux-${arch}"
    cp "$out" "$ver_out"

    chmod +x "$out" "$ver_out"
    echo "  ✅ $out ($(du -h "$out" | cut -f1))"
    echo "  ✅ $ver_out (versioned)"
}

# ── Manager (Linux only) ──

build_manager() {
    local arch="$1"
    echo ""
    echo "── Building Manager ($arch) ──"

    cd "$PROJECT_DIR/cmd/manager"

    out="$BUILD_DIR/ddns-manager-linux-${arch}"
    GOOS=linux GOARCH="$arch" CGO_ENABLED=0 \
        go build -trimpath -ldflags "$LDFLAGS" -o "$out" .

    ver_out="$BUILD_DIR/ddns-manager-v${VER_NUM}-linux-${arch}"
    cp "$out" "$ver_out"

    chmod +x "$out" "$ver_out"
    echo "  ✅ $out ($(du -h "$out" | cut -f1))"
    echo "  ✅ $ver_out (versioned)"
}

# ── Installer ──

build_installer() {
    local arch="$1"
    local goarch="$arch"
    local goarm=""
    case "$arch" in
        armv7|arm) goarch="arm"; goarm="7"; arch="arm" ;;
    esac
    echo ""
    echo "-- Building Installer (linux/$arch) --"
    cd "$PROJECT_DIR/cmd/installer"
    out="$BUILD_DIR/ddns-installer-linux-${arch}"
    if [ -n "$goarm" ]; then
        GOOS=linux GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$out" .
    else
        GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$out" .
    fi
    ver_out="$BUILD_DIR/ddns-installer-v${VER_NUM}-linux-${arch}"
    cp "$out" "$ver_out"
    chmod +x "$out" "$ver_out"
    echo "  OK $out"
    echo "  OK $ver_out (versioned)"
}

build_installer_win() {
    local goarch="$1"
    echo ""
    echo "-- Building Installer (windows/$goarch) --"
    cd "$PROJECT_DIR/cmd/installer"
    out="$BUILD_DIR/ddns-installer-windows-${goarch}.exe"
    GOOS=windows GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$out" .
    ver_out="$BUILD_DIR/ddns-installer-v${VER_NUM}-windows-${goarch}.exe"
    cp "$out" "$ver_out"
    echo "  OK $out"
    echo "  OK $ver_out (versioned)"
}

# ── Build all ──

build_windows amd64
build_linux amd64
build_linux arm64
build_linux arm    # Raspberry Pi 3 (32-bit) — Go标准命名, 文件名与detectPlatform一致
build_manager amd64
build_manager arm64
build_installer amd64
build_installer arm64
build_installer arm
build_installer_win amd64

echo ""
echo "============================================"
echo " Build complete! Output: $BUILD_DIR/"
echo "============================================"
ls -lh "$BUILD_DIR/" | awk '{print "  " $5 "\t" $9}'
echo ""
echo "Code signing checklist for Windows release:"
echo "  1. Obtain EV Code Signing Certificate (e.g. DigiCert, Sectigo)"
echo "  2. Install cert to Windows certificate store or export as .pfx"
echo "  3. Set env: SIGNCERT_FILE=/path/to/cert.pfx SIGNCERT_PASSWORD=xxx"
echo "  4. Re-run this script"
echo "  5. Verify: right-click .exe → Properties → Digital Signatures"
echo "     Should show: Lanxun CO.,Ltd."
echo ""
