#!/bin/bash
# ddns-manager 发布脚本
# 用法:
#   bash scripts/release.sh                  # Phase A: 构建 + 内部部署
#   bash scripts/release.sh --with-github     # Phase A + Phase B: GitHub Release
#   bash scripts/release.sh --dry-run         # 仅安全检查 + snapshot 构建
#   bash scripts/release.sh --skip-deploy     # Phase A 跳过部署
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"

# ── 参数 ──
DRY_RUN=false
SKIP_DEPLOY=false
WITH_GITHUB=false
SKIP_DOCKER=false
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --skip-deploy) SKIP_DEPLOY=true ;;
        --with-github) WITH_GITHUB=true ;;
        *) echo "未知参数: $arg"; exit 1 ;;
    esac
done

# ── 颜色 ──
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()  { echo -e "${GREEN}  ✅${NC} $1"; }
warn(){ echo -e "${YELLOW}  ⚠️${NC}  $1"; }
err() { echo -e "${RED}  ❌${NC} $1"; }
info(){ echo -e "${CYAN}  ℹ️${NC}  $1"; }
section() { echo ""; echo -e "${CYAN}════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}════════════════════════════════════════${NC}"; }

# ── 版本号 ──
VERSION_FILE="$PROJECT_DIR/VERSION"
if [ ! -f "$VERSION_FILE" ]; then
    err "未找到 VERSION 文件"
    exit 1
fi
FULL_VERSION="$(cat "$VERSION_FILE")"
VER_NUM="${FULL_VERSION#v}"
INSTALLER_VERSION="$(cat "$PROJECT_DIR/INSTALLER_VERSION" 2>/dev/null || echo "1.0.0")"

# ── 部署配置 ──
DEPLOY_HOST="${DEPLOY_HOST:-}"
DEPLOY_USER="${DEPLOY_USER:-}"
DEPLOY_BIN="${DEPLOY_BIN:-/opt/ddns-manager/data/bin}"
DEPLOY_OPT="${DEPLOY_OPT:-/opt/ddns-manager}"

FAILED=0

# ══════════════════════════════════════════════
# 0. 脱敏核验
# ══════════════════════════════════════════════

sanitize_check() {
    section "0. 脱敏核验"

    # 黑名单模式 — 匹配任一则告警
    local BLACKLIST=(
        "192\.168\.110\."        # 内部管理网段
        "192\.168\.2\."          # 内部业务网段
        "172\.17\.0\."           # Docker bridge
        "example\.com"            # 真实域名
        "example\.org"             # 真实域名
        "example\.org"              # 真实域名
        # 密码检测: 匹配8位以上字母+数字组合（疑似密码/Token），但不包含已知公开字符串
        "[A-Z][a-z]+[0-9]{8,}"  # 疑似密码模式
    )

    # 扫描范围: git tracked 且不在 .gitignore 的文件
    local FILES
    # git ls-files (tracked) + git ls-files --others (untracked, 非gitignore)
    FILES=$(cd "$PROJECT_DIR" && { git ls-files; git ls-files --others --exclude-standard; })

    # 白名单: 允许出现的文件 (相对于项目根)
    # 注意: 不再豁免任何文件。发布计划等敏感文档不应出现在仓库中。
    local WHITELIST_FILES=(
    )

    # 白名单: 允许出现的行内容 grep 模式
    local WHITELIST_PATTERNS=(
        "Publisher: Lanxun CO.,Ltd."  # 版权声明
        "Admin12345"                   # 默认密码（已标注 WARNING）
        "your-server-ip"              # 示例占位符
        "your-username"               # 示例占位符
        "your-manager.example.com"    # 示例域名
        "10\.0\.0\."                  # 示例 IP
    )

    local hits=0
    for pattern in "${BLACKLIST[@]}"; do
        while IFS= read -r file; do
            # 跳过白名单文件
            local whitelisted=false
            for wf in "${WHITELIST_FILES[@]}"; do
                [[ "$file" == "$wf" ]] && whitelisted=true && break
            done
            $whitelisted && continue

            # 跳过白名单路径前缀 (memory/, internal-docs/ — 内部文件不对外发布)
            [[ "$file" == memory/* ]] && continue
            [[ "$file" == internal-docs/* ]] && continue

            while IFS=: read -r line_num content; do
                # 跳过白名单行
                local line_ok=false
                for wp in "${WHITELIST_PATTERNS[@]}"; do
                    if echo "$content" | grep -qE "$wp"; then
                        line_ok=true; break
                    fi
                done
                $line_ok && continue

                err "$file:$line_num: $content"
                hits=$((hits + 1))
            done < <(grep -n "$pattern" "$PROJECT_DIR/$file" 2>/dev/null || true)
        done < <(echo "$FILES")
    done

    if [ "$hits" -gt 0 ]; then
        echo ""
        err "脱敏核验失败: 发现 $hits 处疑似敏感信息"
        echo "   请检查上述文件，确认敏感信息已脱敏后重试。"
        echo "   参考脱敏映射表: internal-docs/ 目录下文档"
        exit 1
    fi
    ok "脱敏核验通过"
}

# ══════════════════════════════════════════════
# 1. 安全检查
# ══════════════════════════════════════════════

preflight() {
    section "1. 安全检查"

    # 1.1 git clean
    if ! git -C "$PROJECT_DIR" diff-index --quiet HEAD --; then
        err "工作区不干净，请先提交或暂存所有更改"
        git -C "$PROJECT_DIR" status --short
        exit 1
    fi
    ok "git 工作区干净"

    # 1.2 on main branch
    local branch
    branch=$(git -C "$PROJECT_DIR" branch --show-current)
    if [ "$branch" != "main" ]; then
        err "当前分支 $branch，必须在 main 分支发布"
        exit 1
    fi
    ok "当前分支: main"

    # 1.3 VERSION valid
    if ! echo "$VER_NUM" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        err "VERSION 格式无效: $FULL_VERSION (期望 x.y.z)"
        exit 1
    fi
    ok "VERSION: $FULL_VERSION"

    # 1.4 version not already tagged
    if git -C "$PROJECT_DIR" rev-parse "v$VER_NUM" >/dev/null 2>&1; then
        err "git tag v$VER_NUM 已存在"
        exit 1
    fi
    ok "git tag v$VER_NUM 未使用"

    # 1.5 tests pass
    info "运行测试..."
    if ! go test "$PROJECT_DIR/..." -count=1 >/dev/null 2>&1; then
        err "测试未通过"
        go test "$PROJECT_DIR/..." -count=1 2>&1 | tail -20
        exit 1
    fi
    ok "go test 全部通过"

    # 1.6 goreleaser config valid
    if command -v goreleaser &>/dev/null; then
        if ! goreleaser check -f "$PROJECT_DIR/.goreleaser.yaml" >/dev/null 2>&1; then
            err "goreleaser 配置无效"
            goreleaser check -f "$PROJECT_DIR/.goreleaser.yaml" 2>&1
            exit 1
        fi
        ok "goreleaser 配置有效"
    else
        warn "goreleaser 未安装 — Phase B GitHub Release 将不可用"
        info "安装: go install github.com/goreleaser/goreleaser/v2@latest"
    fi

    # 1.7 GITHUB_TOKEN (Phase B 需要)
    if $WITH_GITHUB && [ -z "${GITHUB_TOKEN:-}" ]; then
        warn "GITHUB_TOKEN 未设置 — Phase B 将无法创建 GitHub Release"
    fi

    # 1.8 SSH connectivity (deploy target)
    if ! $SKIP_DEPLOY; then
        if [ -z "$DEPLOY_HOST" ] || [ -z "$DEPLOY_USER" ]; then
            warn "DEPLOY_HOST/DEPLOY_USER 未设置 — 将跳过部署"
            SKIP_DEPLOY=true
        elif ! ssh -o ConnectTimeout=5 -o BatchMode=yes "${DEPLOY_USER}@${DEPLOY_HOST}" "echo ok" &>/dev/null; then
            warn "SSH 密钥不可用 — 将跳过部署"
            info "设置: DEPLOY_HOST=... DEPLOY_USER=... 并配置 SSH 密钥或 sshpass"
            SKIP_DEPLOY=true
        else
            ok "SSH ${DEPLOY_USER}@${DEPLOY_HOST} 可达"
        fi
    fi

    # 1.9 tools
    if ! command -v goversioninfo &>/dev/null; then
        warn "goversioninfo 未安装 — Windows 构建将无版本资源"
    fi
    if ! command -v zip &>/dev/null; then
        warn "zip 未安装 — Windows ZIP 打包将跳过"
    fi

    echo ""
    ok "全部安全检查通过"
}

# ══════════════════════════════════════════════
# 2. 构建
# ══════════════════════════════════════════════

do_build() {
    section "2. 编译"

    if $DRY_RUN; then
        info "dry-run 模式: 执行 goreleaser --snapshot"
        cd "$PROJECT_DIR"
        goreleaser release --snapshot --clean -f .goreleaser.yaml
        ok "snapshot 构建完成 → dist/"
        return
    fi

    info "执行 build.sh..."
    bash "$SCRIPT_DIR/build.sh"
    ok "build.sh 完成 → $BUILD_DIR/"
}

# ══════════════════════════════════════════════
# 3. 部署到管理端
# ══════════════════════════════════════════════

do_deploy() {
    section "3. 部署到管理端"

    if $SKIP_DEPLOY; then
        info "已跳过部署"
        return
    fi
    if $DRY_RUN; then
        info "dry-run: 跳过部署"
        return
    fi

    local SERVER="${DEPLOY_USER}@${DEPLOY_HOST}"
    local TMPDIR
    TMPDIR=$(mktemp -d)

    # Agent + Installer + Helper 二进制
    local FILES=(
        "node-agent-v${VER_NUM}-linux-amd64"       "node-agent-v${VER_NUM}-linux-amd64.sha256"
        "node-agent-v${VER_NUM}-linux-arm64"       "node-agent-v${VER_NUM}-linux-arm64.sha256"
        "node-agent-v${VER_NUM}-linux-arm"         "node-agent-v${VER_NUM}-linux-arm.sha256"
        "node-agent-v${VER_NUM}-windows-amd64.exe"  "node-agent-v${VER_NUM}-windows-amd64.exe.sha256"
        "ddns-installer-v${INSTALLER_VERSION}-linux-amd64"
        "ddns-installer-v${INSTALLER_VERSION}-linux-arm64"
        "ddns-installer-v${INSTALLER_VERSION}-windows-amd64.exe"
        "upgrade_helper-v${VER_NUM}-windows-amd64.exe"
        "upgrade_helper-v${VER_NUM}-windows-amd64.exe.sha256"
    )

    info "收集构建产物..."
    for f in "${FILES[@]}"; do
        if [ -f "$BUILD_DIR/$f" ]; then
            cp "$BUILD_DIR/$f" "$TMPDIR/"
        else
            warn "缺失: $f"
        fi
    done
    cp "$SCRIPT_DIR/install.sh" "$TMPDIR/install.sh"

    local count
    count=$(ls "$TMPDIR" | wc -l)
    info "上传 $count 个文件 → $SERVER:$DEPLOY_BIN"

    for f in "$TMPDIR"/*; do
        local fname
        fname=$(basename "$f")
        if scp -q "$f" "${SERVER}:${DEPLOY_BIN}/"; then
            ok "$fname"
        else
            err "上传失败: $fname"
            FAILED=1
        fi
    done

    # 权限
    ssh "$SERVER" "chmod 644 ${DEPLOY_BIN}/*.sha256 ${DEPLOY_BIN}/install.sh 2>/dev/null; chmod 755 ${DEPLOY_BIN}/node-agent-v* ${DEPLOY_BIN}/ddns-installer-* ${DEPLOY_BIN}/upgrade_helper-* 2>/dev/null; true"

    # Manager 二进制
    local MANAGER_BIN="ddns-manager-v${VER_NUM}-linux-amd64"
    if [ -f "$BUILD_DIR/$MANAGER_BIN" ]; then
        scp -q "$BUILD_DIR/$MANAGER_BIN" "$SERVER:/tmp/"
        ssh "$SERVER" "chmod 755 /tmp/$MANAGER_BIN"
        ok "Manager → /tmp/$MANAGER_BIN"

        info "重启 Manager 服务..."
        ssh "$SERVER" "
            sudo systemctl stop ddns-manager 2>/dev/null
            sudo cp /tmp/$MANAGER_BIN ${DEPLOY_OPT}/$MANAGER_BIN
            sudo ln -sf $MANAGER_BIN ${DEPLOY_OPT}/ddns-manager
            sudo systemctl start ddns-manager
            sleep 2
            systemctl is-active ddns-manager
        "
        ok "Manager 服务已重启"
    else
        warn "Manager 二进制缺失: $MANAGER_BIN"
    fi

    rm -rf "$TMPDIR"
}

# ══════════════════════════════════════════════
# 4. 部署后校验
# ══════════════════════════════════════════════

do_verify() {
    section "4. 部署校验"

    if $SKIP_DEPLOY || $DRY_RUN; then
        info "跳过校验"
        return
    fi

    local SERVER="${DEPLOY_USER}@${DEPLOY_HOST}"

    local VERIFY_FILES=(
        "bin/node-agent-v${VER_NUM}-linux-amd64"
        "bin/node-agent-v${VER_NUM}-linux-arm64"
        "bin/node-agent-v${VER_NUM}-linux-arm"
        "bin/node-agent-v${VER_NUM}-windows-amd64.exe"
        "bin/ddns-installer-v${INSTALLER_VERSION}-linux-amd64"
        "bin/ddns-installer-v${INSTALLER_VERSION}-linux-arm64"
        "bin/ddns-installer-v${INSTALLER_VERSION}-windows-amd64.exe"
        "bin/upgrade_helper-v${VER_NUM}-windows-amd64.exe"
        "bin/install.sh"
    )

    for path in "${VERIFY_FILES[@]}"; do
        local code
        code=$(ssh "$SERVER" "curl -s -o /dev/null -w '%{http_code}' http://localhost:9877/$path" 2>/dev/null || echo "000")
        if [ "$code" = "200" ]; then
            ok "$path"
        else
            err "$path → HTTP $code"
            FAILED=1
        fi
    done

    # 推送 Agent 版本
    info "推送 Agent 目标版本: $VER_NUM"
    local TOKEN
    TOKEN=$(ssh "$SERVER" "curl -s -X POST http://localhost:9877/api/auth/login -H 'Content-Type: application/json' -d '{\"password\":\"Admin12345\"}'" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null)

    if [ -n "$TOKEN" ]; then
        local result
        result=$(ssh "$SERVER" "curl -s -X POST http://localhost:9877/api/admin/agent-version -H 'Content-Type: application/json' -H 'Authorization: Bearer $TOKEN' -d '{\"latest_version\":\"$VER_NUM\"}'")
        if echo "$result" | grep -q '"ok"'; then
            ok "Agent 版本已推送: $VER_NUM"
        else
            warn "Agent 版本推送可能失败: $result"
        fi
    else
        warn "无法获取 API Token (密码已修改?)，跳过 Agent 版本推送"
        info "请手动在 Web UI → 版本管理 → 设置强制版本为 $VER_NUM"
    fi
}

# ══════════════════════════════════════════════
# 5. GitHub Release (Phase B)
# ══════════════════════════════════════════════

do_github_release() {
    section "5. GitHub Release"

    if $DRY_RUN; then
        info "dry-run: 跳过 GitHub Release"
        return
    fi

    if ! $WITH_GITHUB; then
        info "未指定 --with-github，跳过 GitHub Release"
        echo "  内部部署完成后，确认无误再运行:"
        echo "  bash scripts/release.sh --with-github"
        return
    fi

    if [ -z "${GITHUB_TOKEN:-}" ]; then
        err "GITHUB_TOKEN 未设置"
        exit 1
    fi

    info "git tag v$VER_NUM..."
    cd "$PROJECT_DIR"
    git tag -a "v$VER_NUM" -m "Release v$VER_NUM"

    info "goreleaser release --clean..."
    goreleaser release --clean -f .goreleaser.yaml

    info "git push origin main --tags..."
    git push origin main --tags

    ok "GitHub Release v$VER_NUM 已发布"
}

# ══════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════

echo "============================================"
echo " ddns-manager 发布"
echo " Version: $FULL_VERSION"
echo " Mode:    $( $DRY_RUN && echo 'dry-run' || echo 'production')"
echo " Deploy:  $( $SKIP_DEPLOY && echo 'skip' || echo "${DEPLOY_HOST:-未配置}")"
echo " GitHub:  $( $WITH_GITHUB && echo 'yes' || echo 'manual')"
echo "============================================"

sanitize_check
preflight
do_build
do_deploy
do_verify
do_github_release

# ── 结果 ──
echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "============================================"
    echo -e " ${GREEN}发布完成 v$FULL_VERSION${NC}"
    echo "============================================"
    if ! $WITH_GITHUB && ! $DRY_RUN; then
        echo ""
        echo "内部部署已完成。确认运行正常后执行:"
        echo "  bash scripts/release.sh --with-github"
        echo ""
    fi
else
    echo "============================================"
    echo -e " ${RED}发布有部分失败${NC}"
    echo "============================================"
    exit 1
fi
