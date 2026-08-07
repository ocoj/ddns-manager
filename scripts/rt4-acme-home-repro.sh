#!/usr/bin/env bash
# RT4 / RT5 —— v1.6.71 N1（acme.sh home）的真实环境复现
#
# RT4: 以 `env -i`（**无 HOME、无 LE_WORKING_DIR**）运行 N1 的 Go 测试。
#      这是唯一能证明"代码兜底独立生效、而非依赖部署层环境"的方式 ——
#      普通 `go test` 的进程天生带 HOME，结构上无法复现 systemd 的状态（I27）。
#
# RT5: 用**真实 acme.sh** 探测 home 判定（三形态），确认 `LE_WORKING_DIR` 才是
#      acme.sh 读取的变量、且它是唯一能把 home 钉住的手段。
#      本机无 acme.sh 时自动 SKIP（可在生产机运行：ACME_SH=/root/.acme.sh/acme.sh）。
#
# 自包含、只读仓库、沙箱自动清理。
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
PASS=0; FAIL=0; SKIP=0
ok()   { echo "  ✅ PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  ❌ FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "  ⏭️  SKIP: $1"; SKIP=$((SKIP+1)); }

D=$(mktemp -d); trap 'rm -rf "$D"' EXIT

echo "════════ RT4：env -i（无 HOME）下的 N1 端到端 ════════"
# env -i 会清空 Go 工具链所需变量：显式透传，但**保持 HOME 为空**（这才是要复现的状态）
GOENVV=()
for k in GOROOT GOPATH GOMODCACHE GOCACHE GOFLAGS GOPROXY GOSUMDB GOPRIVATE; do
  v="$(go env "$k" 2>/dev/null || true)"
  [ -n "$v" ] && GOENVV+=("$k=$v")
done
if ! command -v go >/dev/null 2>&1; then
  skip "本机无 go 工具链（RT4 需在开发机运行）"
elif env -i PATH="$PATH" HOME= "${GOENVV[@]}" \
      bash -c "cd '$REPO' && go test ./internal/acme/ -count=1 -run 'TestT34_Renew_PinnedHomeInChildEnv|TestT39_InstallCert|TestT41d_Renew' -v" \
      > "$D/rt4.out" 2>&1; then
  if grep -q "^--- PASS: TestT34_Renew_PinnedHomeInChildEnv" "$D/rt4.out" \
     && grep -q "^--- PASS: TestT41d_Renew_NoHome_FailFastAndAcmeShNeverCalled" "$D/rt4.out"; then
    ok "无 HOME 环境下：home 被显式固定（T34）且不可判定时 fail-fast（T41d）"
  else
    bad "测试通过但关键用例未见 PASS（输出见下）"; sed 's/^/     /' "$D/rt4.out" | tail -20
  fi
else
  bad "env -i 下测试失败"; sed 's/^/     /' "$D/rt4.out" | tail -25
fi

echo
echo "════════ RT5：真实 acme.sh 的 home 判定探测 ════════"
ACME_SH="${ACME_SH:-}"
if [ -z "$ACME_SH" ]; then
  for c in "$(command -v acme.sh 2>/dev/null)" /root/.acme.sh/acme.sh /usr/local/bin/acme.sh; do
    [ -n "$c" ] && [ -f "$c" ] && ACME_SH="$c" && break
  done
fi
if [ -z "$ACME_SH" ] || [ ! -f "$ACME_SH" ]; then
  skip "未找到 acme.sh（可用 ACME_SH=/path/to/acme.sh 指定；生产机：ACME_SH=/root/.acme.sh/acme.sh）"
else
  echo "  使用 acme.sh: $ACME_SH ($("$ACME_SH" --version 2>/dev/null | tail -1))"
  probe() { # $1: LE_WORKING_DIR（可空）  $2: HOME（可空）
    local lwd="$1" home="$2" envargs=()
    [ -n "$lwd" ] && envargs+=("LE_WORKING_DIR=$lwd")
    [ -n "$home" ] && envargs+=("HOME=$home")
    env -i PATH=/usr/bin:/bin "${envargs[@]}" "$ACME_SH" \
        --install-cert -d rt.example.com 2>&1 \
      | sed -n "s/.*Cannot find path: '\([^']*\)'.*/\1/p" | head -1
  }
  get() {
    env -i PATH=/usr/bin:/bin "$ACME_SH" --install-cert -d rt.example.com 2>&1
  }

  # ① 无 HOME、无 LE_WORKING_DIR ⇒ 必须落到 /.acme.sh（缺陷机制的实证）
  got=$(probe "" "")
  case "$got" in
    /.acme.sh/*) ok "无 HOME 时 acme.sh 的 home = /.acme.sh（缺陷机制实证：$got）" ;;
    "") bad "未能解析出路径（acme.sh 输出异常）"; get | sed 's/^/     /' | tail -5 ;;
    *)  bad "无 HOME 时 home = $got（预期 /.acme.sh/…）" ;;
  esac

  # ② LE_WORKING_DIR 生效 ⇒ home 被钉到沙箱
  got=$(probe "$D/lwd" "")
  case "$got" in
    "$D/lwd"/*) ok "LE_WORKING_DIR 生效（home = $got）" ;;
    *) bad "LE_WORKING_DIR 未生效：home = $got（预期 $D/lwd/…）" ;;
  esac

  # ③ HOME 生效 ⇒ home = $HOME/.acme.sh
  got=$(probe "" "$D/fh")
  case "$got" in
    "$D/fh/.acme.sh"/*) ok "HOME 生效（home = $got）" ;;
    *) bad "HOME 未生效：home = $got（预期 $D/fh/.acme.sh/…）" ;;
  esac

  # ④ ACME_HOME 不被识别（防止后人误用该变量名）
  got=$(env -i PATH=/usr/bin:/bin ACME_HOME="$D/acmehome-probe" "$ACME_SH" \
          --install-cert -d rt.example.com 2>&1 \
        | sed -n "s/.*Cannot find path: '\([^']*\)'.*/\1/p" | head -1)
  case "$got" in
    /.acme.sh/*) ok "ACME_HOME 不被识别（仍走默认：$got）—— 必须用 LE_WORKING_DIR" ;;
    *) bad "ACME_HOME 竟生效（$got）—— 请重新核对该变量的语义" ;;
  esac
fi

echo
echo "════════ 汇总：PASS=$PASS FAIL=$FAIL SKIP=$SKIP ════════"
[ "$FAIL" -eq 0 ] || exit 1
