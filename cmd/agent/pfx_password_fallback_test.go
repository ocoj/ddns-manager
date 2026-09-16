package main

// v1.6.73 修复：PFX 默认口令兜底路径的「口令传递」缺陷（cmd/agent/main.go，Agent 侧）
//
// 缺陷：importPFXToIIS 在「默认口令兜底导入成功」时**只更新 out/err，未更新口令变量**，
// 而紧随其后的指纹提取 extractPFXInfo 仍用**旧口令** ⇒ `certutil -dump` 认证失败返回空指纹
// ⇒ 函数返回 false（**尽管证书已成功导入证书存储**）⇒ 调用方判定「Modern PFX 失败」
// ⇒ 降级 Legacy ⇒ 再降级 openssl ⇒ **三重重复导入 + 虚假失败审计 + 绑定被跳过**。
//
// 本文件覆盖：
//   T74a 兜底成功 ⇒ 生效口令必须是**默认口令**（核心断言，旧实现返回入参 ⇒ FAIL）
//   T74b 首次成功 ⇒ 生效口令 = 入参，且**不得**多余重试
//   T74c 两次均失败 ⇒ 生效口令 = 入参 + Err 非 nil（调用方须报失败）
//   T74d 非密码类错误 ⇒ **不得**用默认口令兜底（否则掩盖真实故障）
//   T74e 入参已是默认口令且失败 ⇒ **不得**同口令重试（无意义）
//   T74f 正控：假 runner 确实被调用 + 口令序列精确匹配（防空转/防断言空真）
//   T74g 结构性守卫：importPFXToIIS 内**兜底调用之后不得再使用入参 pfxPassword**
//
// 注：Agent 的 certutil 路径无法在 Linux 上真跑（无 certutil），故按项目惯例把「决策逻辑」
// 抽成可注入 runner 的纯函数 importPFXWithFallback 并对其离线断言；真实 certutil 的行为
// 由 Windows 侧验收（Runbook H2''/H3''）覆盖。

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/ocoj/ddns-manager/internal/crypto"
)

type t74Result struct {
	out []byte
	err error
}

// t74Runner 记录每次 certutil 调用的完整参数，并按序返回预设结果。
type t74Runner struct {
	calls   [][]string
	results []t74Result
}

func (r *t74Runner) run(args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	i := len(r.calls) - 1
	if i < len(r.results) {
		return r.results[i].out, r.results[i].err
	}
	return nil, errors.New("T74: 意外的额外 certutil 调用（多余重试？）")
}

// pwOf 取出调用的 -p 参数值（缺失返回 ""）。
func pwOf(call []string) string {
	for i, a := range call {
		if a == "-p" && i+1 < len(call) {
			return call[i+1]
		}
	}
	return ""
}

var errT74 = errors.New("exit status 1")

// pwErrOut 模拟中文 Windows 的密码错误输出（GBK 乱码 + hex 错误码）。
func pwErrOut() []byte {
	return []byte("\xc3\xdc\xc2\xeb\xb4\xed\xce\xf3 0x80070056 (WIN32: 2147942486)\r\n")
}

const t74CustomPw = "user-custom-pw"

func TestT74a_FallbackSuccessYieldsDefaultPassword(t *testing.T) {
	r := &t74Runner{results: []t74Result{
		{out: pwErrOut(), err: errT74},  // 初审：口令不符
		{out: []byte("导入成功"), err: nil}, // 兜底：默认口令成功
	}}
	res := importPFXWithFallback(r.run, "cert.pfx", t74CustomPw)

	if len(r.calls) != 2 {
		t.Fatalf("期望 2 次 certutil 调用（初审 + 兜底），实际 %d", len(r.calls))
	}
	if got := pwOf(r.calls[0]); got != t74CustomPw {
		t.Errorf("首次调用应使用入参口令 %q，实际 %q", t74CustomPw, got)
	}
	if got := pwOf(r.calls[1]); got != crypto.DefaultPFXPassword {
		t.Errorf("兜底调用应使用默认口令 %q，实际 %q", crypto.DefaultPFXPassword, got)
	}
	if !res.FallbackAttempted {
		t.Error("FallbackAttempted 应为 true")
	}
	if res.Err != nil {
		t.Fatalf("兜底成功后 Err 应为 nil，实际 %v", res.Err)
	}
	// ★ 核心断言：生效口令必须是默认口令。旧实现返回入参口令 ⇒ 下游 extractPFXInfo
	//   会用错口令 ⇒ 空指纹 ⇒ 误报失败 ⇒ 三重降级级联。
	if res.EffectivePassword != crypto.DefaultPFXPassword {
		t.Errorf("兜底成功后生效口令必须是默认口令 %q，实际 %q（旧缺陷形态）",
			crypto.DefaultPFXPassword, res.EffectivePassword)
	}
	// 正控：Out 应来自**生效的那次**尝试（兜底输出），而非失败输出
	if string(res.Out) != "导入成功" {
		t.Errorf("成功后 Out 应为生效尝试的输出 %q，实际 %q", "导入成功", string(res.Out))
	}
	if string(res.FallbackOut) != "导入成功" {
		t.Errorf("FallbackOut 应保留兜底输出，实际 %q", string(res.FallbackOut))
	}
}

func TestT74b_FirstAttemptSuccessNoRetry(t *testing.T) {
	r := &t74Runner{results: []t74Result{{out: []byte("导入成功"), err: nil}}}
	res := importPFXWithFallback(r.run, "cert.pfx", t74CustomPw)

	if len(r.calls) != 1 {
		t.Errorf("首次即成功 ⇒ 不得重试（实际调用 %d 次）", len(r.calls))
	}
	if res.FallbackAttempted {
		t.Error("FallbackAttempted 应为 false")
	}
	if res.EffectivePassword != t74CustomPw {
		t.Errorf("生效口令应为入参 %q，实际 %q", t74CustomPw, res.EffectivePassword)
	}
	if res.Err != nil {
		t.Errorf("Err 应为 nil，实际 %v", res.Err)
	}
}

func TestT74c_BothAttemptsFail(t *testing.T) {
	r := &t74Runner{results: []t74Result{
		{out: pwErrOut(), err: errT74},
		{out: []byte("0x80070056 仍失败"), err: errT74},
	}}
	res := importPFXWithFallback(r.run, "cert.pfx", t74CustomPw)

	if len(r.calls) != 2 {
		t.Errorf("期望 2 次调用，实际 %d", len(r.calls))
	}
	if !res.FallbackAttempted {
		t.Error("FallbackAttempted 应为 true（已尝试兜底）")
	}
	if res.Err == nil {
		t.Error("两次均失败 ⇒ Err 必须非 nil（调用方须报失败）")
	}
	if res.EffectivePassword != t74CustomPw {
		t.Errorf("失败时生效口令应保持入参 %q，实际 %q", t74CustomPw, res.EffectivePassword)
	}
	if !errors.Is(res.FallbackErr, errT74) {
		t.Errorf("FallbackErr 应保留兜底错误，实际 %v", res.FallbackErr)
	}
}

func TestT74d_NonPasswordErrorMustNotFallBack(t *testing.T) {
	// 权限/文件损坏等非密码错误：用默认口令兜底会**掩盖真实故障**且必然再次失败
	r := &t74Runner{results: []t74Result{
		{out: []byte("0x80070005 (WIN32: 5) 拒绝访问"), err: errT74},
	}}
	res := importPFXWithFallback(r.run, "cert.pfx", t74CustomPw)

	if len(r.calls) != 1 {
		t.Errorf("非密码类错误**不得**触发默认口令兜底（实际调用 %d 次）", len(r.calls))
	}
	if res.FallbackAttempted {
		t.Error("FallbackAttempted 应为 false")
	}
	if res.Err == nil {
		t.Error("Err 必须非 nil")
	}
	if res.EffectivePassword != t74CustomPw {
		t.Errorf("生效口令应保持入参 %q，实际 %q", t74CustomPw, res.EffectivePassword)
	}
}

func TestT74e_AlreadyDefaultPasswordNoPointlessRetry(t *testing.T) {
	r := &t74Runner{results: []t74Result{
		{out: pwErrOut(), err: errT74},
	}}
	res := importPFXWithFallback(r.run, "cert.pfx", crypto.DefaultPFXPassword)

	if len(r.calls) != 1 {
		t.Errorf("入参已是默认口令 ⇒ 同口令重试无意义（实际调用 %d 次）", len(r.calls))
	}
	if res.FallbackAttempted {
		t.Error("FallbackAttempted 应为 false")
	}
	if res.Err == nil {
		t.Error("Err 必须非 nil")
	}
}

func TestT74f_PositiveControl_RunnerActuallyInvokedWithExpectedArgs(t *testing.T) {
	r := &t74Runner{results: []t74Result{
		{out: pwErrOut(), err: errT74},
		{out: []byte("ok"), err: nil},
	}}
	_ = importPFXWithFallback(r.run, "the-cert.pfx", t74CustomPw)

	// 正控 1：runner 确实被调用（否则上面的断言全部空真）
	if len(r.calls) == 0 {
		t.Fatal("正控失败：假 runner 未被调用 ⇒ 本文件断言无效")
	}
	// 正控 2：参数形状精确匹配 —— 若实现改为丢弃 -p 或换文件，此处必须失败
	for i, c := range r.calls {
		want := []string{"-importpfx", "-p", "", "-enterprise", "the-cert.pfx"}
		if len(c) != len(want) {
			t.Fatalf("第 %d 次调用参数个数 %d，期望 %d：%v", i+1, len(c), len(want), c)
		}
		for j := range want {
			if j == 2 { // 口令位单独校验（见下）
				continue
			}
			if c[j] != want[j] {
				t.Errorf("第 %d 次调用参数[%d] = %q，期望 %q", i+1, j, c[j], want[j])
			}
		}
	}
	if got := pwOf(r.calls[0]); got != t74CustomPw {
		t.Errorf("第 1 次口令 = %q，期望 %q", got, t74CustomPw)
	}
	if got := pwOf(r.calls[1]); got != crypto.DefaultPFXPassword {
		t.Errorf("第 2 次口令 = %q，期望 %q", got, crypto.DefaultPFXPassword)
	}
}

// ── T74g：结构性守卫 —— 兜底调用之后不得再使用入参 pfxPassword ──
//
// 为什么需要结构守卫：T74a 只证明 **helper 返回值**正确；而本缺陷的形态是
// 「**调用方忽略了返回值**、继续用入参口令」。等价回归（例如把 effectivePFXPassword
// 换回 pfxPassword）不会被 T74a 捕获 ⇒ 必须有针对调用方的静态断言。
// 判据：`importPFXToIIS` 内标识符 `pfxPassword` 的**最后一个使用点必须早于**
// importPFXWithFallback 调用行（即其后不得再出现）。允许的前置使用：函数首部
// 「删除旧证书」所需的 extractPFXInfo 预取（此时尚不知生效口令）。
func TestT74g_NoStalePasswordAfterFallbackCall(t *testing.T) {
	const file = "main.go"
	const fnName = "importPFXToIIS"
	const callName = "importPFXWithFallback"

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s 失败: %v", file, err)
	}

	var target *ast.FuncDecl
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if ok && fd.Name != nil && fd.Name.Name == fnName {
			target = fd
			break
		}
	}
	if target == nil {
		t.Fatalf("未找到函数 %s ⇒ 本守卫已失效（函数被改名/删除）", fnName)
	}

	callLine := 0
	var useLines []int
	ast.Inspect(target, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if ok {
			if id, ok := ce.Fun.(*ast.Ident); ok && id.Name == callName {
				callLine = fset.Position(ce.Pos()).Line
			}
		}
		if id, ok := n.(*ast.Ident); ok && id.Name == "pfxPassword" {
			// 仅统计**使用**（非声明）：声明位于该函数的参数列表内
			if target.Type.Params != nil {
				declPos := fset.Position(target.Type.Params.Pos()).Line
				declEnd := fset.Position(target.Type.Params.End()).Line
				l := fset.Position(id.Pos()).Line
				if l >= declPos && l <= declEnd {
					return true
				}
			}
			useLines = append(useLines, fset.Position(id.Pos()).Line)
		}
		return true
	})

	if callLine == 0 {
		t.Fatalf("%s 内未找到对 %s 的调用 ⇒ 本守卫失效（防空真）", fnName, callName)
	}
	if len(useLines) == 0 {
		t.Fatalf("%s 内未发现 pfxPassword 使用点 ⇒ 判据口径需复核（防空真）", fnName)
	}
	var stale []int
	for _, l := range useLines {
		if l > callLine {
			stale = append(stale, l)
		}
	}
	if len(stale) > 0 {
		t.Errorf("%s 在 %s 调用（第 %d 行）**之后**仍使用入参 pfxPassword（行 %v）——\n"+
			"这正是 v1.6.73 修复的缺陷形态：兜底成功后必须改用 res.EffectivePassword，\n"+
			"否则指纹提取会用错口令 ⇒ 证书已导入却报失败 ⇒ Modern→Legacy→openssl 三重降级。",
			fnName, callName, callLine, stale)
	}
	t.Logf("T74g 通过：%s 内 pfxPassword 使用点 %v，全部早于 %s 调用行 %d",
		fnName, useLines, callName, callLine)
}
