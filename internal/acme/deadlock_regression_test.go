package acme

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// T50（v1.6.72 P0-F1）：公开入口 IssueDNS01 不得自死锁。
//
// 生产复现（H2）：IssueDNS01 持 m.mu → issueViaAcmeSh → acmeShEnvFor 再次获取
// m.mu（sync.Mutex 不可重入）⇒ 请求永久挂起、acme.sh 从未启动、每次请求泄漏一个
// goroutine。此前测试均直接调用内部函数（renewOne / issueViaAcmeSh / InstallCert），
// 因而完全绕过了外层锁 ⇒ 未被发现。
//
// 判据：走**真实公开入口** + 真实 fake acme.sh，必须在看门狗时限内返回。
func TestT50_IssueDNS01_NoSelfDeadlock(t *testing.T) {
	m, h, _ := setupHarness(t)
	m.reg = &xacme.Account{} // 跳过 RegisterAccount（其需要网络）

	type result struct {
		name string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		n, err := m.IssueDNS01(context.Background(), []string{"x.example.com"},
			DNSProvider{Name: "alidns", KeyID: "k", KeySecret: "s", KeyName: "权威"})
		done <- result{n, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("IssueDNS01 返回错误（应成功）: %v", r.err)
		}
		if r.name == "" {
			t.Fatal("IssueDNS01 返回空证书名")
		}
		requireAcmeShInvoked(t, h) // 防"空转通过"
	case <-time.After(10 * time.Second):
		t.Fatalf("IssueDNS01 未在 10s 内返回 ⇒ 自死锁（m.mu 非可重入）。\n%s",
			goroutineDump("IssueDNS01", "acmeShEnvFor", "issueViaAcmeSh"))
	}
}

// goroutineDump 只保留含指定关键词的 goroutine 栈，避免整机栈噪音。
func goroutineDump(keys ...string) string {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	blocks := strings.Split(string(buf[:n]), "\n\n")
	var out []string
	for _, b := range blocks {
		for _, k := range keys {
			if strings.Contains(b, k) {
				out = append(out, b)
				break
			}
		}
	}
	if len(out) == 0 {
		return "（未匹配到相关 goroutine，仍判定为超时）"
	}
	return strings.Join(out, "\n\n")
}

// T51（v1.6.72 P0-F1）：结构性守卫 —— 任何一个"自身获取 m.mu"的函数，都不得在
// **仍持锁**的情况下直接或经包内调用链抵达另一个"自身获取 m.mu"的方法。
//
// 该类自死锁已出现两次：v2 方案中的 addACMEMgr（评审否决）、本次 IssueDNS01。
// 规则：F 持锁（含 defer Unlock 形式），且调用链可达 T 中方法（T = 取 m.mu 的方法及其
// 传递调用者），且 F 在锁区间内未显式 Unlock ⇒ 违规。
func TestT51_NoLockHoldingCallIntoLockTakingMethod(t *testing.T) {
	type call struct {
		line int
		name string
	}
	type fnInfo struct {
		name        string
		locks       []int
		unlocks     []int
		deferUnlock bool
		calls       []call
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "acme.go", nil, 0)
	if err != nil {
		t.Fatalf("解析 acme.go 失败: %v", err)
	}

	var funcs []*fnInfo
	for _, d := range file.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || len(fd.Recv.List) == 0 {
			continue
		}
		// 仅分析 receiver 名为 m 的方法（形如 func (m *Manager) X()，需解开 StarExpr）
		recvType := fd.Recv.List[0].Type
		if star, ok := recvType.(*ast.StarExpr); ok {
			recvType = star.X
		}
		recvIdent, ok := recvType.(*ast.Ident)
		if !ok || recvIdent.Name != "Manager" {
			continue
		}
		if names := fd.Recv.List[0].Names; len(names) == 0 || names[0].Name != "m" {
			continue
		}
		fi := &fnInfo{name: fd.Name.Name}
		// isMMu 判断表达式是否为 `m.mu`（m.mu.Lock() 的 Fun 是嵌套 SelectorExpr）
		isMMu := func(e ast.Expr) bool {
			sel, ok := e.(*ast.SelectorExpr)
			if !ok {
				return false
			}
			id, ok := sel.X.(*ast.Ident)
			return ok && id.Name == "m" && sel.Sel.Name == "mu"
		}
		ast.Inspect(fd, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.DeferStmt:
				if s, ok := x.Call.Fun.(*ast.SelectorExpr); ok && isMMu(s.X) &&
					strings.HasPrefix(s.Sel.Name, "Unlock") {
					fi.deferUnlock = true
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				line := fset.Position(x.Pos()).Line
				if isMMu(sel.X) { // m.mu.Lock() / m.mu.Unlock()
					switch {
					case sel.Sel.Name == "Lock" || sel.Sel.Name == "RLock":
						fi.locks = append(fi.locks, line)
					case strings.HasPrefix(sel.Sel.Name, "Unlock") || sel.Sel.Name == "RUnlock":
						fi.unlocks = append(fi.unlocks, line)
					}
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok || id.Name != "m" { // 仅记录 m.X(...) 形式的方法调用
					return true
				}
				fi.calls = append(fi.calls, call{line, sel.Sel.Name})
			}
			return true
		})
		funcs = append(funcs, fi)
	}

	// T：取 m.mu 的方法 + 传递可达它们的包内方法
	inT := map[string]bool{}
	for _, f := range funcs {
		if len(f.locks) > 0 {
			inT[f.name] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for _, f := range funcs {
			if inT[f.name] {
				continue
			}
			for _, c := range f.calls {
				if inT[c.name] {
					inT[f.name] = true
					changed = true
					break
				}
			}
		}
	}

	var bad []string
	for _, f := range funcs {
		if len(f.locks) == 0 {
			continue
		}
		first := f.locks[0]
		for _, c := range f.calls {
			if !inT[c.name] || c.line < first {
				continue
			}
			held := f.deferUnlock
			if !held {
				held = true
				for _, u := range f.unlocks {
					if u > first && u < c.line {
						held = false
						break
					}
				}
			}
			if held {
				bad = append(bad, strings.Join([]string{
					f.name, ":", itoa(first), "持 m.mu",
					"→ 在 :" + itoa(c.line) + " 调用 m." + c.name + "()（该类方法自身取 m.mu ⇒ 自死锁）",
				}, " "))
			}
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("发现持锁自死锁风险 %d 处（m.mu 不可重入）：\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
	t.Logf("已分析 %d 个方法；T 集合大小 %d（取 m.mu 的方法及其传递调用者）", len(funcs), len(inT))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
