package acme

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// T50（v1.6.72 P0-F1 / A4-D4）：**全部公开入口**均不得自死锁（表驱动 6 项）。
//
// 生产复现（H2）：IssueDNS01 持 m.mu → issueViaAcmeSh → acmeShEnvFor 再次获取
// m.mu（sync.Mutex 不可重入）⇒ 请求永久挂起、acme.sh 从未启动、每次请求泄漏一个
// goroutine。此前测试均直接调用内部函数（renewOne / issueViaAcmeSh / InstallCert），
// 因而完全绕过了外层锁 ⇒ 未被发现。
//
// v1.6.72 A4：由「单入口」扩展为**表驱动 6 项**（覆盖 Manager 全部公开入口）：
//
//	IssueDNS01 · IssueHTTP01 · RenewByName · RenewWithOutcomes · InstallCert · AcmeShAvailable
//
// 判据：走**真实公开入口** + 真实 fake acme.sh，必须在**看门狗时限内返回**（10s）。
//
// 设计要点（A4 实施期修正，均已实测）：
//   - **goroutine 安全**：看门狗 goroutine **只回传 error**，断言一律在主 goroutine 执行。
//     否则 goroutine 内的 t.Fatalf ⇒ runtime.Goexit ⇒ 通道永不送达 ⇒ **假"自死锁"**。
//   - **离线保障**：包内测试可直接 `m.reg = &xacme.Account{}`（包内特权）跳过 RegisterAccount，
//     故本用例**不触网**；`internal/server` 侧无此特权，故 handler 级看门狗另议。
//   - **IssueHTTP01 的判据**（A4-① 裁定）：该入口自行 `net.Listen("tcp", m.httpPort)`（:80）
//     且其挑战走 Go 原生 ACME 客户端 ⇒ 非 root 必失败、root 下会真实外呼 ⇒ 判据只能取
//     「**在看门狗内返回**」；仅放行「端口/权限」类错误，其余（含死锁）仍上报。
func TestT50_PublicEntryPoints_NoSelfDeadlock(t *testing.T) {
	cases := []struct {
		name   string
		prep   func(t *testing.T, root string) // 主 goroutine 内设置夹具（可空）
		run    func(m *Manager) error
		needSh bool // 是否要求 acme.sh 被真正调用（防空转）；IssueHTTP01 在绑定失败处提前返回
	}{
		{
			name: "IssueDNS01",
			run: func(m *Manager) error {
				_, err := m.IssueDNS01(context.Background(), []string{"a.example.com"},
					DNSProvider{Name: "alidns", KeyID: "k", KeySecret: "s", KeyName: "权威"})
				return err
			},
			needSh: true,
		},
		{
			name: "IssueHTTP01",
			run: func(m *Manager) error {
				_, err := m.IssueHTTP01(context.Background(), []string{"b.example.com"})
				if err != nil && (strings.Contains(err.Error(), "need root for port 80") ||
					strings.Contains(err.Error(), "listen")) {
					return nil // 见函数头注释：离线判据 = 「已返回」
				}
				return err
			},
			needSh: false,
		},
		{
			name: "RenewByName",
			prep: func(t *testing.T, root string) {
				newCert, _ := selfSigned(t, "x.example.com")
				repl := filepath.Join(root, "replacement.pem")
				if err := os.WriteFile(repl, newCert, 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("FAKE_REPLACE", repl) // 使假 acme.sh 真正替换 fullchain（否则 KindNotReplaced）
			},
			run: func(m *Manager) error {
				if !m.RenewByName(context.Background(), "x.example.com") {
					return fmt.Errorf("RenewByName 返回 false（应成功）")
				}
				return nil
			},
			needSh: true,
		},
		{
			name: "RenewWithOutcomes",
			prep: func(t *testing.T, root string) {
				// 该入口用 force=false ⇒ 必须先让证书"到期"，否则 not-due 预检会在调用
				// acme.sh 之前返回（KindSkipped）⇒ 触发 requireAcmeShInvoked 的空转防护。
				makeCertDue(t, root, 10)
				newCert, _ := selfSigned(t, "x.example.com")
				repl := filepath.Join(root, "replacement.pem")
				if err := os.WriteFile(repl, newCert, 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("FAKE_REPLACE", repl)
			},
			run: func(m *Manager) error {
				if outs := m.RenewWithOutcomes(context.Background()); len(outs) == 0 {
					return fmt.Errorf("RenewWithOutcomes 未返回任何结果（harness 证书应被发现）")
				}
				return nil
			},
			needSh: true,
		},
		{
			name: "InstallCert",
			prep: func(t *testing.T, root string) {
				if err := os.MkdirAll(filepath.Join(root, "certs", "acme-x.example.com"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			run: func(m *Manager) error {
				return m.InstallCert(context.Background(), "x.example.com",
					filepath.Join(m.certsDir, "acme-x.example.com"))
			},
			needSh: true,
		},
		{
			name: "AcmeShAvailable",
			run: func(m *Manager) error {
				_ = m.AcmeShAvailable()
				return nil
			},
			needSh: true, // 该入口本身即执行 `acme.sh --version`
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, h, root := setupHarness(t)
			m.reg = &xacme.Account{} // 跳过 RegisterAccount（其需要网络）
			if tc.prep != nil {
				tc.prep(t, root)
			}

			errc := make(chan error, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						errc <- fmt.Errorf("panic: %v", r)
					}
				}()
				errc <- tc.run(m)
			}()

			select {
			case err := <-errc:
				if err != nil {
					t.Fatalf("%s 返回错误：%v", tc.name, err)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("%s 未在 10s 内返回 ⇒ 自死锁（m.mu 非可重入）。\n%s",
					tc.name, goroutineDump(tc.name, "acmeShEnvFor", "issueViaAcmeSh", "renewOne"))
			}

			// 断言在主 goroutine（防 goroutine 内 Fatal 导致的假"自死锁"），并防"空转通过"。
			if tc.needSh {
				requireAcmeShInvoked(t, h)
			}
		})
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

// T51（v1.6.72 P0-F1 / A5-D5）：结构性守卫 —— 锁使用规则 L1/L2/L3 的**包内静态护栏**。
//
// 锁使用规则（三条，跨包统一口径；详见
// internal-docs/acme-consistency-timing-and-lock-order.md）：
//
//	L1（自死锁，**本守卫**）：任何一个"自身获取 m.mu"的函数，都不得在**仍持锁**的情况下
//	    直接或经包内调用链抵达另一个"自身获取 m.mu"的方法（sync.Mutex 不可重入）。
//	    该类自死锁已出现两次：v2 方案中的 addACMEMgr（评审否决）、v1.6.71 的 IssueDNS01。
//	L2（包间锁序，**包外，本守卫不覆盖**）：`acmeMu` 与 `store.mu` 是独立锁，**任何代码路径
//	    不得同时持有两者**（反向获取会死锁）；initACMEManagers 等处在持 acmeMu 时不得调用
//	    store 方法。
//	L3（跨层锁序，**本守卫不覆盖**）：`s.acmeMu → m.mu` 为**单向**允许（server 侧可在持
//	    acmeMu 时调用 mgr.SetAcmeShPath / ResolveAcmeHome / SetDNSKeyLookup）；反向
//	    （acme 内回取 server 锁）**禁止**。当前无反向路径（A4 复核 §4.2 实测确认）。
//
// 规则（判定）：F 持锁（含 defer Unlock 形式），且调用链可达 T 中方法（T = 取 m.mu 的方法及其
// 传递调用者），且 F 在锁区间内未显式 Unlock ⇒ 违规。
//
// **判别边界（A4 复核 §3 实测，务必知悉）**：本守卫只记录 `m.X(...)` 形式的**方法调用**；
// 若把取锁调用**等价改写**为非方法形态，或在基线构造之外新增持锁点，可能不被捕获
// （复核方实测：在 IssueDNS01 顶部注入 m.mu.Lock() 时 T51 未报错）。
// ⇒ 完备性分工：**L1 的结构面由本守卫承担，运行时的"真的挂起"由 T50 的 10s 看门狗承担**
// （6 项主要公开入口）。二者互补，缺一不可。
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
