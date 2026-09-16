package store

// v1.6.73 N-32：**store 级自死锁守卫**（补齐 T50/T51 只覆盖 internal/acme 的空缺）。
//
// 背景：v1.6.73 B-1 Slice 2 初版在 `loadDNSKeysToCache`（**由 LoadDNSKeys 持 s.mu 调用**）
// 内再次 `s.mu.Lock()` ⇒ `sync.RWMutex` 不可重入 ⇒ **死锁**；而症状是「`go test` 挂死
// 至超时被 SIGKILL」—— 不报错、不断言失败，属**最差形态**（登记册 N-32）。
//
// 与 acme 侧的分工（同一口径，见 internal/acme/deadlock_regression_test.go）：
//
//	T73a 运行时看门狗：store **公开入口**（含回调路径）必须在时限内返回；并断言回调**真被调用**
//	     （防空转通过）。运行时"真的挂起"由这一层承担。
//	T73b 结构性守卫 L1'：取 s.mu 的函数不得（直接或经包内传递调用）抵达另一个取 s.mu 的函数；
//	     并单独钉死"`*Locked` 助手不得取锁"（它们是给已持锁调用方用的无锁版本）。
//	T73c 回调调用点白名单：调用点集合 + **调用时是否持锁**必须与源码一致（增删 ⇒ FAIL 需评审），
//	     且"持锁调用"的点必须保留**回调契约注释**（回调内不得取 store 锁）。
//
// **判别边界（必须知悉，与 T51 同口径）**：T73b/T73c 只做**文本/AST 级近似**（仅识别 `s.X(...)`
// 形式的方法调用与 `:= s.<field>` 形式的回调赋值）。等价改写（动态派发、字段间接、非方法形态）
// 可绕过 ⇒ 结构面由 T73b/T73c 承担、运行时由 T73a 承担，二者互补，缺一不可。

import (
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

	"github.com/ocoj/ddns-manager/internal/model"
)

// ── T73a：运行时看门狗（表驱动）──

func TestT73a_StoreEntryPoints_NoSelfDeadlock(t *testing.T) {
	const limit = 8 * time.Second

	type C struct {
		name string
		// prep 在主 goroutine 内准备夹具并提供回调计数
		prep func(t *testing.T) (st *ManagerStore, run func() error, cbCalls func() int, needCb bool)
	}
	cases := []C{
		{
			name: "LoadDNSKeys（v1→v2 迁移路径 + 迁移回调）",
			prep: func(t *testing.T) (*ManagerStore, func() error, func() int, bool) {
				dir := t.TempDir()
				st, err := NewStore(dir)
				if err != nil {
					t.Fatal(err)
				}
				// 写 v1 明文 ⇒ 触发迁移（**回调在持写锁时被调用** ⇒ 本体即自死锁高危路径）
				plain := `{"k":{"name":"k","provider":"alidns","access_key_id":"a","access_key_secret":"s"}}`
				if err := os.WriteFile(filepath.Join(dir, "dns_keys.json"), []byte(plain), 0o600); err != nil {
					t.Fatal(err)
				}
				n := 0
				st.SetDNSKeysMigrationReporter(func(backupPath string, err error) {
					n++
					if err != nil {
						t.Errorf("迁移回调收到错误: %v", err)
					}
					if backupPath == "" {
						t.Error("迁移成功时回调应带回 .bak 路径")
					}
				})
				return st, func() error { _, err := st.LoadDNSKeys(); return err }, func() int { return n }, true
			},
		},
		{
			name: "SaveCertBundle（受管键冲突路径 + 冲突回调）",
			prep: func(t *testing.T) (*ManagerStore, func() error, func() int, bool) {
				dir := t.TempDir()
				st, err := NewStore(dir)
				if err != nil {
					t.Fatal(err)
				}
				bd := filepath.Join(dir, "certs", "acme-t73")
				if err := os.MkdirAll(bd, 0o700); err != nil {
					t.Fatal(err)
				}
				// 旧 meta 的受管键 domains 与 struct 权威值不一致 ⇒ 触发冲突回调
				if err := os.WriteFile(filepath.Join(bd, "meta.json"),
					[]byte(`{"acme":true,"domains":["stale.example.com"]}`), 0o600); err != nil {
					t.Fatal(err)
				}
				n := 0
				st.SetCertMetaConflictReporter(func(bundleName, key string) {
					n++
					if key != "domains" {
						t.Errorf("冲突回调应收到键名 domains，实际 %q", key)
					}
				})
				b := &CertBundle{Name: "acme-t73", Domains: []string{"new.example.com"}}
				return st, func() error { return st.SaveCertBundle(b) }, func() int { return n }, true
			},
		},
		{
			name: "缓存与读写（Nodes/DNSKeys/ACME/CertBundles/AdminState/AgentConfig）",
			prep: func(t *testing.T) (*ManagerStore, func() error, func() int, bool) {
				dir := t.TempDir()
				st, err := NewStore(dir)
				if err != nil {
					t.Fatal(err)
				}
				if err := st.SaveDNSKeys(map[string]*model.DNSKeyRecord{"k": {Name: "k", Provider: "alidns"}}); err != nil {
					t.Fatal(err)
				}
				if err := st.SaveNodes(map[string]*model.NodeRecord{"n1": {Fingerprint: "fp"}}); err != nil {
					t.Fatal(err)
				}
				if err := st.PutNode("n2", &model.NodeRecord{Fingerprint: "fp2"}); err != nil {
					t.Fatal(err)
				}
				if err := st.SaveCertBundle(&CertBundle{Name: "acme-t73b", PFXPassword: "pw"}); err != nil {
					t.Fatal(err)
				}
				if err := st.SaveACMEAccounts([]ACMEAccountConfig{{Email: "a@example.invalid", AccountKey: "k1"}}); err != nil {
					t.Fatal(err)
				}
				return st, func() error {
					if _, err := st.LoadNodes(); err != nil {
						return err
					}
					if _, err := st.GetNode("n1"); err != nil {
						return err
					}
					if _, err := st.LoadDNSKeys(); err != nil {
						return err
					}
					_ = st.DNSKeysVersion()
					if _, err := st.ListCertBundles(); err != nil {
						return err
					}
					if _, err := st.LoadCertBundle("acme-t73b"); err != nil {
						return err
					}
					if _, err := st.LoadCertMeta("acme-t73b"); err != nil {
						return err
					}
					if _, err := st.LoadACMEAccounts(); err != nil {
						return err
					}
					if err := st.UpdateACMEAccountsAtomic(func(a []ACMEAccountConfig) error { return nil }); err != nil {
						return err
					}
					if _, err := st.ValidateDNSKeysDecryptable(); err != nil {
						return err
					}
					if _, err := st.MetaPFXPassword(map[string]interface{}{"pfx_password_enc": "x"}); err == nil {
						return fmt.Errorf("损坏密文应报错（不得静默回落）")
					}
					if _, err := st.BundlePFXPassword(&CertBundle{Name: "acme-t73b"}); err != nil {
						return err
					}
					if err := st.BumpDNSKeysVersion(); err != nil {
						return err
					}
					if err := st.TrackDNSKeyUsage("k", "n1"); err != nil {
						return err
					}
					st.ResetCaches()
					if err := st.ReloadStorageKey(); err != nil {
						return err
					}
					if _, err := st.LoadDNSKeys(); err != nil { // 缓存已清 ⇒ 走磁盘慢路径
						return err
					}
					return nil
				}, func() int { return 0 }, false
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, run, cbCalls, needCb := tc.prep(t)
			_ = st
			errc := make(chan error, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						errc <- fmt.Errorf("panic: %v", r)
					}
				}()
				errc <- run()
			}()
			select {
			case err := <-errc:
				if err != nil {
					t.Fatalf("%s 返回错误：%v", tc.name, err)
				}
			case <-time.After(limit):
				t.Fatalf("%s 未在 %v 内返回 ⇒ 自死锁（s.mu 非可重入）。\n%s",
					tc.name, limit, storeGoroutineDump("loadDNSKeysToCache", "LoadDNSKeys", "SaveCertBundle", "mu", "sync"))
			}
			// 断言在主 goroutine（防 goroutine 内 Fatal 造成假"自死锁"），并防"空转通过"
			if needCb && cbCalls() == 0 {
				t.Errorf("%s：回调**从未被调用** ⇒ 本用例未覆盖持锁回调路径（空转通过）", tc.name)
			}
		})
	}
}

func storeGoroutineDump(keys ...string) string {
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

// ── T73b：结构性守卫 L1'（取锁函数不得抵取锁函数）+ `*Locked` 助手不得取锁 ──

func TestT73b_NoLockHoldingCallIntoLockTakingFunc(t *testing.T) {
	type call struct {
		line int
		name string
	}
	type fnInfo struct {
		name    string
		start   int
		end     int
		locks   []int
		unlocks []int
		calls   []call
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "store.go", nil, 0)
	if err != nil {
		t.Fatalf("解析 store.go 失败: %v", err)
	}

	var funcs []*fnInfo
	byName := map[string]*fnInfo{}
	for _, d := range file.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || len(fd.Recv.List) == 0 {
			continue
		}
		recvType := fd.Recv.List[0].Type
		if star, ok := recvType.(*ast.StarExpr); ok {
			recvType = star.X
		}
		if id, ok := recvType.(*ast.Ident); !ok || id.Name != "ManagerStore" {
			continue
		}
		if names := fd.Recv.List[0].Names; len(names) == 0 || names[0].Name != "s" {
			continue
		}
		fi := &fnInfo{
			name:  fd.Name.Name,
			start: fset.Position(fd.Pos()).Line,
			end:   fset.Position(fd.End()).Line,
		}
		isMu := func(e ast.Expr) bool {
			sel, ok := e.(*ast.SelectorExpr)
			if !ok {
				return false
			}
			id, ok := sel.X.(*ast.Ident)
			return ok && id.Name == "s" && sel.Sel.Name == "mu"
		}
		ast.Inspect(fd, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.DeferStmt:
				// `defer s.mu.Unlock()` **不算**关闭区间（它在返回时才执行）
				if sel, ok := x.Call.Fun.(*ast.SelectorExpr); ok && isMu(sel.X) &&
					strings.HasPrefix(sel.Sel.Name, "Unlock") {
					// 标记：记一条"远大于函数体"的解锁位置 ⇒ 永不关闭区间（保守）
					fi.unlocks = append(fi.unlocks, 1<<30)
					// **必须 return false**：否则 ast.Inspect 会继续深入该 DeferStmt 内部的
					// CallExpr，把这条 Unlock 也当作普通解锁记录 ⇒ 区间被错误关闭 ⇒
					// **守卫退化为空判定**（本文件自测曾踩此坑，见实现报告"自纠缺陷 2"）。
					return false
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				line := fset.Position(x.Pos()).Line
				if isMu(sel.X) {
					switch {
					case sel.Sel.Name == "Lock" || sel.Sel.Name == "RLock":
						fi.locks = append(fi.locks, line)
					case strings.HasPrefix(sel.Sel.Name, "Unlock") || sel.Sel.Name == "RUnlock":
						fi.unlocks = append(fi.unlocks, line)
					}
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "s" {
					fi.calls = append(fi.calls, call{line, sel.Sel.Name})
				}
			}
			return true
		})
		funcs = append(funcs, fi)
		byName[fi.name] = fi
	}
	if len(funcs) == 0 {
		t.Fatal("未解析到任何 *ManagerStore 方法 ⇒ 守卫失效（解析口径需更新）")
	}

	// T = 取 s.mu 的函数 + 传递可达它们的包内方法
	inT := map[string]bool{}
	lockCount := 0
	for _, f := range funcs {
		if len(f.locks) > 0 {
			inT[f.name] = true
			lockCount++
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

	// 判据：F 取锁；在其"锁区间内"（按行号近似）调用 m.X() 且 X ∈ T ⇒ 违规
	// 行号近似：对每个调用点，若存在 l ≤ line 的取锁点 l，且不存在 l < u < line 的显式解锁 u ⇒ 视为持锁
	heldAt := func(f *fnInfo, line int) bool {
		for _, l := range f.locks {
			if l > line {
				continue
			}
			closed := false
			for _, u := range f.unlocks {
				if u > l && u < line {
					closed = true
					break
				}
			}
			if !closed {
				return true
			}
		}
		return false
	}

	var bad []string
	for _, f := range funcs {
		if len(f.locks) == 0 {
			continue
		}
		for _, c := range f.calls {
			if !inT[c.name] || !heldAt(f, c.line) {
				continue
			}
			bad = append(bad, fmt.Sprintf("%s:%d 持 s.mu → 调 s.%s()（该类方法自身取 s.mu ⇒ 自死锁）",
				f.name, c.line, c.name))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("发现持锁自死锁风险 %d 处（s.mu 非可重入）：\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
	t.Logf("L1' 通过：分析 %d 个方法（其中取锁 %d 个 ⇒ T 集合 %d）", len(funcs), lockCount, len(inT))

	// 独立规则：`*Locked` 助手是"给已持锁调用方用的无锁版本" ⇒ 自身**不得**取锁
	lockedHelpers := []string{"saveNodesLocked", "saveDNSKeysLocked", "loadACMEAccountsLocked", "saveACMEAccountsLocked"}
	found := 0
	for _, name := range lockedHelpers {
		f, ok := byName[name]
		if !ok {
			continue
		}
		found++
		if len(f.locks) > 0 {
			t.Errorf("%s 是 `*Locked` 无锁助手，不得取 s.mu（否则调用方持锁时自死锁）", name)
		}
	}
	// 排除项独立断言：助手集合必须仍存在（改名/删除 ⇒ 本规则静默失效）
	if found != len(lockedHelpers) {
		t.Errorf("`*Locked` 助手只找到 %d/%d 个 ⇒ 规则可能静默失效（请同步更新名单）",
			found, len(lockedHelpers))
	}
	t.Logf("`*Locked` 无锁助手核对：%d/%d 均未取锁", found, len(lockedHelpers))
}

// ── T73c：回调调用点白名单（含"调用时是否持锁"声明 + 契约注释）──
//
// 为什么需要"声明 + 两路核验"：回调的锁态**不能只看所在函数**——
//   - `SaveCertBundle` 自己取锁，但**先 Unlock 再调用** ⇒ 局部可判定（self-locked）；
//   - `loadDNSKeysToCache` 自己**不取锁**，它是被 `LoadDNSKeys` **持写锁**调用的助手
//     ⇒ 锁态由**调用方**决定（by-contract），必须反向核验"存在持锁的调用方"。
//
// 两路都写进判据，避免把 by-contract 的点误判为无锁（那正是 N-32 死锁的形态）。
func TestT73c_CallbackInvocationSitesPinned(t *testing.T) {
	type decl struct {
		fn     string
		field  string
		locked bool // 声明：调用回调时是否持有 s.mu（self 或 by-contract 都算）
	}
	// 白名单：新增/删除/改锁态 ⇒ 本测试 FAIL ⇒ 必须显式评审（并保留契约注释）
	want := []decl{
		{fn: "SaveCertBundle", field: "certMetaConflict", locked: false},
		{fn: "loadDNSKeysToCache", field: "dnsKeysMigrationReporter", locked: true},
	}
	const contractPhrase = "回调内不得取"

	src, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(src), "\n")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "store.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	isMu := func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == "s" && sel.Sel.Name == "mu"
	}

	locks := map[string][]int{}
	unlocks := map[string][]int{}
	// callee → 调用点（用于"by-contract"反向核验）
	type callSite struct {
		caller string
		line   int
	}
	calls := map[string][]callSite{}
	funcBody := map[string]string{}
	// (fn, field) → 回调调用行号集合
	cbLines := map[string][]int{}
	cbKey := func(fn, field string) string { return fn + "\x00" + field }

	for _, d := range file.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || fd.Name == nil {
			continue
		}
		recvType := fd.Recv.List[0].Type
		if star, ok := recvType.(*ast.StarExpr); ok {
			recvType = star.X
		}
		if id, ok := recvType.(*ast.Ident); !ok || id.Name != "ManagerStore" {
			continue
		}
		fn := fd.Name.Name
		start := fset.Position(fd.Pos()).Line - 1
		end := fset.Position(fd.End()).Line
		if start >= 0 && end <= len(lines) {
			funcBody[fn] = strings.Join(lines[start:end], "\n")
		}

		fieldOf := map[string]string{}
		ast.Inspect(fd, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			lhs, ok := as.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			sel, ok := as.Rhs[0].(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "s" &&
				(sel.Sel.Name == "certMetaConflict" || sel.Sel.Name == "dnsKeysMigrationReporter") {
				fieldOf[lhs.Name] = sel.Sel.Name
			}
			return true
		})

		ast.Inspect(fd, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.DeferStmt:
				if sel, ok := x.Call.Fun.(*ast.SelectorExpr); ok && isMu(sel.X) &&
					strings.HasPrefix(sel.Sel.Name, "Unlock") {
					unlocks[fn] = append(unlocks[fn], 1<<30) // defer 不关闭区间
					return false                             // 不深入内部 CallExpr（否则区间被误关闭）
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				line := fset.Position(x.Pos()).Line
				if isMu(sel.X) {
					switch {
					case sel.Sel.Name == "Lock" || sel.Sel.Name == "RLock":
						locks[fn] = append(locks[fn], line)
					case strings.HasPrefix(sel.Sel.Name, "Unlock") || sel.Sel.Name == "RUnlock":
						unlocks[fn] = append(unlocks[fn], line)
					}
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "s" {
					calls[sel.Sel.Name] = append(calls[sel.Sel.Name], callSite{caller: fn, line: line})
				}
			}
			return true
		})

		// 回调调用点
		ast.Inspect(fd, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := ce.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			field, isCb := fieldOf[id.Name]
			if !isCb {
				return true
			}
			k := cbKey(fn, field)
			cbLines[k] = append(cbLines[k], fset.Position(ce.Pos()).Line)
			return true
		})
	}

	// 局部可判定：函数自身取锁且该行未被显式解锁关闭 ⇒ 持锁
	heldSelf := func(fn string, line int) bool {
		for _, l := range locks[fn] {
			if l > line {
				continue
			}
			closed := false
			for _, u := range unlocks[fn] {
				if u > l && u < line {
					closed = true
					break
				}
			}
			if !closed {
				return true
			}
		}
		return false
	}

	var got []decl
	var problems []string
	for k, lns := range cbLines {
		parts := strings.SplitN(k, "\x00", 2)
		fn, field := parts[0], parts[1]
		// 两路核验：任一回调调用点"局部持锁"，或"存在持锁的调用方"（by-contract）
		locked := false
		how := ""
		for _, ln := range lns {
			if heldSelf(fn, ln) {
				locked, how = true, "self"
				break
			}
		}
		if !locked {
			for _, cs := range calls[fn] {
				if heldSelf(cs.caller, cs.line) {
					locked, how = true, "by-contract("+cs.caller+":"+fmt.Sprint(cs.line)+")"
					break
				}
			}
		}
		got = append(got, decl{fn: fn, field: field, locked: locked})
		if locked && !strings.Contains(funcBody[fn], contractPhrase) {
			problems = append(problems, fmt.Sprintf(
				"%s 在**持锁**时调用回调 %s（%s）但缺少契约注释（需含「%s」）",
				fn, field, how, contractPhrase))
		}
		if locked {
			t.Logf("持锁回调点：%s → %s（%s；%d 个调用点）", fn, field, how, len(lns))
		}
	}

	norm := func(d decl) string { return fmt.Sprintf("%s/%s/locked=%v", d.fn, d.field, d.locked) }
	var wantSet, gotSet []string
	for _, d := range want {
		wantSet = append(wantSet, norm(d))
	}
	for _, d := range got {
		gotSet = append(gotSet, norm(d))
	}
	sort.Strings(wantSet)
	sort.Strings(gotSet)
	if strings.Join(wantSet, "|") != strings.Join(gotSet, "|") {
		t.Errorf("回调调用点白名单不一致（增删或锁态改变 ⇒ 必须显式评审并更新契约注释）：\n  期望: %v\n  实际: %v",
			wantSet, gotSet)
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		t.Errorf("持锁回调调用点缺少契约注释：\n  %s", strings.Join(problems, "\n  "))
	}
	// 非空判定：发现 0 处回调点 ⇒ 判据失效（解析口径需更新）
	if len(got) == 0 {
		t.Error("未发现任何回调调用点 ⇒ 本守卫已退化为空判定")
	}
	lockedN := 0
	for _, d := range got {
		if d.locked {
			lockedN++
		}
	}
	t.Logf("回调调用点核对：%d 处（其中持锁 %d 处）", len(got), lockedN)
}
