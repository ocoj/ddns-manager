package server

// v1.6.71 N1 测试：acme.sh 路径 + home 的接线自检（I29）、cert.provider 校验（C5/T44）、
// 以及 fail-fast 的审计去重（Q4/Q6）。
//
// 规格：internal-docs/audits/2026-09-16-acme-renew-N1-N2-followup-plan-v3.md §1.4/§4

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ocoj/ddns-manager/internal/acme"
	srvcfg "github.com/ocoj/ddns-manager/internal/config"
)

// T49 [D]: 未接线（缺 acme.sh 路径或未固定 home）的 Manager 必须被启动自检
// 显式报出 error —— 否则 fail-fast 会以"续期莫名失败"的形式静默出现。
func TestT49_StartupAudit_AcmeShWiring(t *testing.T) {
	root := t.TempDir()
	homeDir := filepath.Join(root, "acme-home")
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(homeDir, "account.conf"), []byte("SAVED_MARKER=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "acme.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LE_WORKING_DIR", homeDir)

	s, _, dir := newCertConsistencyServer(t)
	s.cfg = &srvcfg.ManagerConfig{DataDir: dir}
	s.cfg.Cert.Provider = script

	// 已接线：路径来自 cert.provider，home 来自 LE_WORKING_DIR
	wired, err := acme.New(filepath.Join(dir, "certs"), "wired@example.com", ":80")
	if err != nil {
		t.Fatal(err)
	}
	// 未接线：既不注入路径也不解析 home
	unwired, err := acme.New(filepath.Join(dir, "certs"), "unwired@example.com", ":80")
	if err != nil {
		t.Fatal(err)
	}

	s.attachAcmeShPath(wired)
	if wired.AcmeShPath() != script {
		t.Errorf("cert.provider 必须被接线（I29/C5）: got %q", wired.AcmeShPath())
	}
	if !wired.AcmeHomeConfigured() {
		t.Errorf("home 必须被固定: trace=%v", wired.AcmeHomeTrace())
	}

	s.acmeMgrs = []*acme.Manager{wired, unwired}
	s.startupAudit()

	logData := string(readFileOrNil(filepath.Join(dir, "events.log")))
	if !strings.Contains(logData, "acme.sh 接线未完成") {
		t.Error("未接线的 Manager 必须产生 error 级接线自检（I29）")
	}
	if !strings.Contains(logData, "1 个 ACME 帐号未接线 acme.sh 路径") {
		t.Errorf("自检应精确报出 1 个未接线的路径；实际日志：%s", tailLines(logData, 3))
	}
}

// T44 [D]: cert.provider 为相对路径 ⇒ 必须回退 LookPath 并告警（绝不按 cwd 解析）。
func TestT44_CertProvider_RelativePathFallsBackWithAudit(t *testing.T) {
	s, _, dir := newCertConsistencyServer(t)
	s.cfg = &srvcfg.ManagerConfig{DataDir: dir}
	s.cfg.Cert.Provider = "acme.sh" // 相对路径

	mgr, err := acme.New(filepath.Join(dir, "certs"), "rel@example.com", ":80")
	if err != nil {
		t.Fatal(err)
	}
	s.attachAcmeShPath(mgr)
	s.flushAcmeWireIssues()

	logData := string(readFileOrNil(filepath.Join(dir, "events.log")))
	if !strings.Contains(logData, "cert.provider 非绝对路径") {
		t.Errorf("相对 provider 必须告警并回退（C2）; 日志：%s", tailLines(logData, 3))
	}
	if mgr.AcmeShPath() == "acme.sh" {
		t.Error("绝不能把相对路径当作 acme.sh 路径（会以 cwd 为基准）")
	}
}

// Q4/Q6: home 不可判定时——审计**恰好一条**，且重复 flush 不再增长（去重）。
func TestT49b_HomeFailFast_AuditOnceAndDeduped(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "acme.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LE_WORKING_DIR", "")
	t.Setenv("HOME", "")

	s, _, dir := newCertConsistencyServer(t)
	s.cfg = &srvcfg.ManagerConfig{DataDir: dir}
	s.cfg.Cert.Provider = script

	mgr, err := acme.New(filepath.Join(dir, "certs"), "nohome@example.com", ":80")
	if err != nil {
		t.Fatal(err)
	}
	s.attachAcmeShPath(mgr) // 应产生 home 解析失败
	if mgr.AcmeHomeConfigured() {
		t.Fatalf("home 不应被确定: %q", mgr.AcmeHome())
	}
	if err := mgr.ResolveAcmeHome(true); err == nil {
		t.Fatal("home 不可判定必须返回错误（调用方据此 fail-fast）")
	}

	s.flushAcmeWireIssues()
	logPath := filepath.Join(dir, "events.log")
	first := strings.Count(string(readFileOrNil(logPath)), "home 解析失败")
	if first != 1 {
		t.Fatalf("home 解析失败应恰有一条审计，got %d", first)
	}
	s.flushAcmeWireIssues() // 重复 flush 不得增长
	second := strings.Count(string(readFileOrNil(logPath)), "home 解析失败")
	if second != first {
		t.Errorf("flush 必须去重（before=%d after=%d）", first, second)
	}
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// T49c [D]: C5 的静态守卫 —— attachAcmeShPath 必须覆盖**全部** Manager 构造点，
// 且**只能**出现在白名单列出的函数中。
//
// v1.6.72 A-3 加固（依第三方裁决 A3-③ / 登记项 (5.3)）：
// 原实现只遍历 `want` 中列出的**文件**、并按**具名函数**计数 ⇒「在**新函数/新文件**中新增调用点」
// **不会被发现**（复核方对抗性验证已证实，与 T55 早期版本同源缺陷）。现改为：
//
//	① **全仓扫描**（`internal/**/*.go`，排除 `_test.go` 与 `testdata`）；
//	② **总数断言** == 6（多一个 / 少一个都 FAIL）；
//	③ **精确等值断言**：`got`（相对路径→函数→次数）必须与 `want` **完全相等**
//	  ⇒ 任何未登记的函数/文件出现调用即 FAIL（"新增调用点须显式评审"真正成立）。
//
// 测试文件按设计排除（`internal/acme/renew_integration_test.go` 等含合法测试调用）。
func TestT49c_AllAcmeShWiringCallSites(t *testing.T) {
	want := map[string]map[string]int{
		"internal/server/server.go":         {"New": 1, "addACMEMgr": 1, "setACMEMgr": 1, "initACMEManagers": 2},
		"internal/server/handlers_certs.go": {"handleACMEIssue": 1},
	}
	const wantTotal = 6

	got := map[string]map[string]int{}
	var total int
	var sites []string
	// 扫描根可经环境变量覆盖 ⇒ 判别性注入可在**临时树副本**上完成（不改动真实仓库）
	root := strings.TrimSpace(os.Getenv("DDNS_TEST_SCAN_ROOT"))
	if root == "" {
		root = ".."
	}
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		key := "internal/" + filepath.ToSlash(rel)
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel == nil || sel.Sel.Name != "attachAcmeShPath" {
					return true
				}
				if got[key] == nil {
					got[key] = map[string]int{}
				}
				got[key][fd.Name.Name]++
				total++
				sites = append(sites, fset.Position(call.Pos()).String())
				return true
			})
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("扫描 internal/ 失败：%v", walkErr)
	}
	if total != wantTotal {
		t.Errorf("attachAcmeShPath 调用点总数应为 %d；实际 %d：%v（新增调用点须显式评审）",
			wantTotal, total, sites)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("接线点分布与白名单不一致 —— 任何新函数/新文件出现调用即 FAIL：\n实际: %v\n期望: %v",
			got, want)
	}
}

// T49d: G4 —— 证书集合读取**失败**时必须保守按"已有证书"处理（否则等价于"全新安装"，
// 会解锁判定表中"未初始化路径被采用"的分支）；同时留下审计。
func TestT49d_DetectLocalACMECerts_ConservativeOnReadError(t *testing.T) {
	s, _, dir := newCertConsistencyServer(t)
	certsPath := filepath.Join(dir, "certs")
	if err := os.RemoveAll(certsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certsPath, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !s.detectLocalACMECerts() {
		t.Fatal("读取失败时必须保守返回 true（按“已有证书”处理）")
	}
	s.flushAcmeWireIssues()
	if logData := string(readFileOrNil(filepath.Join(dir, "events.log"))); !strings.Contains(logData, "保守处理") {
		t.Error("保守处理必须留下审计（G4）")
	}

	// 对照组：certs 目录不存在 ⇒ 真正的全新安装 ⇒ false（不得过度收紧）
	s2, _, dir2 := newCertConsistencyServer(t)
	if err := os.RemoveAll(filepath.Join(dir2, "certs")); err != nil {
		t.Fatal(err)
	}
	if s2.detectLocalACMECerts() {
		t.Error("certs 目录不存在应视为全新安装（false）")
	}
}

// T49e: G5 —— 多账号共用同一接线故障时，审计只记一条（与通知去重口径一致）。
func TestT49e_WiringAudit_DedupedAcrossManagers(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "acme.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LE_WORKING_DIR", "")
	t.Setenv("HOME", "")

	s, _, dir := newCertConsistencyServer(t)
	s.cfg = &srvcfg.ManagerConfig{DataDir: dir}
	s.cfg.Cert.Provider = script

	for i := 0; i < 3; i++ {
		m, err := acme.New(filepath.Join(dir, "certs"), fmt.Sprintf("m%d@example.com", i), ":80")
		if err != nil {
			t.Fatal(err)
		}
		s.attachAcmeShPath(m)
		s.acmeMgrs = append(s.acmeMgrs, m)
	}
	s.flushAcmeWireIssues()

	n := strings.Count(string(readFileOrNil(filepath.Join(dir, "events.log"))), "home 解析失败")
	if n != 1 {
		t.Errorf("3 个账号共用同一故障时审计应只记 1 条（G5），got %d", n)
	}
}

// T55 [D]（P3 / G-2）：`--install-cert` 的落点必须**只能**是 bundle 目录。
//
// 背景（R3 同族风险）：`issueViaAcmeSh` 把证书首次安装到 `certs/<域名>/`，而 handleACMEIssue 随后
// 会 os.RemoveAll 该目录；若 InstallCert 的目标不是 `certs/acme-<域名>/`（bundle 目录），
// 则**此后每次续期都不会落入 bundle** ⇒ 分发链静默失效。该缺陷在运行时不可见（新签发当下正常），
// 只能用源码级断言锁住，故本守卫含两层：
//
//	① **调用侧**：全部 `InstallCert(` 调用点的第 3 实参（ctx, primaryDomain, dir）必须是白名单内的 bundle 目录变量；
//	② **实现侧**：`InstallCert` 内三个路径参数（cert/key/fullchain）必须由 `dir` 形参经
//	   `filepath.Join(dir, …)` 派生（防止内部改回硬编码 / 其它目录）。
func TestT55_InstallCert_TargetsBundleDirOnly(t *testing.T) {
	// ── ① 调用侧：**全仓扫描**（`internal/**/*.go`，排除测试文件）──
	//
	// v1.6.72 A3 修订（采纳验收复核 §3 建议 (a)）：原实现用 `want` 只列具名函数，
	// 导致「在**新函数/新文件**中新增调用点」不会被发现（复核方对抗性验证已证实）。
	// 现改为全仓扫描 ⇒ 「任何新增调用点即 FAIL」**真正成立**。
	// 说明：测试文件按设计排除（`internal/acme/renew_integration_test.go` 有两处合法测试调用）。
	allowed := map[string]bool{"bundleDir": true}
	const wantTotal = 1
	var total int
	var sites []string
	root := ".." // internal/（测试以包目录为 cwd，与 T49c 同法）
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "InstallCert" {
				return true
			}
			pos := fset.Position(call.Pos()).String()
			sites = append(sites, pos)
			total++
			if len(call.Args) < 3 {
				t.Errorf("%s: InstallCert 调用参数不足（应 3 个：ctx, primaryDomain, dir）", pos)
				return true
			}
			id, ok := call.Args[2].(*ast.Ident)
			if !ok || !allowed[id.Name] {
				t.Errorf("%s: InstallCert 第 3 实参必须为 bundle 目录变量（白名单 %v），实际 %#v",
					pos, allowed, call.Args[2])
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("扫描 internal/ 失败：%v", walkErr)
	}
	if total != wantTotal {
		t.Errorf("InstallCert 调用点总数应为 %d（仅 handleACMEIssue 的 bundleDir 落点）；实际 %d：%v（新增调用点须显式评审）",
			wantTotal, total, sites)
	}

	// ── ② 实现侧：三个路径参数必须由 dir 形参派生 ──
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../acme/acme.go", nil, 0)
	if err != nil {
		t.Fatalf("parse ../acme/acme.go: %v", err)
	}
	joined := map[string]bool{}
	var found bool
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name == nil || fd.Name.Name != "InstallCert" || fd.Body == nil {
			continue
		}
		found = true
		ast.Inspect(fd.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "Join" || len(call.Args) != 2 {
				return true
			}
			base, ok := call.Args[0].(*ast.Ident)
			if !ok || base.Name != "dir" {
				return true
			}
			if lit, ok := call.Args[1].(*ast.BasicLit); ok {
				joined[strings.Trim(lit.Value, `"`)] = true
			}
			return true
		})
	}
	if !found {
		t.Fatal("未找到 InstallCert 实现（守卫失效，需更新）")
	}
	for _, want := range []string{"cert.pem", "privkey.pem", "fullchain.pem"} {
		if !joined[want] {
			t.Errorf("InstallCert 必须由 dir 形参派生 %s（filepath.Join(dir, %q)）—— 否则落点可能不是 bundle 目录（R3/G-2）",
				want, want)
		}
	}
}
