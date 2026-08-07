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
	"os"
	"path/filepath"
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

// T49c [D]: C5 的静态守卫 —— attachAcmeShPath 必须覆盖**全部** Manager 构造点。
// 只注入一半会让"签发"与"续期"使用不同的 acme.sh/home（与本次事故同族），
// 而该缺陷在运行时不可见，只能用源码级断言锁住。
func TestT49c_AllAcmeShWiringCallSites(t *testing.T) {
	want := map[string]map[string]int{
		"server.go":         {"New": 1, "addACMEMgr": 1, "setACMEMgr": 1, "initACMEManagers": 2},
		"handlers_certs.go": {"handleACMEIssue": 1},
	}
	got := map[string]map[string]int{}
	for file := range want {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		got[file] = map[string]int{}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "attachAcmeShPath" {
					got[file][fd.Name.Name]++
				}
				return true
			})
		}
	}
	for file, funcs := range want {
		for fn, n := range funcs {
			if got[file][fn] != n {
				t.Errorf("C5 接线覆盖不足：%s 的 %s 调用 attachAcmeShPath %d 次，应为 %d 次\n实际全量：%v",
					file, fn, got[file][fn], n, got)
			}
		}
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
