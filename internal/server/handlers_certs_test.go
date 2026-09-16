package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/ocoj/ddns-manager/internal/store"
)

// T54 [P2/F7]：bundle 的 meta.domains 必须被持久化，且在"续期/重建路径"（Load→Save）后仍非空。
//
// 语义依据（复核方一轮实测，本测试在仓库内固化为回归）：
//
//	(B) LoadCertBundle 会从 meta 回填 Domains；
//	(C) 因此 Load→Save 不会致 null（其余 5 处 SaveCertBundle 站点不受影响）；
//	(D) 全新签发（无既有 meta.json）只有**显式赋值**才能闭合 ⇒ 方案②/③ 不构成替代。
func TestT54_MetaDomains_PersistedAndPreserved(t *testing.T) {
	_, st, _ := newCertConsistencyServer(t)

	files := map[string][]byte{
		"cert.pem":      []byte("cert"),
		"fullchain.pem": []byte("chain"),
		"privkey.pem":   []byte("key"),
	}

	// ① 显式赋值 ⇒ meta.domains 落盘
	b := &store.CertBundle{Name: "acme-t54.example.com", Files: files, Domains: []string{"t54.example.com", "alt.example.com"}}
	if err := st.SaveCertBundle(b); err != nil {
		t.Fatalf("SaveCertBundle: %v", err)
	}
	meta, err := st.LoadCertMeta("acme-t54.example.com")
	if err != nil {
		t.Fatalf("LoadCertMeta: %v", err)
	}
	got, ok := meta["domains"].([]interface{})
	if !ok || len(got) != 2 {
		t.Fatalf("① 显式赋值后 meta.domains 应为 2 项，实际 %v (%T)", meta["domains"], meta["domains"])
	}

	// ② 续期/重建路径（Load→Save）⇒ 仍非空
	lb, err := st.LoadCertBundle("acme-t54.example.com")
	if err != nil {
		t.Fatalf("LoadCertBundle: %v", err)
	}
	if len(lb.Domains) == 0 {
		t.Fatalf("② LoadCertBundle 必须回填 Domains（复核实测 B）")
	}
	if err := st.SaveCertBundle(lb); err != nil {
		t.Fatalf("SaveCertBundle(2): %v", err)
	}
	meta2, err := st.LoadCertMeta("acme-t54.example.com")
	if err != nil {
		t.Fatalf("LoadCertMeta(2): %v", err)
	}
	if ds, ok := meta2["domains"].([]interface{}); !ok || len(ds) != 2 {
		t.Fatalf("② 续期路径后 meta.domains 不应为空（复核实测 C），实际 %v", meta2["domains"])
	}

	// ③ **不变量式断言**（v1.6.72 A-4 修订，依第三方裁决 Q8①/Q8②）：
	//    对"未显式赋值"的 bundle，**必须**满足以下之一，且**不得被他 bundle 污染**：
	//      (a) domains == null（当前 `structKeys` **加法白名单**实现的现状）；或
	//      (b) 保留 meta 原值（若未来实施 **B-3** 的**减法白名单**）。
	//    ⚠️ 本断言**不得**把 (a) 钉成唯一期望 —— 否则 B-3 落地时会把**正确改动**判为失败（假门禁）。
	//    ⇒ **B-3 依赖本项**（批次顺序锁定：A-4 先于 B-3）。
	//    反证价值保留：本步骤仍证明"全新签发（无既有 meta.json）只有显式赋值才能闭合"（见 T54b）。
	nb := &store.CertBundle{Name: "acme-t54null.example.com", Files: files}
	if err := st.SaveCertBundle(nb); err != nil {
		t.Fatalf("SaveCertBundle(3): %v", err)
	}
	meta3, err := st.LoadCertMeta("acme-t54null.example.com")
	if err != nil {
		t.Fatalf("LoadCertMeta(3): %v", err)
	}
	switch v := meta3["domains"].(type) {
	case nil:
		// (a) 现状实现：未赋值 ⇒ null（当前白名单行为）
	case []interface{}:
		// (b) 未来减法白名单：允许保留原值 —— 但**不得**是别的 bundle 的 domains（污染检测）
		for _, d := range v {
			if d == "t54.example.com" || d == "alt.example.com" {
				t.Fatalf("③ 污染：未赋值 bundle 的 domains 出现了**他 bundle** 的值：%v", v)
			}
		}
		t.Logf("③ 观察到减法白名单形态（保留原值 %v）—— 符合不变量 (b)", v)
	default:
		t.Fatalf("③ domains 形态异常：%T（应为 nil 或 []interface{}）", meta3["domains"])
	}
}

// T54b [P2/F7] 源码级守卫：**公开签发入口** handleACMEIssue 构造 bundle 时必须显式赋值
// `Domains: req.Domains`，否则 SaveCertBundle 的 structKeys 白名单会把预写 meta 的 domains
// 覆盖为 null（P2/F7 的回归面）。
//
// ⚠️ 离线限制（实施期实测，2026-09-16）：
//
//	原计划"假 acme.sh 走公开签发入口"**无法离线驱动** —— handleACMEIssue → IssueDNS01 会先经
//	ACME 客户端**真实注册账号**（实测触发网络请求并返回
//	`register: 400 urn:ietf:params:acme:error:invalidContact ... forbidden domain "example.com"`），
//	且 acme 包未提供该客户端的注入点。故：
//	  · 语义层由 TestT54 覆盖（store 级，离线、稳定）；
//	  · 接线层由本守卫覆盖（AST，同 T49c/T51 做法）；
//	  · 真路径留待"带 mock CA 的联机测试批次"或生产验收（H2 同口径）。
func TestT54b_IssueHandler_SetsBundleDomains(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "handlers_certs.go", nil, 0)
	if err != nil {
		t.Fatalf("parse handlers_certs.go: %v", err)
	}
	var (
		foundFn          bool
		foundField       bool
		foundValue       bool
		foundWrongSource bool // A-5：出现 `Domains: <非 req>.Domains` 同形不同源
	)
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != "handleACMEIssue" {
			return true
		}
		foundFn = true
		ast.Inspect(fn, func(m ast.Node) bool {
			cl, ok := m.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := cl.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "CertBundle" {
				return true
			}
			for _, el := range cl.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "Domains" {
					continue
				}
				foundField = true
				// A-5（v1.6.72 补丁 v2）：只断言字段名不够 —— `Domains: other.Domains`
				// （**同形不同源**）也会通过。必须断言**接收者标识为 `req`** ⇒ 精确匹配 `req.Domains`。
				vs, ok := kv.Value.(*ast.SelectorExpr)
				if !ok || vs.Sel == nil || vs.Sel.Name != "Domains" {
					continue
				}
				recv, ok := vs.X.(*ast.Ident)
				if !ok || recv.Name != "req" {
					// 记录"同形不同源"的证据，供下方报错信息使用
					foundWrongSource = true
					continue
				}
				foundValue = true
			}
			return true
		})
		return false
	})
	if !foundFn {
		t.Fatal("未找到 handleACMEIssue（守卫失效，需更新）")
	}
	if !foundField || !foundValue {
		t.Errorf("handleACMEIssue 必须在 store.CertBundle 字面量中显式赋值 `Domains: req.Domains`（P2/F7）: foundField=%v foundValue=%v foundWrongSource=%v（同形不同源亦须 FAIL）",
			foundField, foundValue, foundWrongSource)
	}

	// 配套：后置自检必须存在（meta.domains 为空时报 warning）
	src, err := os.ReadFile("handlers_certs.go")
	if err != nil {
		t.Fatalf("read handlers_certs.go: %v", err)
	}
	if !strings.Contains(string(src), "meta.domains 缺失") {
		t.Error("handleACMEIssue 必须保留 meta.domains 后置自检（P2/F7 防回归）")
	}
}
