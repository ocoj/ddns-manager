package server

// T57（v1.6.72 补丁 v2 · A-1/A-4 配套守卫）
//
// 目标：把「文档（附录 A 退役流程）」与「实现（handleDeleteCert 的 ACME 托管保护）」的一致性
// 钉成可执行断言，防止二者再次漂移（历史上文档写「UI 删除」，而实现对 ACME 证书**无条件拒绝**）。
//
// 三处限定（依第三方裁决 Q3-3）：
//  ① **解析附录 A 的表格行**判定，而非 strings.Contains 全文匹配（文本包含式断言对排版/标点极脆弱）；
//  ② AST 侧不只断言「常量存在」，还断言该拒绝分支的**无条件性**
//     （条件必须是 strings.HasPrefix(name, "acme-")，分支体内无附加条件、直接 jsonErr+return）
//     —— 否则将来改成「仅未绑定时拒绝」时，常量仍在、守卫仍绿、缺陷复发；
//  ③ **判别性注入三例**（文档改回 UI 删除 / 删拒绝分支 / 改为绑定检查后才拒绝）⇒ 均须被**真实守卫**判为异常；
//     并附**负控**（未改动副本 ⇒ 守卫必须为空），证明守卫不是「常亮/常灭」。
//
// 设计要点：断言逻辑集中在 t57Check* 两个函数；**测试与注入自检调用同一函数**（避免自证式复制逻辑）。
// 路径可经环境变量覆盖（DDNS_TEST_DOCS / DDNS_TEST_HANDLERS_SRC），注入在**临时副本**上进行。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"
)

const (
	t57DocDefault     = "../../docs/usage-guide.md"
	t57HandlersSource = "handlers_certs.go"
	t57RejectMsg      = "不能删除 ACME 管理的证书"
	t57HasAcmeCond    = `strings.HasPrefix(name, "acme-")`
)

func t57Path(env, def string) string {
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		return v
	}
	return def
}

func t57AppendixARows(doc string) ([][]string, bool) {
	lines := strings.Split(doc, "\n")
	inAppA := false
	var rows [][]string
	for _, ln := range lines {
		s := strings.TrimSpace(ln)
		if strings.HasPrefix(s, "## 附录 A") {
			inAppA = true
			continue
		}
		if !inAppA {
			continue
		}
		if strings.HasPrefix(s, "## ") { // 下一个二级标题 ⇒ 结束
			break
		}
		if !strings.HasPrefix(s, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(s, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		rows = append(rows, cells)
	}
	return rows, len(rows) > 0
}

// t57CheckAppendixA 返回问题列表（空 ⇒ 合规）。
func t57CheckAppendixA(doc string) []string {
	var probs []string
	rows, ok := t57AppendixARows(doc)
	if !ok {
		return []string{"未能解析出附录 A 的表格行（文档结构可能已变）"}
	}
	step2 := ""
	for _, r := range rows {
		if len(r) >= 2 && strings.Contains(r[0], "2") && !strings.Contains(r[0], "4") {
			step2 = r[1]
			break
		}
	}
	if step2 == "" {
		probs = append(probs, "未找到附录 A 的「第 2 步」行")
	} else {
		if strings.Contains(step2, "UI 删除") {
			probs = append(probs, "第 2 步仍写「UI 删除」⇒ 对 ACME 托管证书不可行（应为手动路径）")
		}
		if !strings.Contains(step2, "手动删除") {
			probs = append(probs, "第 2 步未写明「手动删除」路径")
		}
	}
	found4 := false
	for _, r := range rows {
		if len(r) >= 2 && strings.Contains(r[0], "4") && strings.Contains(r[1], "跟进") {
			found4 = true
		}
	}
	if !found4 {
		probs = append(probs, "缺少「第 4 步 删除后跟进（观察一次续期 tick 与推送）」行")
	}
	if strings.Contains(doc, "UI 删除证书 bundle") {
		probs = append(probs, "文档中仍存在旧表述「UI 删除证书 bundle」")
	}
	return probs
}

// t57CheckDeleteHandler 返回问题列表（空 ⇒ 合规）。
func t57CheckDeleteHandler(path string) []string {
	var probs []string
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return []string{"解析失败: " + err.Error()}
	}
	var foundFn, foundReject, foundHasAcme bool
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != "handleDeleteCert" || fn.Body == nil {
			return true
		}
		foundFn = true
		ast.Inspect(fn.Body, func(m ast.Node) bool {
			ifs, ok := m.(*ast.IfStmt)
			if !ok {
				return true
			}
			call, ok := ifs.Cond.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "HasPrefix" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "strings" {
				return true
			}
			if len(call.Args) != 2 {
				return true
			}
			lit, ok := call.Args[1].(*ast.BasicLit)
			if !ok || lit.Value != `"acme-"` {
				return true
			}
			foundHasAcme = true

			if ifs.Init != nil {
				probs = append(probs, "拒绝分支带 Init 语句 ⇒ 非无条件")
			}
			if ifs.Else != nil {
				probs = append(probs, "拒绝分支带 else ⇒ 存在条件化路径")
			}
			if len(ifs.Body.List) < 2 {
				probs = append(probs, "拒绝分支体不足两条语句 ⇒ 保护不完整")
				return true
			}
			if _, isIf := ifs.Body.List[0].(*ast.IfStmt); isIf {
				probs = append(probs, "拒绝分支体内首条语句是 if ⇒ 拒绝被条件化（如「仅未绑定时拒绝」），缺陷复发面")
			}
			expr, ok := ifs.Body.List[0].(*ast.ExprStmt)
			if !ok {
				probs = append(probs, "拒绝分支首条语句不是表达式调用")
			} else if call2, ok := expr.X.(*ast.CallExpr); !ok || len(call2.Args) < 3 {
				probs = append(probs, "拒绝分支首条语句不是 jsonErr(w, 400, msg) 形态")
			} else if lit2, ok := call2.Args[2].(*ast.BasicLit); ok {
				if lit2.Value == `"`+t57RejectMsg+`"` {
					foundReject = true
				} else {
					probs = append(probs, "拒绝文案已变：实际 "+lit2.Value)
				}
			}
			if _, isRet := ifs.Body.List[1].(*ast.ReturnStmt); !isRet {
				probs = append(probs, "拒绝分支第二条语句不是 return")
			}
			return true
		})
		return true
	})
	if !foundFn {
		return append(probs, "未找到 handleDeleteCert")
	}
	if !foundHasAcme {
		probs = append(probs, "未找到条件 "+t57HasAcmeCond+" ⇒ ACME 托管保护可能已被移除/改写")
	}
	if !foundReject {
		probs = append(probs, "未找到 400 +「"+t57RejectMsg+"」拒绝语句 ⇒ 保护缺失")
	}
	return probs
}

func TestT57_AppendixA_ManualRetirePath(t *testing.T) {
	doc := t57Path("DDNS_TEST_DOCS", t57DocDefault)
	data, err := os.ReadFile(doc)
	if err != nil {
		t.Fatalf("T57①: 读取文档失败 %s: %v", doc, err)
	}
	for _, p := range t57CheckAppendixA(string(data)) {
		t.Errorf("T57①(附录A): %s", p)
	}
}

func TestT57_DeleteHandler_ACMERejectIsUnconditional(t *testing.T) {
	src := t57Path("DDNS_TEST_HANDLERS_SRC", t57HandlersSource)
	for _, p := range t57CheckDeleteHandler(src) {
		t.Errorf("T57②(handleDeleteCert): %s", p)
	}
}

// TestT57_GuardItselfIsDiscriminating 对**同一守卫函数**喂入注入变体与负控，验证判别力。
func TestT57_GuardItselfIsDiscriminating(t *testing.T) {
	docSrc, err := os.ReadFile(t57DocDefault)
	if err != nil {
		t.Fatalf("T57③: 文档不可读: %v", err)
	}
	src, err := os.ReadFile(t57HandlersSource)
	if err != nil {
		t.Fatalf("T57③: 源码不可读: %v", err)
	}

	// 负控：未改动副本 ⇒ 守卫必须为空（否则守卫"常亮"，判别力为零）
	if probs := t57CheckAppendixA(string(docSrc)); len(probs) != 0 {
		t.Errorf("T57③ 负控(文档): 未改动副本竟报错 ⇒ %v", probs)
	}
	if probs := t57CheckDeleteHandler(t57HandlersSource); len(probs) != 0 {
		t.Errorf("T57③ 负控(源码): 未改动竟报错 ⇒ %v", probs)
	}

	// 正控①：文档第 2 步改回「UI 删除证书 bundle」
	badDoc := regexp.MustCompile(`(?m)^\| \*\*2\*\* \| \*\*手动删除证书 bundle\*\*`).
		ReplaceAllString(string(docSrc), "| **2** | UI 删除证书 bundle")
	if badDoc == string(docSrc) {
		t.Fatalf("T57③-①: 未能构造（第 2 步行未匹配）")
	}
	if probs := t57CheckAppendixA(badDoc); len(probs) == 0 {
		t.Errorf("T57③-①: 注入「UI 删除」后守卫**未报错**")
	} else {
		t.Logf("T57③-① 守卫正确报错: %v", probs)
	}

	// 正控②：整体删除 ACME 拒绝分支（条件与常量均不可见）
	block := regexp.MustCompile("(?s)\n\tif strings\\.HasPrefix\\(name, \"acme-\"\\) \\{.*?\n\t\\}")
	noReject := block.ReplaceAllString(string(src), "")
	if noReject == string(src) {
		t.Fatalf("T57③-②: 未能构造（拒绝分支未匹配）")
	}
	p2 := t.TempDir() + "/no-reject.go"
	if err := os.WriteFile(p2, []byte(noReject), 0o600); err != nil {
		t.Fatal(err)
	}
	if probs := t57CheckDeleteHandler(p2); len(probs) == 0 {
		t.Errorf("T57③-②: 删除拒绝分支后守卫**未报错**")
	} else {
		t.Logf("T57③-② 守卫正确报错: %v", probs)
	}

	// 正控③：改为「绑定检查后才拒绝」——保留分支、把拒绝包进内层 if（语法合法）
	m := block.FindString(string(src))
	if m == "" {
		t.Fatalf("T57③-③: 未能定位拒绝分支")
	}
	condBlock := strings.Replace(m, "{\n", "{\n\t\tif len(bindings) == 0 {\n", 1)
	condBlock = strings.Replace(condBlock, "\n\t}", "\n\t\t}\n\t}", 1)
	condReject := strings.Replace(string(src), m, condBlock, 1)
	if condReject == string(src) {
		t.Fatalf("T57③-③: 未能构造")
	}
	p3 := t.TempDir() + "/cond-reject.go"
	if err := os.WriteFile(p3, []byte(condReject), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parser.ParseFile(token.NewFileSet(), p3, nil, 0); err != nil {
		t.Fatalf("T57③-③: 注入③ 生成了非法 Go（该用例应检验「条件化」语义而非语法错误）: %v", err)
	}
	if probs := t57CheckDeleteHandler(p3); len(probs) == 0 {
		t.Errorf("T57③-③: 改为绑定式拒绝后守卫**未报错** ⇒ 无条件性断言失效")
	} else {
		t.Logf("T57③-③ 守卫正确报错: %v", probs)
	}
}
