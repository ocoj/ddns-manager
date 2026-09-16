package acme

// v1.6.73 B-2（T59）：证明「非判定性提示」与 adopt/skip 判定**物理解耦**。
//
//   ① **启发式来源**（$HOME/.acme.sh）+ 祖先目录 0777（组/他人可写）
//      ⇒ **仍被采纳**（旧行为：祖先可写被并入 warn ⇒ 启发式来源会被**跳过**）
//      ⇒ Caveats 非空，且 Trace 仍含「强告警」字样（T52c 不变量）
//      —— 本用例即**注入①**（caveats 回塞判定）的判别靶点：回塞后 Caveats 必为空 ⇒ FAIL
//   ② HOME 指向空目录（无 .acme.sh）且无其它候选 ⇒ fail-fast ⇒ Caveats 必为空
//
// 编译探针（开工前核验备忘 ②）：接口漂移在编译期暴露，而非等 CI。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var _ = func(r HomeResolution) []string { return r.Caveats }
var _ = func(m *Manager) []string { return m.AcmeHomeCaveats() }

// t59HeuristicHome 造一个**启发式来源**的已初始化 home，且**不在 tmpLike 前缀内**
// （否则会被 tmpLike 位置体检按设计拒绝 —— 那属"仅显式来源可采用"的既定安全语义，不在 B-2 范围）。
// 结构：<HOME>/.ddns-t59/<pid>（0777，即 home 的祖先）/.acme.sh（home，含 account.conf）
// 返回 (homeEnv, homeDir)。
func t59HeuristicHome(t *testing.T) (string, string) {
	t.Helper()
	uh, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("无 HOME，跳过：%v", err)
	}
	for _, bad := range []string{"/tmp", "/var/tmp", "/dev/shm", "/run"} {
		if strings.HasPrefix(uh, bad) {
			t.Skipf("HOME 落在 tmpLike 前缀（%s），本用例需非 tmpLike 祖先", bad)
		}
	}
	// 候选路径 = <homeEnv>/.acme.sh ⇒ 令 homeEnv = root，则 home = root/.acme.sh，
	// 且 **root 自身即 home 的祖先** ⇒ 将 root 设为 0777 即可触发「祖先组可写」caveat。
	root := filepath.Join(uh, fmt.Sprintf(".ddns-t59-%d", os.Getpid()))
	home := filepath.Join(root, ".acme.sh")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o777); err != nil { // 祖先（root）组/他人可写 ⇒ 应产 Caveats
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "account.conf"), []byte("# t59\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root, home
}

func TestT59_Caveats_DoNotAffectDecision(t *testing.T) {
	t.Run("①启发式+祖先组可写⇒仍采纳+Caveats非空+Trace含强告警", func(t *testing.T) {
		homeEnv, home := t59HeuristicHome(t)
		t.Setenv("LE_WORKING_DIR", "") // 显式来源必须为空 ⇒ 走启发式
		// acmeShPath="" ⇒ binary-dir 候选跳过；homeEnv ⇒ home-default 候选 = <homeEnv>/.acme.sh
		res := ResolveAcmeHome(DefaultHomeProbe(false), "", "", homeEnv)
		if !res.OK() {
			t.Fatalf("启发式来源 + 祖先组可写必须**仍可采纳**（不得因告警被跳过）：trace=%v", res.Trace)
		}
		if res.Home != home {
			t.Errorf("应采纳 %s，实际 %s", home, res.Home)
		}
		if len(res.Caveats) == 0 {
			t.Errorf("应产出 Caveats（祖先组可写属非判定性提示）：trace=%v", res.Trace)
		}
		if !traceHas(res.Trace, "强告警") {
			t.Errorf("Trace 必须仍含「强告警」字样（T52c 不变量）：%v", res.Trace)
		}
	})

	t.Run("②fail-fast⇒Caveats空", func(t *testing.T) {
		emptyHome := t.TempDir() // 无 .acme.sh
		t.Setenv("LE_WORKING_DIR", "")
		res := ResolveAcmeHome(DefaultHomeProbe(false), "", "", emptyHome)
		if res.OK() {
			t.Skipf("本机环境存在可用 home（%s），跳过 fail-fast 负控", res.Home)
		}
		if len(res.Caveats) != 0 {
			t.Errorf("fail-fast 场景不应有 Caveats：%v", res.Caveats)
		}
	})
}
