package acme

// v1.6.71 N1 测试：acme.sh home 的候选判定表（T40–T48）+ 环境构造（T34–T38）。
//
// 规格：internal-docs/audits/2026-09-16-acme-renew-N1-N2-followup-plan-v3.md
//   §1.2 自检 = account.conf | ca/（不含 acme.sh、不含 dnsapi/）
//   §1.3 候选判定表（三分法 + 语义分层 + 绝对化）+ fail-fast
//   §1.3.4 目录体检（C4）+ H1（.git/ 拒绝）
//
// 标注 [D] 的用例在修复前必然 FAIL —— 它们是"测试确实在测"的反证依据。

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ── 可注入探测：用真实目录（绝大多数用例）+ 伪造元数据（属主/权限/git）──

type fakeDirEnt struct {
	isDir   bool
	mode    os.FileMode // 权限位（如 0o755）
	uid     int
	symlink bool // 该项自身是符号链接（Lstat 可见）
}

type fakeProbe struct {
	uid      int
	hasCerts bool
	ents     map[string]fakeDirEnt // 路径 → 元数据
	evalOut  map[string]string     // EvalSymlinks 结果
}

func (f fakeProbe) probe() HomeProbe {
	return HomeProbe{
		UID:      f.uid,
		HasCerts: f.hasCerts,
		TmpLike:  []string{"/definitely-not-tmp"},
		Stat: func(p string) (os.FileInfo, error) {
			e, ok := f.ents[p]
			if !ok {
				return nil, os.ErrNotExist
			}
			if e.symlink {
				// 跟随符号链接：指向同路径去尾（测试用例里链接目标由 ents 表达）
				if tgt, ok := f.evalOut[p]; ok {
					if te, ok := f.ents[tgt]; ok {
						return fakeFI{name: filepath.Base(p), ent: te}, nil
					}
				}
				return nil, os.ErrNotExist
			}
			return fakeFI{name: filepath.Base(p), ent: e}, nil
		},
		Lstat: func(p string) (os.FileInfo, error) {
			e, ok := f.ents[p]
			if !ok {
				return nil, os.ErrNotExist
			}
			return fakeFI{name: filepath.Base(p), ent: e}, nil
		},
		EvalSymlinks: func(p string) (string, error) {
			if v, ok := f.evalOut[p]; ok {
				return v, nil
			}
			if _, ok := f.ents[p]; ok {
				return p, nil
			}
			return "", os.ErrNotExist
		},
		ReadDir: func(dir string) ([]os.DirEntry, error) {
			// 目录本身是符号链接时，跟随到目标（与真实 ReadDir 语义一致）
			base := dir
			if e, ok := f.ents[dir]; ok && e.symlink {
				if tgt, ok2 := f.evalOut[dir]; ok2 {
					base = tgt
				}
			}
			var out []os.DirEntry
			prefix := base + "/"
			for p, e := range f.ents {
				if !strings.HasPrefix(p, prefix) {
					continue
				}
				if strings.Contains(strings.TrimPrefix(p, prefix), "/") {
					continue
				}
				out = append(out, fakeDE{name: filepath.Base(p), dir: e.isDir})
			}
			if len(out) == 0 {
				if _, ok := f.ents[base]; !ok {
					return nil, os.ErrNotExist
				}
			}
			return out, nil
		},
	}
}

// probeWithTmp 与 probe 相同，但可指定"公共可写目录"前缀表。
func (f fakeProbe) probeWithTmp(tmp []string) HomeProbe {
	p := f.probe()
	p.TmpLike = tmp
	return p
}

type fakeFI struct {
	name string
	ent  fakeDirEnt
}

func (f fakeFI) Name() string { return f.name }
func (f fakeFI) Size() int64  { return 0 }
func (f fakeFI) Mode() os.FileMode {
	if f.ent.symlink {
		return os.ModeSymlink | 0o777
	}
	if f.ent.isDir {
		return f.ent.mode | os.ModeDir
	}
	return f.ent.mode
}
func (f fakeFI) ModTime() time.Time { return time.Time{} }
func (f fakeFI) IsDir() bool        { return f.ent.isDir && !f.ent.symlink }
func (f fakeFI) Sys() interface{} {
	m := uint32(f.ent.mode.Perm())
	if f.ent.isDir {
		m |= 0o040000 // S_IFDIR
	}
	return &syscall.Stat_t{Uid: uint32(f.ent.uid), Mode: m}
}

type fakeDE struct {
	name string
	dir  bool
}

func (d fakeDE) Name() string               { return d.name }
func (d fakeDE) IsDir() bool                { return d.dir }
func (d fakeDE) Type() os.FileMode          { return 0 }
func (d fakeDE) Info() (os.FileInfo, error) { return nil, nil }

// emptyProbe 返回一个"什么都没有"的探测（所有候选均不存在）。
func emptyProbe(uid int, hasCerts bool) HomeProbe {
	f := fakeProbe{uid: uid, hasCerts: hasCerts, ents: map[string]fakeDirEnt{}, evalOut: map[string]string{}}
	return f.probe()
}

func traceHas(trace []string, sub string) bool {
	for _, t := range trace {
		if strings.Contains(t, sub) {
			return true
		}
	}
	return false
}

// ── T40：符号链接必须解析到真实目录（生产形态：/usr/local/bin/acme.sh → <home>/acme.sh）──

func TestT40_Home_SymlinkResolvedToRealDir(t *testing.T) {
	root := t.TempDir()
	realHome := filepath.Join(root, "home", ".acme.sh")
	if err := os.MkdirAll(realHome, 0o700); err != nil {
		t.Fatal(err)
	}
	// 真实 home 的标志：account.conf
	if err := os.WriteFile(filepath.Join(realHome, "account.conf"), []byte("SAVED_=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(realHome, "acme.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(binDir, "acme.sh")
	if err := os.Symlink(script, link); err != nil {
		t.Fatal(err)
	}

	// HOME 故意指向别处，且无 LE_WORKING_DIR：只能靠 ③ 解析符号链接得到真实 home
	p := HomeProbe{
		Stat: os.Stat, Lstat: os.Lstat, EvalSymlinks: filepath.EvalSymlinks,
		ReadDir: os.ReadDir, UID: os.Getuid(), HasCerts: true,
		TmpLike: []string{"/definitely-not-tmp"},
	}
	res := ResolveAcmeHome(p, link, "", filepath.Join(root, "nohome"))
	if !res.OK() {
		t.Fatalf("home 未解析（trace=%v）", res.Trace)
	}
	if res.Home != realHome {
		t.Errorf("home = %q，want %q（必须解析符号链接，而不是取 %q）", res.Home, realHome, binDir)
	}
}

// ── T41 / T41b / T41c：自检准则（v3 §1.2）──

// T41：启发式候选目录存在但未过自检 ⇒ 跳过（不误纳）
func TestT41_Home_HeuristicDirWithoutSelfCheckSkipped(t *testing.T) {
	probe := fakeProbe{
		uid: 1000, hasCerts: true,
		ents: map[string]fakeDirEnt{
			"/opt/acme":        {isDir: true, mode: 0o700, uid: 1000},
			"/opt/acme/README": {mode: 0o644, uid: 1000}, // 非空但非 acme home
		},
		evalOut: map[string]string{"/opt/acme/acme.sh": "/opt/acme/acme.sh"},
	}.probe()
	res := ResolveAcmeHome(probe, "/opt/acme/acme.sh", "", "")
	if res.OK() {
		t.Fatalf("未过自检的目录不得被采用，got home=%q", res.Home)
	}
	if !traceHas(res.Trace, "非 ACME home") {
		t.Errorf("trace 应说明未过自检：%v", res.Trace)
	}
}

// T41b [D]：目录中**仅有 acme.sh 脚本** ⇒ 不得判定为 home（🔴 审计场景：
// curl -O /usr/local/bin/acme.sh 时，二进制目录会被误判并落明文凭据）
func TestT41b_Home_OnlyAcmeShScriptIsNotAHome(t *testing.T) {
	probe := fakeProbe{
		uid: 1000, hasCerts: true,
		ents: map[string]fakeDirEnt{
			// 属主与探测 uid 一致 ⇒ 体检不会拦它；能否被接受只取决于"自检判据"
			"/usr/local/bin":         {isDir: true, mode: 0o755, uid: 1000},
			"/usr/local/bin/acme.sh": {mode: 0o755, uid: 1000},
		},
		evalOut: map[string]string{"/usr/local/bin/acme.sh": "/usr/local/bin/acme.sh"},
	}.probe()
	res := ResolveAcmeHome(probe, "/usr/local/bin/acme.sh", "", "")
	if res.OK() {
		t.Fatalf("仅含 acme.sh 的目录不得作为 home（会在此创建 account.conf 并落明文凭据）")
	}
}

// T41c [D]：目录中**仅有 dnsapi/** ⇒ 不得判定为 home（采纳第二轮审计 D2 的否决）
func TestT41c_Home_OnlyDnsapiIsNotAHome(t *testing.T) {
	probe := fakeProbe{
		uid: 1000, hasCerts: true,
		ents: map[string]fakeDirEnt{
			"/opt/acme-src":        {isDir: true, mode: 0o755, uid: 1000},
			"/opt/acme-src/dnsapi": {isDir: true, mode: 0o755, uid: 1000},
		},
		evalOut: map[string]string{"/opt/acme-src/acme.sh": "/opt/acme-src/acme.sh"},
	}.probe()
	res := ResolveAcmeHome(probe, "/opt/acme-src/acme.sh", "", "")
	if res.OK() {
		t.Fatalf("dnsapi/ 不是有效判据（--install 必产 account.conf）")
	}
}

// ca/ 仍是有效判据（acme.sh 运行后产生）
func TestT41_Home_CaDirIsAValidHome(t *testing.T) {
	probe := fakeProbe{
		uid: 1000, hasCerts: true,
		ents: map[string]fakeDirEnt{
			"/root/.acme.sh":    {isDir: true, mode: 0o700, uid: 1000},
			"/root/.acme.sh/ca": {isDir: true, mode: 0o700, uid: 1000},
		},
		evalOut: map[string]string{"/root/.acme.sh/acme.sh": "/root/.acme.sh/acme.sh"},
	}.probe()
	res := ResolveAcmeHome(probe, "/root/.acme.sh/acme.sh", "", "")
	if !res.OK() || res.Home != "/root/.acme.sh" {
		t.Fatalf("ca/ 应为有效判据，got home=%q trace=%v", res.Home, res.Trace)
	}
}

// ── T41d：全部候选耗尽 ⇒ fail-fast（不猜路径、不创建目录）──

func TestT41d_Home_AllCandidatesExhausted_FailFast(t *testing.T) {
	res := ResolveAcmeHome(emptyProbe(1000, true), "/nonexistent/acme.sh", "", "")
	if res.OK() {
		t.Fatalf("无可用 home 时必须 fail-fast，got %q", res.Home)
	}
	if !traceHas(res.Trace, "fail-fast") {
		t.Errorf("trace 必须标注 fail-fast：%v", res.Trace)
	}
	if err := res.Err(); err == nil {
		t.Error("Err() 必须非 nil（调用方据此拒绝执行 acme.sh）")
	}
}

// ── T45 / T46：语义分层（C1）──

// T45 [D]：显式 env 指向"未初始化路径"但本地**已有** ACME 证书 ⇒ 跳过（不得静默另起 home）
func TestT45_Home_ExistingCerts_UninitializedExplicitPathSkipped(t *testing.T) {
	probe := fakeProbe{uid: 1000, hasCerts: true, ents: map[string]fakeDirEnt{}}.probe()
	res := ResolveAcmeHome(probe, "", "/opt/new-acme-home", "")
	if res.OK() {
		t.Fatalf("本地已有证书时不得采用未初始化路径，got %q", res.Home)
	}
	if !traceHas(res.Trace, "语义分层") {
		t.Errorf("trace 应说明语义分层：%v", res.Trace)
	}
}

// T46：全新安装（本地无任何 ACME 证书）⇒ 允许采用未初始化路径（由 acme.sh 初始化）
func TestT46_Home_FreshInstall_UninitializedExplicitPathAdopted(t *testing.T) {
	probe := fakeProbe{uid: 1000, hasCerts: false, ents: map[string]fakeDirEnt{}}.probe()
	res := ResolveAcmeHome(probe, "", "/opt/new-acme-home", "")
	if !res.OK() || res.Home != "/opt/new-acme-home" {
		t.Fatalf("全新安装应采用未初始化路径，got home=%q trace=%v", res.Home, res.Trace)
	}
	if !traceHas(res.Trace, "将由 acme.sh 初始化") {
		t.Errorf("trace 应提示将由 acme.sh 初始化：%v", res.Trace)
	}
}

// ── T47：相对路径绝不按 cwd 解析（C2）──

func TestT47_Home_RelativePathSkipped(t *testing.T) {
	probe := fakeProbe{uid: 1000, hasCerts: true, ents: map[string]fakeDirEnt{}}.probe()
	res := ResolveAcmeHome(probe, "acme.sh", "relative/home", "relative-home")
	if res.OK() {
		t.Fatalf("相对路径候选必须全部跳过（否则 home 会落到进程 cwd），got %q", res.Home)
	}
	for _, want := range []string{"非绝对路径", "HOME 非绝对"} {
		if !traceHas(res.Trace, want) {
			t.Errorf("trace 缺少 %q：%v", want, res.Trace)
		}
	}
}

// ── T48：目录体检（C4 + H1）──

func TestT48_Home_HealthCheck(t *testing.T) {
	base := func() map[string]fakeDirEnt {
		return map[string]fakeDirEnt{
			"/h":              {isDir: true, mode: 0o700, uid: 1000},
			"/h/account.conf": {mode: 0o600, uid: 1000},
		}
	}
	cases := []struct {
		name     string
		mutate   func(m map[string]fakeDirEnt)
		explicit bool // 走 env 候选（显式）
		wantOK   bool
		wantSub  string
	}{
		{"正常 home", func(m map[string]fakeDirEnt) {}, true, true, ""},
		{"H1: 含 .git ⇒ 拒绝", func(m map[string]fakeDirEnt) { m["/h/.git"] = fakeDirEnt{isDir: true, mode: 0o700, uid: 1000} }, true, false, "源码检出"},
		{"属主不符 ⇒ 拒绝", func(m map[string]fakeDirEnt) { m["/h"] = fakeDirEnt{isDir: true, mode: 0o700, uid: 4321} }, true, false, "属主"},
		{"group/other 可写 ⇒ 拒绝", func(m map[string]fakeDirEnt) { m["/h"] = fakeDirEnt{isDir: true, mode: 0o777, uid: 1000} }, true, false, "可写"},
		{"路径含他人符号链接 ⇒ 拒绝", func(m map[string]fakeDirEnt) {
			// /h 是指向 /real/h 的符号链接，且链接属主不是本进程
			m["/h"] = fakeDirEnt{symlink: true, uid: 4321}
			m["/real/h"] = fakeDirEnt{isDir: true, mode: 0o700, uid: 1000}
			m["/real/h/account.conf"] = fakeDirEnt{mode: 0o600, uid: 1000}
		}, true, false, "符号链接"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := base()
			tc.mutate(m)
			probe := fakeProbe{uid: 1000, hasCerts: true, ents: m, evalOut: map[string]string{"/h": "/real/h"}}.probe()
			res := ResolveAcmeHome(probe, "", "/h", "")
			if res.OK() != tc.wantOK {
				t.Fatalf("OK=%v want %v（trace=%v）", res.OK(), tc.wantOK, res.Trace)
			}
			if tc.wantSub != "" && !traceHas(res.Trace, tc.wantSub) {
				t.Errorf("trace 缺少 %q：%v", tc.wantSub, res.Trace)
			}
		})
	}
}

// T48b：公共可写目录（/tmp 类）—— 显式来源 ⇒ 采用但强告警；启发式来源 ⇒ 跳过
func TestT48b_Home_TmpLikeDir(t *testing.T) {
	mk := func() HomeProbe {
		return fakeProbe{
			uid: 1000, hasCerts: true,
			ents: map[string]fakeDirEnt{
				"/tmp/acmehome":              {isDir: true, mode: 0o700, uid: 1000},
				"/tmp/acmehome/account.conf": {mode: 0o600, uid: 1000},
			},
			evalOut: map[string]string{},
		}.probeWithTmp([]string{"/tmp"})
	}
	// 显式（env）⇒ 采用 + 强告警
	res := ResolveAcmeHome(mk(), "", "/tmp/acmehome", "")
	if !res.OK() || res.Home != "/tmp/acmehome" {
		t.Fatalf("显式来源应被采用（强告警），got home=%q trace=%v", res.Home, res.Trace)
	}
	if !traceHas(res.Trace, "强告警") {
		t.Errorf("trace 应含强告警：%v", res.Trace)
	}
	// 启发式（二进制目录）⇒ 跳过
	res2 := ResolveAcmeHome(mk(), "/tmp/acmehome/acme.sh", "", "")
	if res2.OK() {
		t.Fatalf("启发式来源遇到 /tmp 类目录必须跳过，got %q", res2.Home)
	}
}

// ── T35b：运维显式的 LE_WORKING_DIR（已过自检）不得被覆盖 ──

func TestT35b_Home_ExplicitEnvWorkDirNotOverridden(t *testing.T) {
	probe := fakeProbe{
		uid: 1000, hasCerts: true,
		ents: map[string]fakeDirEnt{
			"/opt/acme":                   {isDir: true, mode: 0o700, uid: 1000},
			"/opt/acme/account.conf":      {mode: 0o600, uid: 1000},
			"/root/.acme.sh":              {isDir: true, mode: 0o700, uid: 1000},
			"/root/.acme.sh/account.conf": {mode: 0o600, uid: 1000},
		},
		evalOut: map[string]string{"/root/.acme.sh/acme.sh": "/root/.acme.sh/acme.sh"},
	}.probe()
	res := ResolveAcmeHome(probe, "/root/.acme.sh/acme.sh", "/opt/acme", "/root")
	if !res.OK() || res.Home != "/opt/acme" {
		t.Fatalf("显式 env 优先（③ 的 /root/.acme.sh 不得覆盖它），got home=%q trace=%v", res.Home, res.Trace)
	}
}

// ── T34/T35/T36/T37/T38：环境构造（acmeShEnv）──

func TestT34_Env_HomeFilledWhenParentHomeMissing(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("LE_WORKING_DIR", "")
	home := "/root/.acme.sh"
	m := envMap(acmeShEnv(nil, home))
	if m["HOME"] != "/root" {
		t.Errorf("HOME 缺失时必须补父目录（/root），got %q", m["HOME"])
	}
	if m["LE_WORKING_DIR"] != home {
		t.Errorf("LE_WORKING_DIR = %q, want %q", m["LE_WORKING_DIR"], home)
	}
}

func TestT35_Env_WorkDirAlwaysSet(t *testing.T) {
	t.Setenv("HOME", "/root")
	t.Setenv("LE_WORKING_DIR", "/wrong")
	m := envMap(acmeShEnv(nil, "/root/.acme.sh"))
	if m["LE_WORKING_DIR"] != "/root/.acme.sh" {
		t.Errorf("LE_WORKING_DIR 必须被显式固定，got %q", m["LE_WORKING_DIR"])
	}
}

func TestT36_Env_ParentHomePreserved(t *testing.T) {
	t.Setenv("HOME", "/home/other")
	m := envMap(acmeShEnv(nil, "/root/.acme.sh"))
	if m["HOME"] != "/home/other" {
		t.Errorf("父环境已有 HOME 时不得覆盖，got %q", m["HOME"])
	}
}

func TestT37_Env_CredentialsInjectedOnlyWhenComplete(t *testing.T) {
	m := envMap(acmeShEnv(&DNSProvider{Name: "alidns", KeyID: "AK", KeySecret: "SK"}, "/h/.acme.sh"))
	if m["Ali_Key"] != "AK" || m["Ali_Secret"] != "SK" {
		t.Errorf("alidns 凭据应被注入: %v", m)
	}
	m = envMap(acmeShEnv(&DNSProvider{Name: "alidns", KeyID: "AK"}, "/h/.acme.sh"))
	if _, ok := m["Ali_Secret"]; ok {
		t.Error("空 secret 不得注入")
	}
	m = envMap(acmeShEnv(&DNSProvider{Name: "cloudflare", KeyID: "TOK"}, "/h/.acme.sh"))
	if m["CF_Token"] != "TOK" {
		t.Errorf("cloudflare 单变量应注入: %v", m)
	}
}

// T38 [D]：dp == nil / 未支持 provider ⇒ **不含凭据**，但仍必须固定 HOME/LE_WORKING_DIR（S14）
func TestT38_Env_NilProviderPinsHomeWithoutCredentials(t *testing.T) {
	t.Setenv("HOME", "")
	for _, tc := range []struct {
		name string
		dp   *DNSProvider
	}{
		{"nil provider", nil},
		{"unsupported provider", &DNSProvider{Name: "not-a-provider", KeyID: "x", KeySecret: "y"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := envMap(acmeShEnv(tc.dp, "/root/.acme.sh"))
			if m["LE_WORKING_DIR"] != "/root/.acme.sh" || m["HOME"] != "/root" {
				t.Fatalf("必须固定 home/HOME: %v", m)
			}
			for _, k := range []string{"Ali_Key", "Ali_Secret", "CF_Token"} {
				if _, ok := m[k]; ok {
					t.Errorf("不得注入凭据 %s", k)
				}
			}
		})
	}
}

// dedup：同名键只保留最后一个（不依赖 os/exec 的实现细节）
func TestT38b_Env_DedupKeepsLast(t *testing.T) {
	t.Setenv("HOME", "")
	env := acmeShEnv(nil, "/root/.acme.sh")
	counts := map[string]int{}
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			counts[kv[:i]]++
		}
	}
	for _, k := range []string{"HOME", "LE_WORKING_DIR"} {
		if counts[k] != 1 {
			t.Errorf("%s 出现 %d 次，应为 1 次（显式去重）", k, counts[k])
		}
	}
}

// ── T48c / T48d：G1 修复 —— "未初始化路径"分支也必须过位置/属主体检 ──
//
// 缺口（审计 G1）：`不存在` 与 `空目录` 两个分支此前**直接采用**，绕过了
// §1.3.4 的位置与属主体检 ⇒ 全新安装实例可能把 home 建到 /tmp 类公共可写目录，
// 或采纳他人预置的空目录，随后 acme.sh 在那里写入明文 account.conf（I28/C4 承诺范围）。

// T48c [D]：不存在的路径位于公共可写目录 ⇒ 显式来源"采用 + 强告警"，启发式来源跳过。
func TestT48c_Home_NonexistentUnderTmpLikeDir(t *testing.T) {
	mk := func() HomeProbe {
		return fakeProbe{uid: 1000, hasCerts: false, ents: map[string]fakeDirEnt{}, evalOut: map[string]string{}}.
			probeWithTmp([]string{"/tmp"})
	}
	// 显式（env）：全新安装 ⇒ 采用，但必须给出强告警
	res := ResolveAcmeHome(mk(), "", "/tmp/acme-new", "")
	if !res.OK() || res.Home != "/tmp/acme-new" {
		t.Fatalf("显式来源的全新安装应采用该路径，got home=%q trace=%v", res.Home, res.Trace)
	}
	if !traceHas(res.Trace, "强告警") {
		t.Errorf("位于 /tmp 类目录的未初始化路径必须给出强告警（C4）：%v", res.Trace)
	}
	// 启发式（二进制目录）：跳过
	res2 := ResolveAcmeHome(mk(), "/tmp/acme-new/acme.sh", "", "")
	if res2.OK() {
		t.Fatalf("启发式来源遇到 /tmp 类未初始化路径必须跳过，got %q", res2.Home)
	}
}

// T48d [D]：**他人所有**的空目录 ⇒ 拒绝（属主检查此前被绕过）。
func TestT48d_Home_EmptyDirOwnedByOthersRejected(t *testing.T) {
	mkProbe := func(uid int) HomeProbe {
		return fakeProbe{uid: 1000, hasCerts: false,
			ents:    map[string]fakeDirEnt{"/opt/acme-empty": {isDir: true, mode: 0o700, uid: uid}},
			evalOut: map[string]string{}}.probe()
	}
	// 他人所有 ⇒ 显式来源也必须拒绝
	res := ResolveAcmeHome(mkProbe(999), "", "/opt/acme-empty", "")
	if res.OK() {
		t.Fatalf("他人所有的空目录不得被采纳为 home，got %q", res.Home)
	}
	if !traceHas(res.Trace, "属主") {
		t.Errorf("trace 应说明属主不符：%v", res.Trace)
	}
	// 属主一致的空目录 + 全新安装 ⇒ 仍应正常采用（避免过度收紧）
	res2 := ResolveAcmeHome(mkProbe(1000), "", "/opt/acme-empty", "")
	if !res2.OK() || res2.Home != "/opt/acme-empty" {
		t.Fatalf("属主一致的空目录应被采用（全新安装），got home=%q trace=%v", res2.Home, res2.Trace)
	}
}

// T48e：位置体检对**已存在祖先链上的他人符号链接**同样生效（路径本身不存在）。
func TestT48e_Home_ForeignSymlinkInAncestors(t *testing.T) {
	probe := fakeProbe{uid: 1000, hasCerts: false,
		ents: map[string]fakeDirEnt{
			"/srv":      {isDir: true, mode: 0o755, uid: 1000},
			"/srv/link": {isDir: true, mode: 0o700, uid: 4321, symlink: true}, // 他人所有的符号链接
		},
		evalOut: map[string]string{"/srv/link": "/srv/real"},
	}.probe()
	res := ResolveAcmeHome(probe, "", "/srv/link/acme-new", "")
	if res.OK() {
		t.Fatalf("祖先链含他人符号链接时必须拒绝，got %q", res.Home)
	}
	if !traceHas(res.Trace, "符号链接") {
		t.Errorf("trace 应说明符号链接问题：%v", res.Trace)
	}
}

// ── v1.6.72 P1/R-E：自有符号链接可绕过位置体检（A 形态） ──

// T52a [D]：路径层存在**自有**符号链接、且解析后落在公共可写前缀 ⇒ **必须拒绝**。
// 修复前（仅拦"他人所有"符号链接 + 按字面前缀比对）会放行本用例。
func TestT52a_Home_SelfSymlinkResolvedIntoTmpLike_Rejected(t *testing.T) {
	p := fakeProbe{uid: 1000, hasCerts: false,
		ents: map[string]fakeDirEnt{
			"/srv":                {isDir: true, mode: 0o755, uid: 1000},
			"/srv/link":           {isDir: true, mode: 0o700, uid: 1000, symlink: true}, // 自有符号链接
			"/tmp":                {isDir: true, mode: 0o1777, uid: 0},
			"/tmp/x":              {isDir: true, mode: 0o700, uid: 1000},
			"/tmp/x/account.conf": {mode: 0o600, uid: 1000},
		},
		evalOut: map[string]string{"/srv/link": "/tmp/x"},
	}.probe()
	p.TmpLike = []string{"/tmp"}

	res := ResolveAcmeHome(p, "", "/srv/link", "") // 显式来源（env）
	if res.OK() {
		t.Fatalf("自有符号链接解析后落入公共可写前缀时必须拒绝（R-E），got %q", res.Home)
	}
	if !traceHas(res.Trace, "符号链接") {
		t.Errorf("trace 应说明符号链接问题：%v", res.Trace)
	}
}

// T52b：无符号链接、路径干净 ⇒ **采用**（且 trace 不应出现"符号链接"）。
func TestT52b_Home_CleanPath_Adopted(t *testing.T) {
	p := fakeProbe{uid: 1000, hasCerts: false,
		ents: map[string]fakeDirEnt{
			"/opt":                   {isDir: true, mode: 0o755, uid: 0},
			"/opt/acme":              {isDir: true, mode: 0o700, uid: 1000},
			"/opt/acme/account.conf": {mode: 0o600, uid: 1000},
		},
		evalOut: map[string]string{},
	}.probe()
	p.TmpLike = []string{"/definitely-not-tmp"}

	res := ResolveAcmeHome(p, "", "/opt/acme", "")
	if !res.OK() {
		t.Fatalf("干净路径必须采用，trace=%v", res.Trace)
	}
	if traceHas(res.Trace, "符号链接") {
		t.Errorf("干净路径不应出现符号链接告警：%v", res.Trace)
	}
}

// T52c：**祖先链** group/other 可写（C 形态）⇒ **采用 + 强告警**（不得 fatal；保住 T48b/T48c 语义）。
func TestT52c_Home_AncestorGroupWritable_AdoptedWithStrongWarn(t *testing.T) {
	p := fakeProbe{uid: 1000, hasCerts: false,
		ents: map[string]fakeDirEnt{
			"/w":                   {isDir: true, mode: 0o775, uid: 1000}, // 组可写祖先
			"/w/acme":              {isDir: true, mode: 0o700, uid: 1000},
			"/w/acme/account.conf": {mode: 0o600, uid: 1000},
		},
		evalOut: map[string]string{},
	}.probe()
	p.TmpLike = []string{"/definitely-not-tmp"}

	res := ResolveAcmeHome(p, "", "/w/acme", "")
	if !res.OK() {
		t.Fatalf("组可写祖先必须「采用 + 强告警」而非拒绝，trace=%v", res.Trace)
	}
	if !traceHas(res.Trace, "强告警") {
		t.Errorf("trace 应含强告警（祖先组可写）：%v", res.Trace)
	}
}
