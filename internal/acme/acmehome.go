package acme

// v1.6.71 N1: acme.sh home 的显式解析与判定。
//
// 背景：acme.sh 以 $HOME/.acme.sh 推导自己的 home；systemd 默认不设置 HOME，
// 于是 home 落到 /.acme.sh —— 既找不到既有 conf（续期 install 失败），又会在
// 非预期目录创建携带明文凭据的 account.conf（I28）。
//
// 因此 home 必须显式固定：候选集封闭、逐候选按判定表处置、不可判定即拒绝执行
// （fail-fast），绝不"猜一个会被创建并落密的路径"。
//
// 规格来源：internal-docs/audits/2026-09-16-acme-renew-N1-N2-followup-plan-v3.md
//   §1.2 home 形态自检（account.conf | ca/）
//   §1.3 候选判定表（三分法 + 语义分层 + 绝对化）
//   §1.3.4 目录体检（C4 + H1）

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// HomeSource 标识候选来源（决定"显式意图"与否）。
type HomeSource string

const (
	// SrcEnv 环境变量 LE_WORKING_DIR：运维显式意图。
	SrcEnv HomeSource = "env:LE_WORKING_DIR"
	// SrcBinaryDir acme.sh 可执行文件（解析符号链接后）所在目录：启发式。
	SrcBinaryDir HomeSource = "binary-dir"
	// SrcHomeDefault $HOME/.acme.sh：启发式（acme.sh 自身默认值）。
	SrcHomeDefault HomeSource = "home-default"
)

// HomeProbe 提供可注入的文件系统探测，便于测试构造各种目录形态。
type HomeProbe struct {
	Stat         func(string) (os.FileInfo, error)
	Lstat        func(string) (os.FileInfo, error)
	EvalSymlinks func(string) (string, error)
	ReadDir      func(string) ([]os.DirEntry, error)
	UID          int
	// HasCerts 表示本地是否已管理 ACME 证书（存在 certs/acme-* bundle）。
	// 用于 §1.3 的"语义分层"：本地已有证书时不允许采用未初始化路径。
	HasCerts bool
	// TmpLike 是"公共可写目录"前缀表；为空时使用默认值（/tmp 等）。
	// 可注入仅为测试便利：测试沙箱本身就位于 /tmp 下。
	TmpLike []string
}

// DefaultHomeProbe 返回基于真实文件系统的探测。
func DefaultHomeProbe(hasCerts bool) HomeProbe {
	return HomeProbe{
		Stat:         os.Stat,
		Lstat:        os.Lstat,
		EvalSymlinks: filepath.EvalSymlinks,
		ReadDir:      os.ReadDir,
		UID:          os.Getuid(),
		HasCerts:     hasCerts,
		TmpLike:      append([]string(nil), tmpLikeDirs...),
	}
}

// HomeResolution 是解析结果与审计轨迹。
type HomeResolution struct {
	Home  string   // 采用时的绝对路径；fail-fast 时为空
	Trace []string // 逐候选判定说明（写入审计，便于运维一次定位）
	// Caveats 为**非判定性**提示（仅告警，不参与 adopt/skip 判定）。
	// v1.6.73 B-2：仅供 Server 侧消费（审计/通知），不改变任何判定结果（N-26）。
	Caveats []string
}

// OK 表示已确定可用 home。
func (r HomeResolution) OK() bool { return r.Home != "" }

// Err 在 fail-fast 时返回聚合错误（供调用方拒绝执行 acme.sh）。
func (r HomeResolution) Err() error {
	if r.OK() {
		return nil
	}
	return fmt.Errorf("无法确定 acme.sh home，已拒绝执行 acme.sh（候选解析：%s）", strings.Join(r.Trace, "；"))
}

const (
	selfCheckAccountConf = "account.conf"
	selfCheckCADir       = "ca"
)

// acmeHomeSelfCheck 实现 §1.2 定稿判据：仅 account.conf | ca/。
// 明确不含 acme.sh 本身（它几乎总在其目录内，会把二进制目录误判为 home），
// 也不含 dnsapi/（--install 必产 account.conf，且单文件安装不产 dnsapi/）。
func acmeHomeSelfCheck(p HomeProbe, dir string) (bool, string) {
	if fi, err := p.Stat(filepath.Join(dir, selfCheckAccountConf)); err == nil && !fi.IsDir() {
		return true, selfCheckAccountConf
	}
	if fi, err := p.Stat(filepath.Join(dir, selfCheckCADir)); err == nil && fi.IsDir() {
		return true, selfCheckCADir + "/"
	}
	return false, "无 account.conf / ca/"
}

// acmeHomePositionCheck 对候选路径做"位置类"体检 —— **不要求目录存在**。
//
// G1（v1.6.71 收尾）：位置检查必须先于存在性判断。否则"路径不存在/为空"的分支
// （全新安装）会绕过 C4/H1/属主检查，把 home 建到 /tmp 类公共可写目录，或采纳
// 他人预置的路径，随后 acme.sh 在那里写入明文 account.conf。
//
// 返回 (ok, warn, fatal)：ok=false ⇒ 必须拒绝；warn 非空 ⇒ 可用但需强告警。
func acmeHomePositionCheck(p HomeProbe, dir string) (bool, string, string) {
	if bad, reason := foreignSymlinkInPath(p, dir); bad {
		return false, "", reason
	}
	tmpLike := p.TmpLike
	if len(tmpLike) == 0 {
		tmpLike = tmpLikeDirs
	}
	// v1.6.72 P1/R-E（A 形态）：路径层存在**自有**符号链接、且解析后落在公共可写前缀 ⇒ 拒绝。
	// 与 D 形态（他人所有符号链接，由 foreignSymlinkInPath 处理）区分：本分支只处理自有链接，
	// 以免遮蔽"他人所有"的归因文本（T48e 断言，C1 收口）。
	if hasLink, linkPath := selfSymlinkInPath(p, dir); hasLink {
		if real, err := p.EvalSymlinks(dir); err == nil {
			for _, d := range tmpLike {
				if real == d || strings.HasPrefix(real, d+"/") {
					return false, "", fmt.Sprintf(
						"路径层 %s 是自有符号链接，解析后落在公共可写目录 %s", linkPath, d)
				}
			}
		}
	}
	// B 形态（C4 既有语义）：**字面**路径落在公共可写前缀 ⇒ 采用 + 强告警（T48b/T48c 依赖该语义）。
	warn := ""
	for _, d := range tmpLike {
		if dir == d || strings.HasPrefix(dir, d+"/") {
			warn = "位于公共可写目录 " + d
			break
		}
	}
	// 注：C 形态（祖先组/other 可写）**不在此处**返回告警 —— 位置告警会参与"启发式来源 ⇒ 跳过"的
	// 判定（decideHomeCandidate），而 /tmp、/home 等常见祖先是组可写的 ⇒ 会把合法的启发式 home
	// （如 binary-dir 推导）误判为跳过（T40 实测回归）。故 C 形态改为在 decideHomeCandidate 中
	// **仅对显式来源**附加为信息性强告警（见该函数），不改变任何 adopt/skip 判定。
	return true, warn, ""
}

// selfSymlinkInPath 检查路径任一层是否为**自有**（uid == p.UID）的符号链接。
// 他人所有的符号链接由 foreignSymlinkInPath 负责（保持既有归因文本与 T48e 断言）。
func selfSymlinkInPath(p HomeProbe, dir string) (bool, string) {
	cur := ""
	for _, seg := range strings.Split(dir, "/") {
		if seg == "" {
			continue
		}
		cur += "/" + seg
		fi, err := p.Lstat(cur)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if sys, ok := fi.Sys().(*syscall.Stat_t); ok && int(sys.Uid) == p.UID {
			return true, cur
		}
	}
	return false, ""
}

// ancestorGroupWritable 检查 dir 的**祖先链**（不含 dir 自身）是否存在 group/other 可写层。
func ancestorGroupWritable(p HomeProbe, dir string) string {
	cur := ""
	segs := strings.Split(dir, "/")
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		cur += "/" + seg
		if i == len(segs)-1 {
			break // 不含 dir 自身（由 acmeHomeHealth 负责）
		}
		fi, err := p.Stat(cur)
		if err != nil {
			continue
		}
		if sys, ok := fi.Sys().(*syscall.Stat_t); ok && sys.Mode&0o022 != 0 {
			return fmt.Sprintf("祖先目录 %s 对 group/other 可写", cur)
		}
	}
	return ""
}

// warnSuffix 把位置/体检告警并入"采用"说明；"强告警"字样同时供审计与测试断言。
func warnSuffix(warn string) string {
	if warn == "" {
		return ""
	}
	return "；" + warn + "（强告警）"
}

// acmeHomeHealth 实现 §1.3.4 目录体检。
// 返回 (ok, warn, fatalReason)：ok=false 表示必须拒绝；warn 非空表示可用但需告警。
func acmeHomeHealth(p HomeProbe, dir string) (bool, string, string) {
	// H1：疑似 acme.sh 源码检出 —— 即使自检通过也拒绝（避免凭据落入 VCS 工作树）
	if fi, err := p.Stat(filepath.Join(dir, ".git")); err == nil && fi.IsDir() {
		return false, "", "含 .git/，疑似 acme.sh 源码检出（非 ACME home）"
	}
	if fi, err := p.Stat(dir); err == nil {
		if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
			if int(sys.Uid) != p.UID {
				return false, "", fmt.Sprintf("目录属主 uid=%d ≠ 本进程 uid=%d", sys.Uid, p.UID)
			}
			if sys.Mode&0o022 != 0 {
				return false, "", "目录对 group/other 可写"
			}
		}
	}
	if bad, reason := foreignSymlinkInPath(p, dir); bad {
		return false, "", reason
	}
	tmpLike := p.TmpLike
	if len(tmpLike) == 0 {
		tmpLike = tmpLikeDirs
	}
	for _, d := range tmpLike {
		if dir == d || strings.HasPrefix(dir, d+"/") {
			return true, "位于公共可写目录 " + d, ""
		}
	}
	return true, "", ""
}

var tmpLikeDirs = []string{"/tmp", "/var/tmp", "/dev/shm", "/run"}

// foreignSymlinkInPath 检查路径任一层是否为他人所有的符号链接。
func foreignSymlinkInPath(p HomeProbe, dir string) (bool, string) {
	cur := ""
	for _, seg := range strings.Split(dir, "/") {
		if seg == "" {
			continue
		}
		cur += "/" + seg
		fi, err := p.Lstat(cur)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if sys, ok := fi.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != p.UID {
			return true, fmt.Sprintf("路径层 %s 是他人（uid=%d）所有的符号链接", cur, sys.Uid)
		}
	}
	return false, ""
}

// homeCandidate 是一个待判定的候选。
type homeCandidate struct {
	Source   HomeSource
	Raw      string
	Explicit bool // 运维显式意图（决定"未过自检/体检"时是 fail-fast 还是跳过）
}

// decideHomeCandidate 实现 §1.3 候选判定表。
// 返回 (use, home, note, fatal)。
func decideHomeCandidate(p HomeProbe, c homeCandidate) (bool, string, string, bool) {
	raw := strings.TrimSpace(c.Raw)
	if raw == "" {
		return false, "", fmt.Sprintf("[%s] 未设置 ⇒ 跳过", c.Source), false
	}
	// C2：绝不按进程 cwd 解析相对路径
	if !filepath.IsAbs(raw) {
		return false, "", fmt.Sprintf("[%s] 非绝对路径 %q ⇒ 跳过（不按进程 cwd 解析）", c.Source, raw), false
	}
	dir := filepath.Clean(raw)

	// G1：位置类体检先于存在性判断（对不存在的路径检查其**现有祖先链**）
	posOK, posWarn, posFatal := acmeHomePositionCheck(p, dir)
	if !posOK {
		if c.Explicit {
			return false, "", fmt.Sprintf("[%s] %s 位置体检不通过：%s ⇒ 拒绝", c.Source, dir, posFatal), true
		}
		return false, "", fmt.Sprintf("[%s] %s 位置体检不通过：%s ⇒ 跳过", c.Source, dir, posFatal), false
	}

	fi, statErr := p.Stat(dir)
	if statErr != nil {
		// 不存在：仅显式来源、且本地尚无 ACME 证书（全新安装）才允许由 acme.sh 初始化
		if !c.Explicit {
			return false, "", fmt.Sprintf("[%s] %s 不存在 ⇒ 跳过", c.Source, dir), false
		}
		if !p.HasCerts {
			return true, dir, fmt.Sprintf("[%s] %s 不存在 ⇒ 采用（本地尚无 ACME 证书，将由 acme.sh 初始化）%s", c.Source, dir, warnSuffix(posWarn)), false
		}
		return false, "", fmt.Sprintf("[%s] %s 不存在，但本地已有 ACME 证书 ⇒ 跳过（语义分层）", c.Source, dir), false
	}
	if !fi.IsDir() {
		return false, "", fmt.Sprintf("[%s] %s 不是目录 ⇒ 跳过", c.Source, dir), false
	}
	empty := false
	if es, err := p.ReadDir(dir); err == nil {
		empty = len(es) == 0
	}
	if empty {
		if !c.Explicit {
			return false, "", fmt.Sprintf("[%s] %s 为空目录 ⇒ 跳过", c.Source, dir), false
		}
		// G1：空目录同样必须过完整体检（属主/权限/.git/符号链接/tmp）——
		// 否则会采纳"他人预置的空目录"作为 home。
		if ok, warn, fatalReason := acmeHomeHealth(p, dir); !ok {
			return false, "", fmt.Sprintf("[%s] %s 空目录体检不通过：%s ⇒ 拒绝", c.Source, dir, fatalReason), true
		} else if warn != "" {
			posWarn = warn
		}
		if !p.HasCerts {
			return true, dir, fmt.Sprintf("[%s] %s 为空目录 ⇒ 采用（本地尚无 ACME 证书，将由 acme.sh 初始化）%s", c.Source, dir, warnSuffix(posWarn)), false
		}
		return false, "", fmt.Sprintf("[%s] %s 为空目录，但本地已有 ACME 证书 ⇒ 跳过（语义分层）", c.Source, dir), false
	}

	// 非空目录：必须通过自检
	if ok, why := acmeHomeSelfCheck(p, dir); !ok {
		if c.Explicit {
			return false, "", fmt.Sprintf("[%s] %s 存在但非 ACME home（%s）⇒ 拒绝向其写入凭据", c.Source, dir, why), true
		}
		return false, "", fmt.Sprintf("[%s] %s 存在但非 ACME home（%s）⇒ 跳过", c.Source, dir, why), false
	}
	// 体检
	ok, warn, fatalReason := acmeHomeHealth(p, dir)
	if !ok {
		if c.Explicit {
			return false, "", fmt.Sprintf("[%s] %s 体检不通过：%s ⇒ 拒绝", c.Source, dir, fatalReason), true
		}
		return false, "", fmt.Sprintf("[%s] %s 体检不通过：%s ⇒ 跳过", c.Source, dir, fatalReason), false
	}
	// v1.6.73 B-2：C 形态（祖先链 group/other 可写）**不再并入 warn** ——
	// warn 会参与 adopt/skip 判定（见下方 `if warn != ""`）；本项改为在**采纳后**
	// 由 ResolveAcmeHome 收集进 `Caveats`（非判定通道），且对**全部来源**（含启发式）生效。
	if warn == "" && posWarn != "" {
		warn = posWarn
	}
	if warn != "" {
		if !c.Explicit {
			return false, "", fmt.Sprintf("[%s] %s %s ⇒ 跳过（仅显式来源可采用）", c.Source, dir, warn), false
		}
		return true, dir, fmt.Sprintf("[%s] %s %s ⇒ 采用（强告警：来源为显式）", c.Source, dir, warn), false
	}
	return true, dir, fmt.Sprintf("[%s] %s 通过自检与体检", c.Source, dir), false
}

// ResolveAcmeHome 按 §1.3 判定表逐候选解析（顺序即优先级）。
//
// 候选①（显式配置 cert.provider）不在此函数内：它决定 acme.sh 可执行路径，
// 由 server 层解析后经 SetAcmeShPath 注入（I29）。
func ResolveAcmeHome(p HomeProbe, acmeShPath, envWorkDir, homeEnv string) HomeResolution {
	res := HomeResolution{}
	var cands []homeCandidate
	cands = append(cands, homeCandidate{Source: SrcEnv, Raw: envWorkDir, Explicit: true})

	// ③ acme.sh 所在目录（解析符号链接；必须绝对路径）
	if s := strings.TrimSpace(acmeShPath); s != "" {
		if !filepath.IsAbs(s) {
			res.Trace = append(res.Trace, fmt.Sprintf("[%s] acme.sh 路径非绝对 %q ⇒ 跳过", SrcBinaryDir, s))
		} else if real, err := p.EvalSymlinks(s); err != nil {
			res.Trace = append(res.Trace, fmt.Sprintf("[%s] 无法解析 %s：%v ⇒ 跳过", SrcBinaryDir, s, err))
		} else {
			cands = append(cands, homeCandidate{Source: SrcBinaryDir, Raw: filepath.Dir(real)})
		}
	}
	// ④ $HOME/.acme.sh（HOME 须绝对化；非绝对即跳过）
	if h := strings.TrimSpace(homeEnv); h != "" {
		if !filepath.IsAbs(h) {
			res.Trace = append(res.Trace, fmt.Sprintf("[%s] HOME 非绝对 %q ⇒ 跳过", SrcHomeDefault, h))
		} else {
			cands = append(cands, homeCandidate{Source: SrcHomeDefault, Raw: filepath.Join(h, ".acme.sh")})
		}
	}

	for _, c := range cands {
		use, home, note, fatal := decideHomeCandidate(p, c)
		res.Trace = append(res.Trace, note)
		if fatal {
			res.Trace = append(res.Trace, "⇒ fail-fast：拒绝执行 acme.sh（不创建任何目录）")
			return res
		}
		if use {
			res.Home = home
			// v1.6.73 B-2：**非判定性**提示（仅告警）—— 采纳后收集，写入审计/通知通道。
			// 「强告警」字样与既有 T52c 断言一致（该字样原由 adopt 消息携带，现由告警通道携带）。
			if w := ancestorGroupWritable(p, home); w != "" {
				res.Caveats = append(res.Caveats, w)
				res.Trace = append(res.Trace, "[home 告警] "+w+"（强告警）")
			}
			return res
		}
	}
	res.Trace = append(res.Trace, "⇒ fail-fast：无可用 ACME home，拒绝执行 acme.sh")
	return res
}

// acmeShEnv 构造 acme.sh 子进程环境（S14：永不返回 nil）。
//
//	① 基线 os.Environ()
//	② HOME 缺失/为空 ⇒ HOME=<home 的父目录>（HOME 供 curl/openssl/git 等查找用户配置，
//	   设为父目录才是"最小意外"；设为 home 自身会让它们指向 ACME home）
//	③ 始终显式 LE_WORKING_DIR=<home>
//	④ 仅当 dp != nil 且 provider 映射命中时注入凭据（S3）
//	⑤ 显式去重（保留最后一个），不依赖 os/exec 的实现细节
func acmeShEnv(dp *DNSProvider, home string) []string {
	env := os.Environ()
	if home != "" {
		if strings.TrimSpace(os.Getenv("HOME")) == "" {
			env = append(env, "HOME="+filepath.Dir(home))
		}
		env = append(env, "LE_WORKING_DIR="+home)
	}
	if dp != nil {
		if mapping, ok := dnsAPILookup(dp.Name); ok {
			if mapping.env != "" && dp.KeyID != "" {
				env = append(env, mapping.env+"="+dp.KeyID)
			}
			if mapping.secret != "" && dp.KeySecret != "" {
				env = append(env, mapping.secret+"="+dp.KeySecret)
			}
		}
	}
	return dedupEnv(env)
}

// dedupEnv 去除同名键，仅保留最后一个。
func dedupEnv(env []string) []string {
	last := make(map[string]int, len(env))
	keyOf := func(s string) string {
		if i := strings.IndexByte(s, '='); i >= 0 {
			return s[:i]
		}
		return s
	}
	for i, kv := range env {
		last[keyOf(kv)] = i
	}
	out := make([]string, 0, len(env))
	for i, kv := range env {
		if last[keyOf(kv)] == i {
			out = append(out, kv)
		}
	}
	return out
}
