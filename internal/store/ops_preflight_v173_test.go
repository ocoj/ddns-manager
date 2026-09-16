package store

// v1.6.73 B-1 Slice 4：§4.0 部署前 preflight（N-25）与 §4.2 回退演练（N-3）。
//
// 为什么在这里：§4.0 的 ②「真解一次」与 ③「对现存密文试解」需要**派生密钥 + AES-GCM**
// （`DeriveKey` = HKDF-SHA256，密文为 GCM）—— 纯 shell / python 无法实现（`openssl enc`
// 不支持 GCM）⇒ 这两项由本测试执行；其余可 shell 项（密钥存在/0600、形状判定、备份就位、
// `.storage_key` 可恢复性）由 `internal-docs/audits/preflight-v1.6.73-dns-key.sh` 覆盖，
// 该脚本**强制要求本测试产出的凭据证据**（含 `.storage_key` 的 sha256 绑定），缺证据即拒绝部署。
//
// 口径（与脚本一致，二者必须一致 —— 脚本负责部署侧执行，本测试负责可复现验证）：
//
//	T72a preflight ①–⑥（任一失败 ⇒ 拒绝部署）
//	T72b 回退演练 (i) 未恢复 .bak ⇒ 拒绝 (ii) 恢复 ⇒ 通过 (iii) 逐字节一致 (iv) 迁移预演留痕两行
//	T72c **正控**：每项校验各有 1 个"必须被拒"的负样本（防空判定，D1 教训）；并固定
//	     "① 必须早于 NewStore" 的顺序不变量（NewStore 会补生成密钥 ⇒ 顺序颠倒会使 ① 恒真）
//
// 只读原则：preflight 对**被检目录**只读；任何迁移/写入只在显式副本上发生（T72b (iv)）。

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ocoj/ddns-manager/internal/model"
)

const (
	opsPreflightDirEnv = "DDNS_PREFLIGHT_DIR"        // 生产数据副本（部署期用法）
	opsPreflightBakEnv = "DDNS_PREFLIGHT_BACKUP_DIR" // 备份目录（⑤⑥ 需要）
	opsMkSandboxEnv    = "DDNS_PREFLIGHT_MK_SANDBOX" // 仅产出"生产等价 v2 沙箱"（演练/复核用）
	opsCanonicalToken  = "ddns-manager-preflight-canonical-token"
)

func opsShortHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// ── ① .storage_key 存在且非空（0600）──
//
// **必须在 NewStore 之前调用**：`initStorageKey` 在密钥缺失时会**生成**新密钥，
// 顺序颠倒会让本项永远通过（空判定）—— 而密钥一旦被重新生成，既有密文将不可解。
func opsCheckStorageKey(dir string) (string, error) {
	keyPath := filepath.Join(dir, ".storage_key")
	st, err := os.Stat(keyPath)
	if err != nil {
		return "", fmt.Errorf(".storage_key 不存在（%v）—— 拒绝部署：既有密文将不可解", err)
	}
	if st.Size() == 0 {
		return "", fmt.Errorf(".storage_key 为空 —— 拒绝部署")
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		return "", fmt.Errorf(".storage_key 权限 %04o ≠ 0600 —— 拒绝部署", mode)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf(".storage_key 不可读（%v）—— 拒绝部署", err)
	}
	return fmt.Sprintf("① .storage_key 存在/非空/0600 OK（%d bytes，sha256=%s）",
		st.Size(), opsShortHash(raw)), nil
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 %s 失败: %v", path, err)
	}
	return data
}

// ── ②③ 真解一次 + 对现存密文试解 ──
func opsCheckCrypto(dir string) ([]string, error) {
	store, err := NewStore(dir)
	if err != nil {
		return nil, fmt.Errorf("NewStore(沙箱/副本) 失败: %w", err)
	}
	// ② canonical 令牌往返：证明密钥**可用**（而非仅存在）。
	ct, err := store.encryptWithPurpose(purposeDNSKeys, []byte(opsCanonicalToken))
	if err != nil {
		return nil, fmt.Errorf("canonical 令牌加密失败: %w", err)
	}
	pt, err := store.decryptWithPurpose(purposeDNSKeys, ct)
	if err != nil {
		return nil, fmt.Errorf("canonical 令牌**解得失败** ⇒ .storage_key 不可用 —— 拒绝部署: %w", err)
	}
	if string(pt) != opsCanonicalToken {
		return nil, fmt.Errorf("canonical 令牌往返不一致 —— 拒绝部署")
	}
	// purpose 隔离必须仍然成立（否则 GCM 之外还有跨 purpose 解密风险）
	if _, err := store.decryptWithPurpose(purposePFXPassword, ct); err == nil {
		return nil, fmt.Errorf("purpose 隔离被破坏：错 purpose 竟可解 —— 拒绝部署")
	}
	lines := []string{"② canonical 令牌真解一次 OK（同时验证 purpose 隔离）"}

	// ③ 对**现存**密文试解：dns_keys.json（v2 时）+ ACME 账号面（account_key/eab_key）。
	//    ② 只证明"密钥自洽"，不证明"密钥与现存密文匹配" ⇒ ③ 是必要的独立判据。
	dnsStatus, err := store.ValidateDNSKeysDecryptable()
	if err != nil {
		return nil, fmt.Errorf("对现存 dns_keys.json 试解失败 —— 拒绝部署: %w", err)
	}
	accounts, err := store.LoadACMEAccounts()
	if err != nil {
		return nil, fmt.Errorf("对现存 ACME 账号面试解失败 —— 拒绝部署: %w", err)
	}
	tested := 0
	if dnsStatus == "v2-ok" {
		tested++
	}
	if len(accounts) > 0 {
		tested++
		// 非空判定：落盘不得残留明文 PEM（否则 acme-at-rest 未生效，"试解"名不副实）
		if raw, rerr := os.ReadFile(store.acmeConfigPath()); rerr == nil && strings.Contains(string(raw), "-----BEGIN") {
			return nil, fmt.Errorf("ACME 账号面仍含明文 PEM（acme-at-rest 未生效）—— 拒绝部署")
		}
		// 真解证据：至少一条账号的 account_key 被解出非空（否则"试解"是空判定）
		decrypted := 0
		for _, a := range accounts {
			if a.AccountKey != "" {
				decrypted++
			}
		}
		if decrypted == 0 {
			return nil, fmt.Errorf("ACME 账号面存在但**无任何 account_key 被解出** ⇒ 试解为空判定 —— 拒绝部署")
		}
	}
	if tested == 0 {
		lines = append(lines, fmt.Sprintf(
			"③ 未发现现存加密面（dns_keys.json=%s 且 ACME 账号面为空）⇒ 无密文可试解；真解证据仅来自 ② canonical 令牌（**如实标注**）",
			dnsStatus))
	} else {
		lines = append(lines, fmt.Sprintf(
			"③ 对现存密文试解 OK（dns_keys.json=%s；ACME 账号 %d 条已解出）", dnsStatus, len(accounts)))
	}
	return lines, nil
}

// ── ④ dns_keys.json 形状判定 + 迁移路径预演（**只读**，不执行迁移）──
func opsCheckShape(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "dns_keys.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return "④ dns_keys.json 不存在（全新部署形态）⇒ 无迁移；首启创建 v2 密文", nil
		}
		return "", fmt.Errorf("读 dns_keys.json 失败: %w", err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("dns_keys.json 不是合法 JSON 对象 —— 拒绝部署: %w", err)
	}
	if _, isV2 := probe[dnsKeysEncKey]; isV2 {
		return fmt.Sprintf("④ dns_keys.json = **v2 信封**（哨兵键 %s 存在）⇒ 无需迁移；首启走解密路径", dnsKeysEncKey), nil
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return "", fmt.Errorf("v1 明文解析失败 —— 拒绝部署: %w", err)
	}
	return fmt.Sprintf("④ dns_keys.json = **v1 明文**（%d 个键，无哨兵）⇒ 预演：首启将先写 .bak.<TS>（0600 原件字节快照）再重写 v2；**本项只读、未执行迁移**", len(keys)), nil
}

// ── ⑤⑥ 备份就位 + .storage_key 可恢复性 ──
func opsCheckBackup(dir, backupDir string) ([]string, error) {
	if st, err := os.Stat(backupDir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("备份就位检查失败：备份目录不可用（%v）—— 拒绝部署", err)
	}
	for _, rel := range []string{".storage_key", "dns_keys.json"} {
		if _, err := os.Stat(filepath.Join(backupDir, rel)); err != nil {
			return nil, fmt.Errorf("备份就位检查失败：备份缺少 %s —— 拒绝部署", rel)
		}
	}
	if st, err := os.Stat(filepath.Join(backupDir, "certs")); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("备份就位检查失败：备份缺少 certs/ —— 拒绝部署")
	}
	lines := []string{"⑤ 备份就位 OK（.storage_key + dns_keys.json + certs/）"}

	// ⑥ .storage_key 可恢复性：备份与当前**逐字节一致**。
	//    不一致 ⇒ 用备份恢复时密文不可解（这正是"密钥丢失 fail-fast"要防的场景）。
	cur, err := os.ReadFile(filepath.Join(dir, ".storage_key"))
	if err != nil {
		return nil, fmt.Errorf("读当前 .storage_key 失败: %w", err)
	}
	bak, err := os.ReadFile(filepath.Join(backupDir, ".storage_key"))
	if err != nil {
		return nil, fmt.Errorf("读备份 .storage_key 失败: %w", err)
	}
	if !bytes.Equal(cur, bak) {
		return nil, fmt.Errorf(".storage_key 可恢复性失败：备份与当前不一致（sha256 %s vs %s）—— 拒绝部署",
			opsShortHash(cur), opsShortHash(bak))
	}
	lines = append(lines, fmt.Sprintf("⑥ .storage_key 可恢复性 OK（逐字节一致，sha256=%s）", opsShortHash(cur)))
	return lines, nil
}

// ── 回退前置形状校验（N-3）：解出键集非空且**不含哨兵键**，否则拒绝回退 ──
//
// 这是"未恢复 .bak.<TS> 不得部署回退版本"的强制点：v1.6.72 及更早读不懂 v2 信封，
// 若带着 v2 文件回退，DNS 凭据会**静默丢失**（旧版把信封当作记录集合解析）。
func opsRollbackShapeCheck(dnsKeysPath string) (int, error) {
	data, err := os.ReadFile(dnsKeysPath)
	if err != nil {
		return 0, fmt.Errorf("拒绝回退：%s 不可读（%v）", dnsKeysPath, err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return 0, fmt.Errorf("拒绝回退：%s 不是合法 JSON 对象（%v）", dnsKeysPath, err)
	}
	if _, isV2 := probe[dnsKeysEncKey]; isV2 {
		return 0, fmt.Errorf(
			"拒绝回退：%s 仍为 v2 信封（存在哨兵键 %s）—— 必须先恢复 .bak.<TS> 明文快照", dnsKeysPath, dnsKeysEncKey)
	}
	keys := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &keys); err != nil {
		return 0, fmt.Errorf("拒绝回退：明文结构非法（%v）", err)
	}
	if len(keys) == 0 {
		return 0, fmt.Errorf("拒绝回退：解出键集为空 —— 回退后 DNS 凭据会丢失，需人工确认")
	}
	return len(keys), nil
}

// ── 沙箱 ──

// opsSandbox 构建与生产形态等价的 v2 沙箱（CI 用法）。
// 设置 DDNS_PREFLIGHT_DIR/DDNS_PREFLIGHT_BACKUP_DIR 时改为对**生产数据副本**执行同一套断言。
func opsSandbox(t *testing.T) (dir, backupDir string) {
	t.Helper()
	if d := os.Getenv(opsPreflightDirEnv); d != "" {
		b := os.Getenv(opsPreflightBakEnv)
		if b == "" {
			t.Fatalf("%s 已设置但 %s 未设置（⑤⑥ 需要备份目录）", opsPreflightDirEnv, opsPreflightBakEnv)
		}
		return d, b
	}
	dir = t.TempDir()
	backupDir = filepath.Join(t.TempDir(), "bak")
	opsBuildSandbox(t, dir, backupDir)
	return dir, backupDir
}

// opsBuildSandbox 在**指定**目录写入生产等价的 v2 数据面 + 备份（供演练与复核复现）。
func opsBuildSandbox(t *testing.T, dir, backupDir string) {
	t.Helper()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveDNSKeys(map[string]*model.DNSKeyRecord{
		"pf-key": {Name: "pf-key", Provider: "alidns", AccessKeyID: "pf-akid", AccessKeySecret: "pf-secret"},
	}); err != nil {
		t.Fatal(err)
	}
	// 合成值（**非** PEM）：保存路径会加密任何非空 account_key ⇒ 落盘为密文，
	// 从而让 ③ 的 ACME 面成为真正的"对现存密文试解"。刻意不用 PEM 头，避免在仓库内
	// 出现形似私钥的字面量（脱敏审计）。
	const opsSyntheticAccountKey = "preflight-synthetic-account-key-not-a-real-key"
	if err := st.SaveACMEAccounts([]ACMEAccountConfig{{
		Email: "ops@example.invalid", CA: "Let's Encrypt", KeyType: "ec256",
		AccountKey: opsSyntheticAccountKey,
	}}); err != nil {
		t.Fatal(err)
	}
	// 非空判定：落盘必须是密文（既不含合成明文，也不含 PEM 头）
	if raw, rerr := os.ReadFile(filepath.Join(dir, "acme_config.json")); rerr != nil {
		t.Fatal(rerr)
	} else if strings.Contains(string(raw), opsSyntheticAccountKey) || strings.Contains(string(raw), "-----BEGIN") {
		t.Fatal("前置条件不成立：acme_config.json 仍是明文（acme-at-rest 未生效）")
	}
	if err := st.SaveCertBundle(&CertBundle{
		Name: "acme-ops", PFXPassword: "pf-ops-pw",
		Files: map[string][]byte{"fullchain.pem": []byte("x"), "privkey.pem": []byte("y")},
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(backupDir, "certs"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{".storage_key", "dns_keys.json"} {
		data := mustRead(t, filepath.Join(dir, rel))
		if err := os.WriteFile(filepath.Join(backupDir, rel), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// ── T72a：preflight ①–⑥ ──

func TestT72a_PreflightOnSandboxCopy(t *testing.T) {
	// 演练/复核用：产出"生产等价 v2 沙箱"后退出（不执行断言）。
	if out := os.Getenv(opsMkSandboxEnv); out != "" {
		opsBuildSandbox(t, out, out+"-bak")
		t.Skipf("已产出演练沙箱：数据=%s 备份=%s-bak（本模式不执行断言）", out, out)
	}
	dir, backupDir := opsSandbox(t)

	// ① 必须在 NewStore（②③ 内首次调用）之前
	keyLine, err := opsCheckStorageKey(dir)
	if err != nil {
		t.Fatalf("① preflight 失败：%v", err)
	}
	var lines []string
	lines = append(lines, keyLine)

	cryptoLines, err := opsCheckCrypto(dir) // ②③（含 NewStore）
	if err != nil {
		t.Fatalf("②③ preflight 失败：%v", err)
	}
	lines = append(lines, cryptoLines...)

	shapeLine, err := opsCheckShape(dir) // ④ 只读
	if err != nil {
		t.Fatalf("④ preflight 失败：%v", err)
	}
	lines = append(lines, shapeLine)

	backupLines, err := opsCheckBackup(dir, backupDir) // ⑤⑥
	if err != nil {
		t.Fatalf("⑤⑥ preflight 失败：%v", err)
	}
	lines = append(lines, backupLines...)

	for _, l := range lines {
		t.Log("留痕 " + l)
	}
}

// ── T72b：回退演练（§4.2 必做，(i)–(iv)）──

func TestT72b_RollbackDrill(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 当前状态 = 已迁移（v2 信封）
	if err := st.SaveDNSKeys(map[string]*model.DNSKeyRecord{
		"pf-key": {Name: "pf-key", Provider: "alidns", AccessKeyID: "pf-akid", AccessKeySecret: "pf-secret"},
	}); err != nil {
		t.Fatal(err)
	}
	dnsKeysPath := filepath.Join(dir, "dns_keys.json")
	// 迁移期留下的 v1 明文快照（0600，原件字节）
	v1Plain := []byte(`{"pf-key":{"name":"pf-key","provider":"alidns","access_key_id":"pf-akid","access_key_secret":"pf-secret"}}`)
	bakPath := dnsKeysPath + ".bak.20260917T000000Z"
	if err := os.WriteFile(bakPath, v1Plain, 0o600); err != nil {
		t.Fatal(err)
	}

	// (i) 未恢复 .bak（当前为 v2 哨兵）⇒ 必须**拒绝回退**
	if n, err := opsRollbackShapeCheck(dnsKeysPath); err == nil {
		t.Errorf("(i) 未恢复 .bak 时必须拒绝回退（当前为 v2 信封），实际通过（键数 %d）", n)
	} else {
		t.Log("留痕 (i) 拒绝回退 —— " + err.Error())
	}

	// (ii) 恢复 .bak ⇒ 通过
	if err := os.WriteFile(dnsKeysPath, v1Plain, 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := opsRollbackShapeCheck(dnsKeysPath)
	if err != nil {
		t.Fatalf("(ii) 恢复 .bak 后应允许回退，实际被拒: %v", err)
	}
	t.Logf("留痕 (ii) 允许回退（明文键集 %d 个，无哨兵键）", n)

	// (iii) 校验一致（与 .bak 逐字节一致）
	got := mustRead(t, dnsKeysPath)
	if !bytes.Equal(got, v1Plain) {
		t.Error("(iii) 恢复内容应与 .bak 逐字节一致")
	}
	t.Log("留痕 (iii) 恢复内容与 .bak 逐字节一致 OK")

	// (iv) 迁移预演：在**副本**上真实执行一次迁移，验证「密文真解成功 + 记录结构合法」
	scratch := t.TempDir()
	for _, rel := range []string{".storage_key", "dns_keys.json", filepath.Base(bakPath)} {
		data := mustRead(t, filepath.Join(dir, rel))
		if err := os.WriteFile(filepath.Join(scratch, rel), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sst, err := NewStore(scratch)
	if err != nil {
		t.Fatal(err)
	}
	if err := sst.ReloadStorageKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := sst.LoadDNSKeys(); err != nil { // 触发 v1→v2 迁移（写 .bak + 重写）
		t.Fatalf("(iv) 迁移预演失败: %v", err)
	}
	status, err := sst.ValidateDNSKeysDecryptable()
	if err != nil {
		t.Fatalf("(iv) 迁移后真解失败: %v", err)
	}
	if status != "v2-ok" {
		t.Fatalf("(iv) 迁移后形状应为 v2-ok，实际 %q", status)
	}
	keys, err := sst.LoadDNSKeys()
	if err != nil || len(keys) != 1 {
		t.Fatalf("(iv) 迁移后记录结构应合法且非空（1 条），实际 %d 条 err=%v", len(keys), err)
	}
	t.Log("留痕 (iv-1) 对现存密文解密成功（v2-ok）")
	t.Log("留痕 (iv-2) 记录结构合法（DNS Key 1 条，键集非空）")

	// 迁移必须**不就地覆盖**：副本内应出现 .bak.<TS> 快照
	matches, _ := filepath.Glob(dnsKeysPathGlob(scratch))
	if len(matches) < 1 {
		t.Error("(iv) 迁移必须留下 .bak.<TS> 原件快照（不就地覆盖）")
	}
}

func dnsKeysPathGlob(dir string) string {
	return filepath.Join(dir, "dns_keys.json.bak.*")
}

// ── T72c：正控（每项校验各 1 个必须被拒的负样本）──

func TestT72c_PreflightPositiveControl(t *testing.T) {
	dir, backupDir := opsSandbox(t)

	t.Run("① 缺 .storage_key ⇒ 必须拒绝；且必须早于 NewStore", func(t *testing.T) {
		bare := t.TempDir()
		if _, err := opsCheckStorageKey(bare); err == nil {
			t.Error("正控失败：无 .storage_key 时 ① 未报错（空判定）")
		}
		// 顺序证明：NewStore 会**补生成**密钥 ⇒ 若 ① 在 NewStore 之后，本项将永远通过
		if _, err := NewStore(bare); err != nil {
			t.Fatal(err)
		}
		if _, err := opsCheckStorageKey(bare); err != nil {
			t.Errorf("顺序不变量被破坏：NewStore 后密钥已生成 ⇒ ① 必须在 NewStore 之前（实际报错 %v）", err)
		}
	})

	t.Run("① 权限 0644 / 空文件 ⇒ 必须拒绝", func(t *testing.T) {
		d := t.TempDir()
		p := filepath.Join(d, ".storage_key")
		if err := os.WriteFile(p, mustRead(t, filepath.Join(dir, ".storage_key")), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := opsCheckStorageKey(d); err == nil {
			t.Error("正控失败：0644 应被拒")
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := opsCheckStorageKey(d); err == nil {
			t.Error("正控失败：空密钥应被拒")
		}
	})

	t.Run("③ .storage_key 与现存密文不匹配 ⇒ 必须拒绝（且 ② 单独不足以发现）", func(t *testing.T) {
		mismatched := t.TempDir()
		// 拷贝数据面，但换成**另一个合法 32 字节密钥**
		for _, rel := range []string{"dns_keys.json", "acme_config.json"} {
			if data, err := os.ReadFile(filepath.Join(dir, rel)); err == nil {
				if err := os.WriteFile(filepath.Join(mismatched, rel), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		other := bytes.Repeat([]byte{0x5a}, 32)
		if err := os.WriteFile(filepath.Join(mismatched, ".storage_key"), other, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := opsCheckCrypto(mismatched); err == nil {
			t.Error("正控失败：密钥与现存密文不匹配时必须拒绝（② 只证明密钥自洽，③ 才是匹配判据）")
		}
	})

	t.Run("④ dns_keys.json 非法 JSON ⇒ 必须拒绝", func(t *testing.T) {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, "dns_keys.json"), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := opsCheckShape(d); err == nil {
			t.Error("正控失败：非法 JSON 应被拒")
		}
	})

	t.Run("⑤ 备份缺 certs/ ⇒ 必须拒绝；⑥ .storage_key 不一致 ⇒ 必须拒绝", func(t *testing.T) {
		bad := t.TempDir()
		if err := os.MkdirAll(bad, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, rel := range []string{".storage_key", "dns_keys.json"} {
			if err := os.WriteFile(filepath.Join(bad, rel), mustRead(t, filepath.Join(backupDir, rel)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := opsCheckBackup(dir, bad); err == nil {
			t.Error("正控失败：备份缺 certs/ 应被拒")
		}
		if err := os.MkdirAll(filepath.Join(bad, "certs"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := opsCheckBackup(dir, bad); err != nil {
			t.Fatalf("补齐 certs/ 后应通过 ⑤，实际 %v", err)
		}
		// ⑥：把备份里的密钥换成别的内容 ⇒ 必须拒绝
		if err := os.WriteFile(filepath.Join(bad, ".storage_key"), bytes.Repeat([]byte{0x11}, 32), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := opsCheckBackup(dir, bad); err == nil {
			t.Error("正控失败：⑥ 备份密钥与当前不一致应被拒")
		}
	})

	t.Run("回退前置：键集为空 ⇒ 必须拒绝", func(t *testing.T) {
		d := t.TempDir()
		p := filepath.Join(d, "dns_keys.json")
		if err := os.WriteFile(p, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := opsRollbackShapeCheck(p); err == nil {
			t.Error("正控失败：空键集回退应被拒（会静默丢凭据）")
		}
	})
}
