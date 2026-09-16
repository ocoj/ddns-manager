package store

// v1.6.73 B-1（Slice 2，T66–T69）：DNS 凭据落盘加密、迁移与 fail-fast。
//
//   T66 落盘为 v2 密文信封（含哨兵键 `__ddnskey_enc`，**不得**出现明文凭据串）+ 往返一致
//   T67 v1 明文 ⇒ 自动迁移：先落 `.bak.<TS>`（0600、原件字节）再写 v2；回调恰一次
//   T68 密文损坏/密钥不匹配 ⇒ **报错 fail-fast**（绝不降级为空集合）
//   T69 ValidateDNSKeysDecryptable：v2-ok / v1-plaintext / absent / 损坏 ⇒ 错误（对**现存密文**真解一次）

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ocoj/ddns-manager/internal/model"
)

const b1Secret = "LTAI5tSECRET-VALUE-FOR-TEST-9f2a"

func b1WriteV1(t *testing.T, dir string, keys map[string]*model.DNSKeyRecord) []byte {
	t.Helper()
	b, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dns_keys.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestT66_DNSKeysOnDiskIsCiphertext(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]*model.DNSKeyRecord{"k1": {Name: "k1", Provider: "alidns", AccessKeyID: "id", AccessKeySecret: b1Secret}}
	if err := st.SaveDNSKeys(keys); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "dns_keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"__ddnskey_enc"`) {
		t.Errorf("落盘必须为 v2 信封（含哨兵键 __ddnskey_enc）：%s", string(raw)[:min(200, len(raw))])
	}
	if strings.Contains(string(raw), b1Secret) {
		t.Errorf("落盘**不得**出现明文凭据串（事故同形态）")
	}
	got, err := st.LoadDNSKeys()
	if err != nil {
		t.Fatal(err)
	}
	if got["k1"] == nil || got["k1"].AccessKeySecret != b1Secret {
		t.Errorf("往返必须一致，实际 %+v", got["k1"])
	}
}

func TestT67_PlaintextMigrates_WithBackup(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	v1 := map[string]*model.DNSKeyRecord{"k2": {Name: "k2", Provider: "alidns", AccessKeyID: "id2", AccessKeySecret: b1Secret}}
	orig := b1WriteV1(t, dir, v1)

	var backups []string
	st.SetDNSKeysMigrationReporter(func(bp string, err error) {
		if err != nil {
			t.Errorf("迁移备份失败：%v", err)
			return
		}
		backups = append(backups, bp)
	})
	got, err := st.LoadDNSKeys()
	if err != nil {
		t.Fatalf("v1 明文应可读：%v", err)
	}
	if got["k2"] == nil || got["k2"].AccessKeySecret != b1Secret {
		t.Errorf("迁移后取值必须不变：%+v", got["k2"])
	}
	if len(backups) != 1 {
		t.Fatalf("迁移回调应恰一次，实际 %v", backups)
	}
	bak, err := os.ReadFile(backups[0])
	if err != nil {
		t.Fatalf("备份文件应存在且可读：%v", err)
	}
	if string(bak) != string(orig) {
		t.Errorf("备份必须是**原件字节**（不就地覆盖）")
	}
	if fi, _ := os.Stat(backups[0]); fi != nil && fi.Mode().Perm() != 0o600 {
		t.Errorf("备份权限应 0600，实际 %v", fi.Mode().Perm())
	}
	after, _ := os.ReadFile(filepath.Join(dir, "dns_keys.json"))
	if !strings.Contains(string(after), `"__ddnskey_enc"`) {
		t.Errorf("迁移后文件应为 v2 密文：%s", string(after)[:min(200, len(after))])
	}
	// 幂等：再次加载不再迁移（回调不再触发）
	st2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	st2.SetDNSKeysMigrationReporter(func(string, error) { n++ })
	if _, err := st2.LoadDNSKeys(); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("v2 文件不应再触发迁移（幂等），实际回调 %d 次", n)
	}
}

// ── T68（规格 ⑥ 强化）：密钥丢失 / 不匹配 ⇒ **启动** fail-fast ──
//
// 旧版 T68 只断言"读取层报错"，并**显式断言 NewStore 必须成功**（第 140-143 行）⇒ 恰好把
// 规格 ⑥ 的反面固化为期望：密钥丢失后进程照常启动 ⇒ 写路径（SaveDNSKeys /
// TrackDNSKeyUsage / BumpDNSKeysVersion）会以**新密钥**原子覆盖 dns_keys.json
// ⇒ 唯一密文副本被销毁且不生成 .bak ⇒ 不可恢复。
// 现按规格 ⑥ 强化为**启动层**断言，并覆盖**三类**密文 + **两个正控**（防空判定）。

// t68WantRefuse 断言：必须拒绝启动，且文案含规格指定的恢复指引。
func t68WantRefuse(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s：`NewStore` 必须**拒绝启动**，实际成功返回（规格 ⑥）", what)
	}
	if !strings.Contains(err.Error(), "恢复 .storage_key 或从 .bak/快照恢复") {
		t.Errorf("%s：错误文案须含规格指定的恢复指引；实际: %v", what, err)
	}
}

func t68KeyPath(dir string) string { return filepath.Join(dir, ".storage_key") }

func TestT68a_CorruptCiphertextRefusesStartup(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveDNSKeys(map[string]*model.DNSKeyRecord{"k3": {Name: "k3", Provider: "alidns", AccessKeySecret: b1Secret}}); err != nil {
		t.Fatal(err)
	}
	// 读取层：损坏密文 ⇒ 报错且**不得**返回空集合（不降级、防空跑覆盖）
	p := filepath.Join(dir, "dns_keys.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]interface{}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env["ct"] = "AAAA" + "not-a-valid-ciphertext"
	nb, _ := json.MarshalIndent(env, "", "  ")
	if err := os.WriteFile(p, nb, 0o600); err != nil {
		t.Fatal(err)
	}
	// 读取层（**先清缓存**，否则会命中校验前写入的内存缓存 ⇒ 断言空真）
	st.ResetCaches()
	got, lerr := st.LoadDNSKeys()
	if lerr == nil {
		t.Fatalf("密文损坏 ⇒ 读取必须报错（不得降级为空集合）；实际返回 %d 条", len(got))
	}
	if got != nil {
		t.Errorf("失败时不得返回集合（防空跑覆盖）：%+v", got)
	}
	if _, verr := st.ValidateDNSKeysDecryptable(); verr == nil {
		t.Error("ValidateDNSKeysDecryptable 也必须报错（对现存密文真解一次）")
	}
	// 启动层 ⇒ 必须拒绝
	_, err = NewStore(dir)
	t68WantRefuse(t, "密文损坏", err)
}

// T68b = 规格 ⑥ 的**字面场景**：密钥文件丢失但已有密文 ⇒ 拒绝启动，且**不得留下"补生成"的
// 新密钥文件**（否则原密钥路径被新密钥占据，运维恢复时更易出错）。
func TestT68b_MissingKeyWithCiphertextRefusesStartup(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveDNSKeys(map[string]*model.DNSKeyRecord{"k1": {Name: "k1", Provider: "alidns", AccessKeySecret: b1Secret}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(t68KeyPath(dir)); err != nil { // 模拟"密钥丢失"
		t.Fatal(err)
	}
	_, err = NewStore(dir)
	t68WantRefuse(t, "密钥文件丢失但有 v2 密文", err)
	if _, statErr := os.Stat(t68KeyPath(dir)); statErr == nil {
		t.Error("拒绝启动时**不得**在磁盘上留下补生成的新 .storage_key（本路径必须对磁盘零副作用）")
	}
}

// T68c 正控：全新空目录 ⇒ 必须**正常生成**密钥（守卫不得误伤首次运行）。
func TestT68c_FreshDirGeneratesKey(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatalf("全新目录必须正常初始化（正控）：%v", err)
	}
	if st == nil {
		t.Fatal("store 为 nil")
	}
	fi, err := os.Stat(t68KeyPath(dir))
	if err != nil {
		t.Fatalf("首次运行应生成 .storage_key：%v", err)
	}
	if fi.Size() != 32 {
		t.Errorf(".storage_key 应为 32 字节，实际 %d", fi.Size())
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf(".storage_key 权限应为 0600，实际 %o", perm)
	}
}

// T68d 正控：仅有 v1 明文 dns_keys.json（无密文）⇒ 必须放行（不得阻断迁移路径）。
func TestT68d_V1PlaintextStillAllowedWithoutKey(t *testing.T) {
	dir := t.TempDir()
	b1WriteV1(t, dir, map[string]*model.DNSKeyRecord{"k9": {Name: "k9", Provider: "alidns", AccessKeySecret: b1Secret}})
	if _, err := os.Stat(t68KeyPath(dir)); !os.IsNotExist(err) {
		t.Fatal("前置：本用例应无 .storage_key")
	}
	if _, err := NewStore(dir); err != nil {
		t.Fatalf("v1 明文（无密文）必须放行以完成迁移（正控）：%v", err)
	}
}

// T68e 密钥被**替换**（文件存在但非原密钥）⇒ 同样必须拒绝启动（与"丢失"同危害）。
func TestT68e_ReplacedKeyRefusesStartup(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveDNSKeys(map[string]*model.DNSKeyRecord{"k2": {Name: "k2", Provider: "alidns", AccessKeySecret: b1Secret}}); err != nil {
		t.Fatal(err)
	}
	other := make([]byte, 32)
	for i := range other {
		other[i] = byte(i + 1)
	}
	if err := os.WriteFile(t68KeyPath(dir), other, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = NewStore(dir)
	t68WantRefuse(t, "密钥被替换为别的 32 字节密钥", err)
}

// T68f 覆盖第二类密文：仅 `certs/*/meta.json` 的 pfx_password_enc 存在 ⇒ 密钥缺失也必须拒绝。
func TestT68f_PFXEncRefusesOnMissingKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "certs", "b1"), 0o700); err != nil {
		t.Fatal(err)
	}
	meta := `{"domains":["a.example.com"],"pfx_password_enc":"QUJDREVGR0g="}`
	if err := os.WriteFile(filepath.Join(dir, "certs", "b1", "meta.json"), []byte(meta), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewStore(dir)
	t68WantRefuse(t, "仅 PFX 口令密文（无 dns_keys.json）", err)
}

// T68g 覆盖第三类密文：仅 `acme_config.json` 的账号私钥密文（非 PEM）⇒ 密钥缺失也必须拒绝。
func TestT68g_ACMECiphertextRefusesOnMissingKey(t *testing.T) {
	dir := t.TempDir()
	acme := `[{"email":"a@b.c","ca":"letsencrypt","account_key":"QUJDREVGR0g="}]`
	if err := os.WriteFile(filepath.Join(dir, "acme_config.json"), []byte(acme), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewStore(dir)
	t68WantRefuse(t, "仅 ACME 账号私钥密文（无 dns_keys.json）", err)
}

func TestT69_ValidateDNSKeysDecryptable(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// absent
	if got, err := st.ValidateDNSKeysDecryptable(); err != nil || got != "absent" {
		t.Errorf("无文件应返回 absent，实际 %q err=%v", got, err)
	}
	// v1 明文
	b1WriteV1(t, dir, map[string]*model.DNSKeyRecord{"k": {Name: "k", Provider: "alidns"}})
	st1, _ := NewStore(dir)
	if got, err := st1.ValidateDNSKeysDecryptable(); err != nil || got != "v1-plaintext" {
		t.Errorf("v1 应返回 v1-plaintext，实际 %q err=%v", got, err)
	}
	// v2 ok（真解一次）
	if err := st1.SaveDNSKeys(map[string]*model.DNSKeyRecord{"k": {Name: "k", Provider: "alidns", AccessKeySecret: b1Secret}}); err != nil {
		t.Fatal(err)
	}
	st2, _ := NewStore(dir)
	if got, err := st2.ValidateDNSKeysDecryptable(); err != nil || got != "v2-ok" {
		t.Errorf("v2 应返回 v2-ok（真解成功），实际 %q err=%v", got, err)
	}
	// 结构非法（解密成功但 JSON 非法）——通过换 purpose 模拟密钥不匹配
	st3, _ := NewStore(dir)
	st3.storageKey = []byte("00000000000000000000000000000000")
	if _, err := st3.ValidateDNSKeysDecryptable(); err == nil {
		t.Errorf("密钥不匹配必须报错（不得静默当作空集）")
	}
}
