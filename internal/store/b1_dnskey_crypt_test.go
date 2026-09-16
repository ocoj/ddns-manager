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

func TestT68_CorruptCiphertextFailsFast(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]*model.DNSKeyRecord{"k3": {Name: "k3", Provider: "alidns", AccessKeySecret: b1Secret}}
	if err := st.SaveDNSKeys(keys); err != nil {
		t.Fatal(err)
	}
	// 篡改密文
	p := filepath.Join(dir, "dns_keys.json")
	raw, _ := os.ReadFile(p)
	bad := strings.Replace(string(raw), "AA", "AA", 1)
	var env map[string]interface{}
	_ = json.Unmarshal([]byte(bad), &env)
	env["ct"] = "AAAA" + "not-a-valid-ciphertext"
	nb, _ := json.MarshalIndent(env, "", "  ")
	if err := os.WriteFile(p, nb, 0o600); err != nil {
		t.Fatal(err)
	}
	st2, err := NewStore(dir) // 新实例 ⇒ 无缓存
	if err != nil {
		t.Fatal(err)
	}
	got, err := st2.LoadDNSKeys()
	if err == nil {
		t.Fatalf("密文损坏**必须报错 fail-fast**（不得降级为空集合）；实际返回 %d 条", len(got))
	}
	if got != nil {
		t.Errorf("失败时不得返回集合（防空跑覆盖）：%+v", got)
	}
	if _, verr := st2.ValidateDNSKeysDecryptable(); verr == nil {
		t.Errorf("preflight 校验也必须报错")
	}
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
