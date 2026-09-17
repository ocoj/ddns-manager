package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeLegacyMeta 造一个"旧版"meta：明文口令 + 0644（模拟 v1.6.72 及更早的落盘形态）
func writeLegacyMeta(t *testing.T, dir, name, pw string) string {
	t.Helper()
	d := filepath.Join(dir, "certs", name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	p := filepath.Join(d, "meta.json")
	b, err := json.MarshalIndent(map[string]interface{}{
		"domains": []string{"x.example.com"}, "dns_key": "k1", "pfx_password": pw,
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// T78a：急切迁移把明文转为密文，且口令值可原样取回、权限收敛 0600
func TestT78a_EagerMigrationConvertsPlaintext(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	p := writeLegacyMeta(t, dir, "acme-x.example.com", "USER-CUSTOM-PW")

	n, fails, err := st.MigratePlaintextPFXPasswords()
	if err != nil || len(fails) != 0 {
		t.Fatalf("migrate: err=%v fails=%v", err, fails)
	}
	if n != 1 {
		t.Fatalf("converted = %d；期望 1", n)
	}
	raw, _ := os.ReadFile(p)
	m := map[string]interface{}{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pw, _ := m["pfx_password"].(string); pw != "" {
		t.Errorf("明文未清空: %q", pw)
	}
	if _, ok := m[PFXPasswordEncKey].(string); !ok {
		t.Errorf("密文键 %s 缺失", PFXPasswordEncKey)
	}
	// 口令值必须可原样取回（不重建 PFX、不改口令）
	if got, err := st.MetaPFXPassword(m); err != nil || got != "USER-CUSTOM-PW" {
		t.Errorf("MetaPFXPassword = %q, %v；期望 USER-CUSTOM-PW", got, err)
	}
	// 权限收敛 0600
	if fi, err := os.Stat(p); err != nil {
		t.Fatalf("stat: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("权限 = %o；期望 600", fi.Mode().Perm())
	}
	// 其他字段不得被改动
	if m["dns_key"] != "k1" {
		t.Errorf("dns_key 被改动: %v", m["dns_key"])
	}
	// 残留临时文件检查
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".meta-*.tmp")); len(left) != 0 {
		t.Errorf("残留临时文件: %v", left)
	}
}

// T78b：幂等 —— 重复执行不产生任何变化
func TestT78b_EagerMigrationIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	p := writeLegacyMeta(t, dir, "acme-y.example.com", "PW-A")
	if n, _, err := st.MigratePlaintextPFXPasswords(); err != nil || n != 1 {
		t.Fatalf("首次: n=%d err=%v", n, err)
	}
	first, _ := os.ReadFile(p)
	n2, fails, err := st.MigratePlaintextPFXPasswords()
	if err != nil || len(fails) != 0 || n2 != 0 {
		t.Fatalf("二次: n=%d fails=%v err=%v；期望 0", n2, fails, err)
	}
	second, _ := os.ReadFile(p)
	if string(first) != string(second) {
		t.Errorf("二次执行改动了文件内容")
	}
}

// T78c：无明文的 meta 一律不动（内容 + 权限 + mtime 都不变）
func TestT78c_EagerMigrationSkipsMetasWithoutPlaintext(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	d := filepath.Join(dir, "certs", "acme-z.example.com")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	p := filepath.Join(d, "meta.json")
	body := []byte(`{"domains":["z.example.com"],"pfx_password":""}`)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	before, _ := os.Stat(p)

	n, fails, err := st.MigratePlaintextPFXPasswords()
	if err != nil || len(fails) != 0 || n != 0 {
		t.Fatalf("n=%d fails=%v err=%v；期望 0/无失败", n, fails, err)
	}
	after, _ := os.Stat(p)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("mtime 被改动（应完全跳过）")
	}
	if got, _ := os.ReadFile(p); string(got) != string(body) {
		t.Errorf("内容被改动: %s", got)
	}
	if after.Mode().Perm() != 0o644 {
		t.Errorf("权限被改动: %o（跳过时不应改权限）", after.Mode().Perm())
	}
}

// T78d：目录无 meta.json ⇒ 不视为失败
func TestT78d_EagerMigrationToleratesMissingMeta(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "certs", "empty.example.com"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	n, fails, err := st.MigratePlaintextPFXPasswords()
	if err != nil || len(fails) != 0 || n != 0 {
		t.Fatalf("n=%d fails=%v err=%v；期望 0/无失败", n, fails, err)
	}
}

// T78e：无 certs/ 目录（全新实例）⇒ 直接返回，不报错
func TestT78e_EagerMigrationOnFreshInstance(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if n, fails, err := st.MigratePlaintextPFXPasswords(); err != nil || n != 0 || len(fails) != 0 {
		t.Fatalf("n=%d fails=%v err=%v", n, fails, err)
	}
}
