package store

// v1.6.73 B-1（Slice 3a，T70d/T70e）：证书 meta 的口令**落盘脱敏**。
//
//   T70d SaveCertBundle 传明文口令 ⇒ ① meta.json **不得含明文** ② 必含 pfx_password_enc（密文）
//        ③ 经单一取值入口可解回原口令 ④ **调用方内存结构不被修改**（b.PFXPassword 保持原值）
//   T70e 后续 Save（口令为空）⇒ 既有 pfx_password_enc 必须**原样保留**（非受管键语义）

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func b1ReadMetaRaw(t *testing.T, dir, name string) (map[string]interface{}, string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "certs", name, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m, string(b)
}

func TestT70d_PFXPasswordSanitizedOnDisk(t *testing.T) {
	const pw = "pw-3a-SECRET-7c1f"
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	b := &CertBundle{
		Name:        "acme-3a",
		Domains:     []string{"a.example.com"},
		PFXPassword: pw,
		Files:       map[string][]byte{"fullchain.pem": []byte("c"), "privkey.pem": []byte("k")},
	}
	if err := st.SaveCertBundle(b); err != nil {
		t.Fatal(err)
	}
	// ④ 调用方内存不被修改
	if b.PFXPassword != pw {
		t.Errorf("调用方结构不得被就地修改（内存明文应保留），实际 %q", b.PFXPassword)
	}
	meta, raw := b1ReadMetaRaw(t, dir, "acme-3a")
	if s, ok := meta["pfx_password"].(string); ok && s != "" {
		t.Errorf("meta.json 的 pfx_password 必须为空/缺失（**判键不判文本**），实际 %q", s)
	}
	if raw == "" || strings.Contains(raw, pw) {
		t.Errorf("meta.json 全文**不得**出现明文口令")
	}
	if _, ok := meta[PFXPasswordEncKey]; !ok {
		t.Errorf("meta.json 必须含 %s（密文），keys=%v", PFXPasswordEncKey, keysOf(meta))
	}
	// ③ 单一入口可解回
	env2 := &CertBundle{Name: "acme-3a"} // 空口令 ⇒ 走 meta 解密路径
	got, err := st.BundlePFXPassword(env2)
	if err != nil {
		t.Fatalf("BundlePFXPassword: %v", err)
	}
	if got != pw {
		t.Errorf("应经 enc 解回原口令，实际 %q", got)
	}
}

func TestT70e_ExistingEncPreservedOnLaterSave(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveCertBundle(&CertBundle{Name: "acme-3b", PFXPassword: "pw-keep"}); err != nil {
		t.Fatal(err)
	}
	first, _ := b1ReadMetaRaw(t, dir, "acme-3b")
	enc1, _ := first[PFXPasswordEncKey].(string)
	if enc1 == "" {
		t.Fatal("首写应产生 enc")
	}
	// 后续 Save 不带口令（如一致性自愈重建 PFX 后）
	if err := st.SaveCertBundle(&CertBundle{Name: "acme-3b", Domains: []string{"b.example.com"}}); err != nil {
		t.Fatal(err)
	}
	second, raw2 := b1ReadMetaRaw(t, dir, "acme-3b")
	if _, ok := second[PFXPasswordEncKey]; !ok {
		t.Errorf("既有 enc 必须原样保留（非受管键语义）；raw=%s", raw2)
	}
	if s, _ := second["pfx_password"].(string); s != "" {
		t.Errorf("后续 Save 不得回填明文口令，实际 %q", s)
	}
}
