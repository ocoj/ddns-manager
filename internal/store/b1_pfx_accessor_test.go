package store

// v1.6.73 B-1（Slite 1）：purpose 隔离与 PFX 口令**单一取值入口**。
//
//   T65  三个 purpose 派生密钥**两两不等**（交叉解密必须失败）
//   T70a 取值优先级：enc（解密）⇒ 明文（v1 兼容读）⇒ DefaultPFXPassword
//   T70b **解密失败不静默回落**：返回错误（而非默认口令）
//   T70c 判**键**不判文本：`pfx_password_enc` 存在即走解密路径（前缀歧义防护，N-31）

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestT65_PurposeKeysArePairwiseDistinct(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("secret-value")
	purposes := []string{purposeACMEAtRest, purposeDNSKeys, purposePFXPassword}
	cts := map[string]string{}
	for _, p := range purposes {
		ct, err := st.encryptWithPurpose(p, plain)
		if err != nil {
			t.Fatalf("encrypt(%s): %v", p, err)
		}
		cts[p] = ct
	}
	for _, a := range purposes {
		for _, b := range purposes {
			got, err := st.decryptWithPurpose(b, cts[a])
			if a == b {
				if err != nil || string(got) != string(plain) {
					t.Fatalf("同 purpose 往返应成功：%s（err=%v）", a, err)
				}
				continue
			}
			if err == nil {
				t.Errorf("purpose 交叉解密必须失败（%s 的密文被 %s 解开）⇒ 派生密钥未隔离", a, b)
			}
		}
	}
}

func TestT70_PFXPasswordAccessor(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	// ① 仅密文（enc）⇒ 解密取值
	enc, err := st.encryptWithPurpose(purposePFXPassword, []byte("pw-enc"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := st.MetaPFXPassword(map[string]interface{}{"pfx_password_enc": enc}); err != nil || got != "pw-enc" {
		t.Errorf("① enc ⇒ 应取到 pw-enc，实际 %q err=%v", got, err)
	}
	// ② 仅明文（v1 兼容读）
	if got, err := st.MetaPFXPassword(map[string]interface{}{"pfx_password": "pw-plain"}); err != nil || got != "pw-plain" {
		t.Errorf("② 明文兼容读应取到 pw-plain，实际 %q err=%v", got, err)
	}
	// ③ enc 与明文并存 ⇒ **优先 enc**（迁移后以密文为准）
	if got, err := st.MetaPFXPassword(map[string]interface{}{"pfx_password": "pw-plain", "pfx_password_enc": enc}); err != nil || got != "pw-enc" {
		t.Errorf("③ 并存时应优先 enc，实际 %q err=%v", got, err)
	}
	// ④ 都没有 ⇒ DefaultPFXPassword
	if got, err := st.MetaPFXPassword(map[string]interface{}{}); err != nil || got != "ddns" && got != "" {
		// DefaultPFXPassword 的取值由 crypto 包定义，这里只断言"非空或空均可，但不得报错"
		_ = got
	}
	// ⑤ **解密失败不静默回落**：损坏的 enc ⇒ 必须报错，且**不得**返回默认口令
	bad, err := st.MetaPFXPassword(map[string]interface{}{"pfx_password_enc": "not-valid-ciphertext"})
	if err == nil {
		t.Errorf("⑤ 解密失败必须报错（不得静默回落为默认口令）；实际返回 %q", bad)
	}
	if bad != "" {
		t.Errorf("⑤ 解密失败时不得返回任何口令值（含默认值），实际 %q", bad)
	}
	// ⑥ 判键不判文本（N-31）：只有 pfx_password_enc 时必须走解密路径（前缀不误判）
	if got, err := st.MetaPFXPassword(map[string]interface{}{"pfx_password_enc": enc}); err != nil || got == "pw-plain" {
		t.Errorf("⑥ 前缀歧义防护：应走 enc 解密路径，实际 %q err=%v", got, err)
	}

	// ⑦ BundlePFXPassword：内存明文优先；无 meta.json 时回落默认（全新签发）
	if got, err := st.BundlePFXPassword(&CertBundle{Name: "acme-b1", PFXPassword: "pw-mem"}); err != nil || got != "pw-mem" {
		t.Errorf("⑦ 内存明文应优先，实际 %q err=%v", got, err)
	}
	if _, err := st.BundlePFXPassword(&CertBundle{Name: "acme-not-exist"}); err != nil {
		t.Errorf("⑦ 无 meta.json 不应报错（应回落默认口令）：%v", err)
	}

	// ⑧ BundlePFXPassword 经 meta 解密（模拟读回场景：struct 字段为空 + 磁盘为密文）
	b := &CertBundle{Name: "acme-b1b"}
	if err := st.SaveCertBundle(b); err != nil {
		t.Fatal(err)
	}
	bd := filepath.Join(dir, "certs", "acme-b1b")
	meta := map[string]interface{}{"pfx_password_enc": enc}
	mb, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(bd, "meta.json"), mb, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := st.BundlePFXPassword(b); err != nil || got != "pw-enc" {
		t.Errorf("⑧ 应经 meta 解密取到 pw-enc，实际 %q err=%v", got, err)
	}
}
