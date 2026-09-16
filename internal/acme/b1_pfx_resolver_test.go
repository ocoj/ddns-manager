package acme

// v1.6.73 B-1 Slice 3b：acme 侧 PFX 口令解析器的语义与失败路径。
//
//	T71f 取值优先级：resolver ⇒ 明文（v1 兼容）⇒ 默认；**resolver 报错必须冒泡**（绝不回落默认）
//	T71g UpdateCertMeta 在 resolver 报错时**跳过 PFX 重建**（保留既有 PFX、不写默认口令）；
//	     正常时用解出的口令重建，且产物**不得**可用默认口令解开
//
// 判别性注入 ⑧（server.attachDNSKeyLookup 内不接线 SetPFXPasswordResolver）会让 T71c
// 失败；T71g 的第二段（正例）则是 acme 包内对该路径的独立断言。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	mycrypto "github.com/ocoj/ddns-manager/internal/crypto"
)

func TestT71f_ResolvePFXPasswordPrecedence(t *testing.T) {
	m, err := New(t.TempDir(), "t@example.com", ":80")
	if err != nil {
		t.Fatal(err)
	}
	if m.PFXPasswordResolverConfigured() {
		t.Fatal("前置条件：新建 Manager 的 resolver 应为未接线")
	}

	// 未接线：明文兼容读（v1 遗留 meta）
	if pw, err := m.resolvePFXPassword(map[string]interface{}{"pfx_password": "plain-pw"}); err != nil || pw != "plain-pw" {
		t.Errorf("未接线时应可读明文 pfx_password，实际 pw=%q err=%v", pw, err)
	}
	// 未接线：无任何口令键 ⇒ 默认
	if pw, err := m.resolvePFXPassword(map[string]interface{}{}); err != nil || pw != mycrypto.DefaultPFXPassword {
		t.Errorf("未接线且无口令键时应回落默认，实际 pw=%q err=%v", pw, err)
	}

	// 接线后：resolver 优先（密文才是权威；明文键不得抢先）
	m.SetPFXPasswordResolver(func(meta map[string]interface{}) (string, error) {
		return "resolved-pw", nil
	})
	if !m.PFXPasswordResolverConfigured() {
		t.Error("SetPFXPasswordResolver 后 Configured 应为 true")
	}
	if pw, err := m.resolvePFXPassword(map[string]interface{}{"pfx_password": "plain-pw"}); err != nil || pw != "resolved-pw" {
		t.Errorf("接线后应以 resolver 为准，实际 pw=%q err=%v", pw, err)
	}

	// resolver 报错 ⇒ 必须冒泡（绝不静默回落默认口令）
	m.SetPFXPasswordResolver(func(meta map[string]interface{}) (string, error) {
		return "", fmt.Errorf("密文不可解")
	})
	if pw, err := m.resolvePFXPassword(map[string]interface{}{}); err == nil {
		t.Errorf("resolver 报错必须返回错误（否则会用错口令），实际 pw=%q err=nil", pw)
	}

	// 恢复未接线后仍走明文/默认退路（证明接线可撤销、退路未坏）
	m.SetPFXPasswordResolver(nil)
	if pw, err := m.resolvePFXPassword(map[string]interface{}{"pfx_password": "plain-pw"}); err != nil || pw != "plain-pw" {
		t.Errorf("撤销接线后应回到明文兼容读，实际 pw=%q err=%v", pw, err)
	}
}

// b1AcmeCertDir builds the acme.sh-side certificate directory layout that
// UpdateCertMeta consumes: PEMs, a stale PFX encrypted with the *default* password
// (so a wrong-password rebuild would look like a success unless we check the
// password actually used), and an acme-side meta.json without any password key.
func b1AcmeCertDir(t *testing.T, root, certName, cn string) string {
	t.Helper()
	certDir := filepath.Join(root, "certs", certName)
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := selfSigned(t, cn)

	stalePFX, err := mycrypto.GeneratePFX(certPEM, keyPEM, mycrypto.DefaultPFXPassword)
	if err != nil {
		t.Fatal(err)
	}
	w := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(certDir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w("fullchain.pem", certPEM)
	w("cert.pem", certPEM)
	w("privkey.pem", keyPEM)
	w("cert.pfx", stalePFX)
	mjs, _ := json.Marshal(map[string]interface{}{"acme": true, "domains": []string{cn}})
	w("meta.json", mjs)
	return certDir
}

func TestT71g_UpdateCertMetaSkipsRebuildWhenResolverFails(t *testing.T) {
	root := t.TempDir()
	certDir := b1AcmeCertDir(t, root, "rp", "rp.example.com")

	// Manager bundle 目录（root/certs/acme-rp）——UpdateCertMeta 的口令权威来源
	bundleDir := filepath.Join(root, "certs", "acme-rp")
	if err := os.MkdirAll(bundleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bms, _ := json.Marshal(map[string]interface{}{"acme": true, "pfx_password_enc": "ciphertext-not-decryptable"})
	if err := os.WriteFile(filepath.Join(bundleDir, "meta.json"), bms, 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := New(filepath.Join(root, "certs"), "t@example.com", ":80")
	if err != nil {
		t.Fatal(err)
	}
	// 注入：解析失败（等价于 .storage_key 不符 / 密文损坏）
	m.SetPFXPasswordResolver(func(meta map[string]interface{}) (string, error) {
		if _, ok := meta["pfx_password_enc"]; ok {
			return "", fmt.Errorf("注入：密文不可解")
		}
		return mycrypto.DefaultPFXPassword, nil
	})

	before, err := os.ReadFile(filepath.Join(certDir, "cert.pfx"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateCertMeta(certDir); err != nil {
		t.Fatalf("解析失败不应让 UpdateCertMeta 整体失败，实际 %v", err)
	}
	after, err := os.ReadFile(filepath.Join(certDir, "cert.pfx"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("解析失败时必须**跳过** PFX 重建（保留既有 PFX，绝不用默认口令重写）")
	}
	if _, _, err := mycrypto.ParsePFXLeafChain(after, mycrypto.DefaultPFXPassword); err != nil {
		t.Errorf("既有 PFX 应保持可用默认口令解开（未被改动），实际 %v", err)
	}

	// 正例：解析成功 ⇒ 用解出的口令重建，且产物不得可用默认口令解开
	const customPw = "custom-pw-3b-acme"
	m.SetPFXPasswordResolver(func(meta map[string]interface{}) (string, error) {
		return customPw, nil
	})
	if err := m.UpdateCertMeta(certDir); err != nil {
		t.Fatalf("UpdateCertMeta: %v", err)
	}
	for _, fn := range []string{"cert.pfx", "cert-modern.pfx"} {
		data, err := os.ReadFile(filepath.Join(certDir, fn))
		if err != nil {
			t.Fatalf("读 %s: %v", fn, err)
		}
		leaf, _, err := mycrypto.ParsePFXLeafChain(data, customPw)
		if err != nil || leaf == nil {
			t.Errorf("③ %s 应以解析出的口令 %q 可解，err=%v", fn, customPw, err)
			continue
		}
		if _, _, err := mycrypto.ParsePFXLeafChain(data, mycrypto.DefaultPFXPassword); err == nil {
			t.Errorf("③ %s 不得可用默认口令解开 ⇒ 说明重建时用了默认口令", fn)
		}
	}
}
