package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// T11: the migration script's premise — fields written into meta.json by an
// external tool (notably dns_key) must survive a SaveCertBundle round-trip.
// SaveCertBundle only models a fixed set of keys in the struct, so extra fields
// are preserved through a structKeys whitelist; if that ever regressed, the
// migration would appear to succeed and then silently lose dns_key on the next
// renewal, re-breaking credential resolution.
func TestLoadCertMeta_ExtraFieldsSurviveSaveCertBundle(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	bd := filepath.Join(dir, "certs", "acme-x")
	if err := os.MkdirAll(bd, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"fullchain.pem": "chain", "cert.pem": "leaf", "privkey.pem": "key",
	} {
		if err := os.WriteFile(filepath.Join(bd, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	const weirdKey = `怪"名\号`
	meta := map[string]interface{}{
		"acme": true, "provider": "alidns", "domains": []string{"x.example.com"},
		"ca": "Let's Encrypt", "pfx_password": "pw", "dns_key": weirdKey,
	}
	mb, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(bd, "meta.json"), mb, 0o600); err != nil {
		t.Fatal(err)
	}

	b, err := st.LoadCertBundle("acme-x")
	if err != nil {
		t.Fatalf("LoadCertBundle: %v", err)
	}
	b.Files["cert.pfx"] = []byte("pfx-bytes")
	// SaveCertBundle updates b.Hash in place, so capture the pre-save value first.
	oldHash := b.Hash
	if err := st.SaveCertBundle(b); err != nil {
		t.Fatalf("SaveCertBundle: %v", err)
	}

	got, err := st.LoadCertMeta("acme-x")
	if err != nil {
		t.Fatalf("LoadCertMeta: %v", err)
	}
	if got["dns_key"] != weirdKey {
		t.Errorf("dns_key lost across SaveCertBundle: got %v", got["dns_key"])
	}
	if got["acme"] != true {
		t.Error("acme flag lost")
	}
	// v1.6.73 B-1（**语义变更**，取代旧断言「明文 pfx_password 必须留存」）：
	// 口令属受管键 ⇒ 落盘一律置空且不得回填；值改由 pfx_password_enc 承载，经单一取值入口解回。
	if pw, _ := got["pfx_password"].(string); pw != "" {
		t.Errorf("pfx_password 明文不得留存在盘上（B-1 落盘脱敏），实际 %q", pw)
	}
	if _, ok := got[PFXPasswordEncKey]; !ok {
		t.Errorf("meta.json 必须含 %s（密文承载口令），keys=%v", PFXPasswordEncKey, got)
	}
	if pw, err := st.BundlePFXPassword(&CertBundle{Name: "acme-x"}); err != nil || pw != "pw" {
		t.Errorf("口令应经单一取值入口解回 pw，实际 %q err=%v", pw, err)
	}
	if got["ca"] != "Let's Encrypt" {
		t.Error("ca lost")
	}

	// The hash must cover the updated file set (otherwise pushes would be missed).
	b2, err := st.LoadCertBundle("acme-x")
	if err != nil {
		t.Fatal(err)
	}
	if b2.Hash == "" || b2.Hash == oldHash {
		t.Errorf("hash should be recomputed over the new file set (got %q, was %q)", b2.Hash, oldHash)
	}
}

// LoadCertMeta must reject a path-traversal bundle name, like LoadCertBundle does.
func TestLoadCertMeta_RejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.LoadCertMeta("../escape"); err == nil {
		t.Error("LoadCertMeta must reject traversal in the bundle name")
	}
}
