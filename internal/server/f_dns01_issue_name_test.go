package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ocoj/ddns-manager/internal/store"
)

// TestT76a_IssueBundleNameNormalization —— F-DNS01-1 回归守卫（命名规范化）。
//
// 缺陷：首发路径用 `!strings.HasPrefix(certName, "acme-")` 当"签发目录≠bundle 目录"的代理判据，
// 当**域名自身以 `acme-` 开头**时四道守卫全部误判跳过，并产出双前缀 `acme-acme-…`。
func TestT76a_IssueBundleNameNormalization(t *testing.T) {
	cases := []struct{ in, want string }{
		{"sp.lanxun.pro", "acme-sp.lanxun.pro"},                  // 普通域名 ⇒ 加前缀
		{"acme-t73dns-1.lanxun.pro", "acme-t73dns-1.lanxun.pro"}, // acme- 开头 ⇒ **不得二次加前缀**
		{"acme-oof.noxen.pro", "acme-oof.noxen.pro"},             // 同上（生产既有形态）
		{"*.lanxun.pro", "acme-*.lanxun.pro"},                    // 通配符
	}
	for _, c := range cases {
		if got := issueBundleName(c.in); got != c.want {
			t.Errorf("issueBundleName(%q) = %q；期望 %q", c.in, got, c.want)
		}
	}
}

// TestT76b_DnsKeyPreservedWhenIssuanceDirIsBundleDir —— F-DNS01-1 核心机制回归。
//
// 场景：域名以 `acme-` 开头 ⇒ 签发目录 == bundle 目录（`certs/<域名>/`），
// 此时 `issueViaAcmeSh` 已把 `dns_key`/`provider` 写在该目录的 meta.json 里，
// `SaveCertBundle` 的"非受管键原样保留"机制**必须**把它们保留下来。
// 修复前：bundle 名被二次加前缀 ⇒ 目标是另一个空目录 ⇒ extra 无从保留 ⇒ `dns_key` 丢失。
func TestT76b_DnsKeyPreservedWhenIssuanceDirIsBundleDir(t *testing.T) {
	dir := t.TempDir()
	st, err := store.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	name := issueBundleName("acme-t73dns-x.lanxun.pro") // 即 "acme-t73dns-x.lanxun.pro"
	bdir := filepath.Join(dir, "certs", name)
	if err := os.MkdirAll(bdir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// 模拟 issueViaAcmeSh 写下的签发 meta（含 dns_key / provider 等非受管键）
	issueMeta := map[string]interface{}{
		"acme":     map[string]interface{}{"ca": "Let's Encrypt", "key_type": "ec-256"},
		"dns_key":  "阿里-蓝迅",
		"provider": "alidns",
		"key_type": "ec-256",
		"x-custom": "keep-me",
	}
	raw, _ := json.MarshalIndent(issueMeta, "", "  ")
	if err := os.WriteFile(filepath.Join(bdir, "meta.json"), raw, 0o600); err != nil {
		t.Fatalf("写签发 meta: %v", err)
	}

	b := &store.CertBundle{
		Name: name, Domains: []string{"acme-t73dns-x.lanxun.pro"},
		Files: map[string][]byte{"fullchain.pem": []byte("CERT"), "privkey.pem": []byte("KEY")},
		Hash:  "sha256:test",
	}
	if err := st.SaveCertBundle(b); err != nil {
		t.Fatalf("SaveCertBundle: %v", err)
	}
	meta, err := st.LoadCertMeta(name)
	if err != nil {
		t.Fatalf("LoadCertMeta: %v", err)
	}
	for _, k := range []string{"dns_key", "provider", "acme", "x-custom"} {
		if _, ok := meta[k]; !ok {
			t.Errorf("meta 丢失非受管键 %q（F-DNS01-1 回归）：meta=%v", k, meta)
		}
	}
	if got, _ := meta["dns_key"].(string); got != "阿里-蓝迅" {
		t.Errorf("meta.dns_key = %q；期望 %q（续期将退化为按 provider 猜 Key）", got, "阿里-蓝迅")
	}
	// 反向控制：受管键由 struct 权威提供（domains 必须来自 struct 而非旧 meta）
	if ds, ok := meta["domains"].([]interface{}); !ok || len(ds) != 1 {
		t.Errorf("meta.domains 应为 struct 提供的 1 个域名，实得 %v", meta["domains"])
	}
}
