package store

// v1.6.73 B-3（T61–T64）：受管键/非受管键口径与「合并顺序即不变量」的回归守卫。
//
//   T61 非受管键经 Load→Save **原样保留**（回归守卫：防将来改回加法白名单）
//   T62 per-bundle 隔离（A 的未知键不得出现在 B）
//   T63 **受管键冲突**：旧 meta 的 domains 与 struct 不一致 ⇒ 落盘以 struct 为准 + 1 条冲突上报
//   T64 同上（target_path）：证明冲突检测覆盖**全部受管键**，而非只针对 domains

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func b3Bundle(t *testing.T, dir, name string, meta map[string]interface{}) {
	t.Helper()
	bd := filepath.Join(dir, "certs", name)
	if err := os.MkdirAll(bd, 0o700); err != nil {
		t.Fatal(err)
	}
	for n, c := range map[string]string{"fullchain.pem": "chain", "cert.pem": "leaf", "privkey.pem": "key"} {
		if err := os.WriteFile(filepath.Join(bd, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if meta != nil {
		b, _ := json.MarshalIndent(meta, "", "  ")
		if err := os.WriteFile(filepath.Join(bd, "meta.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func b3Load(t *testing.T, st *ManagerStore, name string) map[string]interface{} {
	t.Helper()
	m, err := st.LoadCertMeta(name)
	if err != nil {
		t.Fatalf("LoadCertMeta(%s): %v", name, err)
	}
	return m
}

func TestT61_NonManagedKeysSurviveSave(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	b3Bundle(t, dir, "acme-t61", map[string]interface{}{
		"acme": true, "ca": "TestCA", "key_type": "EC256", "dns_key": "K",
		"x-foo": "1", "custom_key": "2",
	})
	if err := st.SaveCertBundle(&CertBundle{Name: "acme-t61", Domains: []string{"t61.example.com"}}); err != nil {
		t.Fatal(err)
	}
	got := b3Load(t, st, "acme-t61")
	for _, k := range []string{"acme", "ca", "key_type", "dns_key", "x-foo", "custom_key"} {
		if _, ok := got[k]; !ok {
			t.Errorf("非受管键 %q 必须在 Load→Save 后保留（回归守卫）；实际 meta=%v", k, got)
		}
	}
	if ds, _ := got["domains"].([]interface{}); len(ds) != 1 || ds[0] != "t61.example.com" {
		t.Errorf("受管键 domains 必须以 struct 为准，实际 %v", got["domains"])
	}
}

func TestT62_PerBundleIsolation(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	b3Bundle(t, dir, "acme-t62a", map[string]interface{}{"x-a": "A"})
	b3Bundle(t, dir, "acme-t62b", map[string]interface{}{"x-b": "B"})
	for _, n := range []string{"acme-t62a", "acme-t62b"} {
		if err := st.SaveCertBundle(&CertBundle{Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	a, b := b3Load(t, st, "acme-t62a"), b3Load(t, st, "acme-t62b")
	if _, ok := a["x-a"]; !ok {
		t.Errorf("A 应保留自己的未知键 x-a：%v", a)
	}
	if _, ok := a["x-b"]; ok {
		t.Errorf("A 不得出现 B 的未知键 x-b（per-bundle 隔离被破坏）：%v", a)
	}
	if _, ok := b["x-b"]; !ok {
		t.Errorf("B 应保留自己的未知键 x-b：%v", b)
	}
}

func TestT63_ManagedKeyConflict_StructWins(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	var reported []string
	st.SetCertMetaConflictReporter(func(bundle, key string) { reported = append(reported, bundle+"/"+key) })
	b3Bundle(t, dir, "acme-t63", map[string]interface{}{"domains": []string{"stale.example.com"}})

	if err := st.SaveCertBundle(&CertBundle{Name: "acme-t63", Domains: []string{"new.example.com"}}); err != nil {
		t.Fatal(err)
	}
	got := b3Load(t, st, "acme-t63")
	ds, _ := got["domains"].([]interface{})
	if len(ds) != 1 || ds[0] != "new.example.com" {
		t.Fatalf("受管键 domains 必须以 struct 权威值覆盖旧 meta（否则 F7 回归）；实际 %v", got["domains"])
	}
	if len(reported) != 1 || reported[0] != "acme-t63/domains" {
		t.Errorf("应恰好上报 1 条冲突（acme-t63/domains），实际 %v", reported)
	}
}

func TestT64_ManagedConflictCoversAllManagedKeys(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	var reported []string
	st.SetCertMetaConflictReporter(func(bundle, key string) { reported = append(reported, key) })
	b3Bundle(t, dir, "acme-t64", map[string]interface{}{
		"target_path": "/old", "hash": "deadbeef",
	})
	if err := st.SaveCertBundle(&CertBundle{Name: "acme-t64", TargetPath: "/new"}); err != nil {
		t.Fatal(err)
	}
	got := b3Load(t, st, "acme-t64")
	if got["target_path"] != "/new" {
		t.Errorf("target_path 必须以 struct 为准，实际 %v", got["target_path"])
	}
	found := false
	for _, k := range reported {
		if k == "target_path" {
			found = true
		}
	}
	if !found {
		t.Errorf("冲突检测必须覆盖 target_path（全部受管键），实际上报 %v", reported)
	}
}
