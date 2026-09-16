package server

// v1.6.73 B-1 Slice 3b：闭合 Slice 3a 引出的「落盘明文口令消失、读取点未跟上」回归。
//
// 5 个读取点逐点独立断言（N-29）：
//
//	T71a ① internal/server/handlers_nodes.go 心跳推送（resp.CertUpdates[].PFXPassword）
//	T71b ② internal/server/cert_consistency.go 一致性判定（candidatePFXPasswords）
//	T71c ③ internal/acme/acme.go UpdateCertMeta 双 PFX 重建（经 attachDNSKeyLookup 接线）
//	T71d ⑤ internal/server/handlers_certs.go detail 接口（UI 契约：值必须仍然正确）
//	T71e 重建写回点（rebuildBundlePFX）不得以默认口令覆盖用户自定义口令
//
// 判别性注入（见实现报告）：
//
//	⑦ 去掉 store.MetaPFXPassword / BundlePFXPassword 的解密分支 ⇒ ① ② ③ ⑤ 全部 FAIL
//	⑧ attachDNSKeyLookup 内不接线 SetPFXPasswordResolver ⇒ ③ FAIL（T71c 接线断言先触发）

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"

	"github.com/ocoj/ddns-manager/internal/acme"
	srvcfg "github.com/ocoj/ddns-manager/internal/config"
	mycrypto "github.com/ocoj/ddns-manager/internal/crypto"
	"github.com/ocoj/ddns-manager/internal/model"
	"github.com/ocoj/ddns-manager/internal/store"
)

// wireB1Resolver runs the one-shot startup audit — the production wiring point of
// pfxPasswordResolverFn (server.New → startupAudit) — and restores the
// package-level hook afterwards, so one test cannot leak wiring into the next.
func wireB1Resolver(t *testing.T, s *Server) {
	t.Helper()
	prev := pfxPasswordResolverFn
	s.startupAudit()
	t.Cleanup(func() { pfxPasswordResolverFn = prev })
}

// b1EncOnlyBundle builds a bundle whose PFX containers are encrypted with pw, then
// rewrites its meta.json through SaveCertBundle so the plaintext password is
// dropped and the ciphertext moves to PFXPasswordEncKey. It returns the reloaded
// bundle + meta and asserts that post-Slice-3a shape as a precondition — without it
// the tests below would not exercise the regression at all.
func b1EncOnlyBundle(t *testing.T, st *store.ManagerStore, dir, name, cn, pw string) (*store.CertBundle, map[string]interface{}) {
	t.Helper()
	c := newCertSet(t, cn, 1)
	meta0 := acmeMeta("alidns")
	meta0["pfx_password"] = pw // 旧形态（明文）—— SaveCertBundle 会转成密文
	acmeBundle(t, dir, name, c, certSet{}, pw, 1, meta0)

	b0, err := st.LoadCertBundle(name)
	if err != nil {
		t.Fatalf("LoadCertBundle: %v", err)
	}
	if b0.PFXPassword != pw {
		t.Fatalf("前置条件：明文 meta 应能读出 %q，实际 %q", pw, b0.PFXPassword)
	}
	if err := st.SaveCertBundle(b0); err != nil {
		t.Fatalf("SaveCertBundle: %v", err)
	}
	b, err := st.LoadCertBundle(name)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if b.PFXPassword != "" {
		t.Fatalf("前置条件不成立：Slice 3a 后盘载 bundle 的明文口令应为空，实际 %q", b.PFXPassword)
	}
	meta, err := st.LoadCertMeta(name)
	if err != nil {
		t.Fatalf("LoadCertMeta: %v", err)
	}
	if _, ok := meta[store.PFXPasswordEncKey]; !ok {
		t.Fatalf("前置条件不成立：meta.json 必须含 %s，实际 %v", store.PFXPasswordEncKey, meta)
	}
	return b, meta
}

// assertPFXOpensWith decrypts both PFX containers of dir and checks that they open
// with want and (when want is not the default) do NOT open with the default — the
// latter is what makes "the resolved password was really used" discriminating.
func assertPFXOpensWith(t *testing.T, dir string, want string, wantLeafDER []byte) {
	t.Helper()
	for _, fn := range []string{"cert.pfx", "cert-modern.pfx"} {
		data, err := os.ReadFile(filepath.Join(dir, fn))
		if err != nil {
			t.Errorf("读 %s 失败: %v", fn, err)
			continue
		}
		leaf, _, err := mycrypto.ParsePFXLeafChain(data, want)
		if err != nil || leaf == nil {
			t.Errorf("%s 应以口令 %q 可解，err=%v", fn, want, err)
			continue
		}
		if wantLeafDER != nil && !bytes.Equal(leaf.Raw, wantLeafDER) {
			t.Errorf("%s 的叶证书与 fullchain.pem 不一致", fn)
		}
		if want != mycrypto.DefaultPFXPassword {
			if _, _, err := mycrypto.ParsePFXLeafChain(data, mycrypto.DefaultPFXPassword); err == nil {
				t.Errorf("%s 竟然可用默认口令 %q 解开 ⇒ 说明重建时用了默认口令（回归）",
					fn, mycrypto.DefaultPFXPassword)
			}
		}
	}
}

// ── ① 心跳推送 ──

func TestT71a_HeartbeatPushesResolvedPFXPassword(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	const customPw = "custom-pw-3b-hb"
	const nodeID, nodePw, fp = "node-3b", "node-secret-3b", "fp-3b"

	b1EncOnlyBundle(t, st, dir, "acme-hb", "hb.example.com", customPw)

	hash, err := bcrypt.GenerateFromPassword([]byte(nodePw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	rec := &model.NodeRecord{
		Fingerprint: fp, PasswordHash: string(hash), Approved: true,
		CertBindings: []model.CertBinding{{BundleName: "acme-hb", DeployPath: "C:/cert3b"}},
	}
	if err := st.PutNode(nodeID, rec); err != nil {
		t.Fatal(err)
	}

	// 空 CertHashes ⇒ 与 bundle.Hash 不匹配 ⇒ 必然推送
	body, _ := json.Marshal(model.HeartbeatReq{Fingerprint: fp})
	r := httptest.NewRequest("POST", "/api/heartbeat", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+
		base64.StdEncoding.EncodeToString([]byte(nodeID+":"+nodePw)))
	w := httptest.NewRecorder()
	s.handleHeartbeat(w, r)

	if w.Code != 200 {
		t.Fatalf("心跳应 200，实际 %d body=%s", w.Code, w.Body.String())
	}
	var resp model.HeartbeatResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解码响应失败: %v (%s)", err, w.Body.String())
	}
	if len(resp.CertUpdates) != 1 {
		t.Fatalf("应推送 1 个证书更新，实际 %d（body=%s）", len(resp.CertUpdates), w.Body.String())
	}
	got := resp.CertUpdates[0].PFXPassword
	if got != customPw {
		t.Errorf("① 心跳推送口令应为解密口令 %q，实际 %q（默认=%q ⇒ 被强制回默认的回归）",
			customPw, got, mycrypto.DefaultPFXPassword)
	}
	if got == mycrypto.DefaultPFXPassword {
		t.Error("① 不得在盘载口令下强制回落默认口令")
	}
}

// ── ② 一致性判定 ──

func TestT71b_ConsistencyVerdictUsesDecryptedPassword(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	const customPw = "custom-pw-3b-cc"
	b, meta := b1EncOnlyBundle(t, st, dir, "acme-cc", "cc.example.com", customPw)

	// 正控：**未接线**（hook 为 nil）时判定必退化 ⇒ 证明本测试确实依赖接线。
	pfxPasswordResolverFn = nil
	if v, _, _ := s.checkBundlePFXConsistency(b, meta); v == pfxConsistent {
		t.Fatal("正控失败：未接线 resolver 时不应判定 consistent（否则本断言无判别力）")
	}

	wireB1Resolver(t, s)
	v, reason, hard := s.checkBundlePFXConsistency(b, meta)
	if v != pfxConsistent {
		t.Errorf("② 接线后应判定 consistent，实际 %v（reason=%q hard=%v）", v, reason, hard)
	}
}

// ── ③ 续签双 PFX 重建（经 attachDNSKeyLookup 接线）──

func TestT71c_UpdateCertMetaUsesDecryptedPassword(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	const customPw = "custom-pw-3b-rp"
	const certName = "rp"

	// Manager bundle 目录（dir/certs/acme-rp）——口令权威来源（密文）
	meta0 := acmeMeta("alidns")
	meta0["pfx_password"] = customPw
	c := newCertSet(t, "rp.example.com", 1)
	acmeBundle(t, dir, "acme-"+certName, c, certSet{}, customPw, 1, meta0)
	b0, err := st.LoadCertBundle("acme-" + certName)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveCertBundle(b0); err != nil {
		t.Fatal(err)
	}

	// acme.sh 侧证书目录（dir/certs/rp）——meta.json 不含口令键，旧 PFX 用默认口令
	certDir := filepath.Join(dir, "certs", certName)
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(certDir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldPFX, err := mycrypto.GeneratePFX(c.chain, c.key, mycrypto.DefaultPFXPassword)
	if err != nil {
		t.Fatal(err)
	}
	write("fullchain.pem", c.chain)
	write("cert.pem", c.cert)
	write("privkey.pem", c.key)
	write("cert.pfx", oldPFX)
	mjs, _ := json.Marshal(map[string]interface{}{"acme": true, "domains": []string{"rp.example.com"}})
	write("meta.json", mjs)

	mgr, err := acme.New(filepath.Join(dir, "certs"), "t@example.com", ":80")
	if err != nil {
		t.Fatal(err)
	}
	if mgr.PFXPasswordResolverConfigured() {
		t.Fatal("前置条件：新建 Manager 不应已接线")
	}
	s.attachDNSKeyLookup(mgr)
	if !mgr.PFXPasswordResolverConfigured() {
		t.Fatal("⑧ 接线断言：attachDNSKeyLookup 必须接线 PFX 口令解析器")
	}

	if err := mgr.UpdateCertMeta(certDir); err != nil {
		t.Fatalf("UpdateCertMeta: %v", err)
	}
	assertPFXOpensWith(t, certDir, customPw, leafDER(c.chain))
}

// ── ⑤ detail 接口（UI 契约）──

func TestT71d_CertDetailReturnsResolvedPassword(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	s.cfg = &srvcfg.ManagerConfig{DataDir: dir}
	const customPw = "custom-pw-3b-detail"
	b1EncOnlyBundle(t, st, dir, "acme-dt", "dt.example.com", customPw)

	r := httptest.NewRequest("GET", "/api/certs/acme-dt", nil)
	r = mux.SetURLVars(r, map[string]string{"name": "acme-dt"})
	w := httptest.NewRecorder()
	s.handleGetCert(w, r)

	if w.Code != 200 {
		t.Fatalf("detail 应 200，实际 %d body=%s", w.Code, w.Body.String())
	}
	var detail map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
		t.Fatalf("解码失败: %v (%s)", err, w.Body.String())
	}
	got, _ := detail["pfx_password"].(string)
	if got != customPw {
		t.Errorf("⑤ detail.pfx_password 应为解密口令 %q，实际 %q（默认=%q ⇒ UI 显示回归）",
			customPw, got, mycrypto.DefaultPFXPassword)
	}
}

// ── 重建写回点：不得以默认口令覆盖用户自定义口令 ──

func TestT71e_RebuildKeepsResolvedPassword(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	const customPw = "custom-pw-3b-rebuild"
	newC := newCertSet(t, "rb.example.com", 1)
	oldC := newCertSet(t, "rb-old.example.com", 1)
	meta0 := map[string]interface{}{
		"acme": true, "provider": "alidns", "domains": []string{"rb.example.com"},
		"pfx_password": customPw,
	}
	// PEM = 新证书，PFX = 旧证书 ⇒ 必判定 needs_rebuild
	acmeBundle(t, dir, "acme-rb", newC, certSet{cert: oldC.cert, chain: oldC.chain, key: oldC.key}, customPw, 1, meta0)
	b0, err := st.LoadCertBundle("acme-rb")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveCertBundle(b0); err != nil {
		t.Fatal(err)
	}
	wireB1Resolver(t, s)

	b, meta := func() (*store.CertBundle, map[string]interface{}) {
		bb, err := st.LoadCertBundle("acme-rb")
		if err != nil {
			t.Fatal(err)
		}
		mm, err := st.LoadCertMeta("acme-rb")
		if err != nil {
			t.Fatal(err)
		}
		return bb, mm
	}()
	if v, reason, _ := s.checkBundlePFXConsistency(b, meta); v != pfxNeedsRebuild {
		t.Fatalf("前置条件：应判定 needs_rebuild，实际 %v（%s）", v, reason)
	}

	if err := s.rebuildBundlePFX(b, meta); err != nil {
		t.Fatalf("rebuildBundlePFX: %v", err)
	}
	got, err := st.BundlePFXPassword(&store.CertBundle{Name: "acme-rb"})
	if err != nil {
		t.Fatalf("BundlePFXPassword: %v", err)
	}
	if got != customPw {
		t.Errorf("重建后盘上口令应为 %q，实际 %q（默认=%q ⇒ 用户口令被覆盖丢失）",
			customPw, got, mycrypto.DefaultPFXPassword)
	}
	assertPFXOpensWith(t, filepath.Join(dir, "certs", "acme-rb"), customPw, leafDER(newC.chain))
}

// 解析失败 ⇒ 拒绝重建（绝不用默认口令顶替），且盘上口令不被改动。
func TestT71e2_RebuildRefusesWhenResolverFails(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	const customPw = "custom-pw-3b-refuse"
	newC := newCertSet(t, "rf.example.com", 1)
	oldC := newCertSet(t, "rf-old.example.com", 1)
	meta0 := map[string]interface{}{
		"acme": true, "provider": "alidns", "domains": []string{"rf.example.com"},
		"pfx_password": customPw,
	}
	acmeBundle(t, dir, "acme-rf", newC, certSet{cert: oldC.cert, chain: oldC.chain, key: oldC.key}, customPw, 1, meta0)
	b0, err := st.LoadCertBundle("acme-rf")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveCertBundle(b0); err != nil {
		t.Fatal(err)
	}
	wireB1Resolver(t, s)

	b, err := st.LoadCertBundle("acme-rf")
	if err != nil {
		t.Fatal(err)
	}
	meta, err := st.LoadCertMeta("acme-rf")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "certs", "acme-rf", "cert.pfx"))
	if err != nil {
		t.Fatal(err)
	}

	// 注入：resolver 报错（模拟密文损坏 / .storage_key 不符）
	pfxPasswordResolverFn = func(map[string]interface{}) (string, error) {
		return "", fmt.Errorf("注入：密文不可解")
	}

	if err := s.rebuildBundlePFX(b, meta); err == nil {
		t.Error("resolver 报错时必须**拒绝重建**（否则会以默认口令覆盖用户自定义口令）")
	}
	after, err := os.ReadFile(filepath.Join(dir, "certs", "acme-rf", "cert.pfx"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("解析失败时不得改动磁盘上的 PFX")
	}
	if got, err := st.BundlePFXPassword(&store.CertBundle{Name: "acme-rf"}); err != nil || got != customPw {
		t.Errorf("盘上口令不得被改动：实际 %q err=%v", got, err)
	}
	if v, _, hard := s.checkBundlePFXConsistency(b, meta); v != pfxUnverifiable || !hard {
		t.Errorf("口令解析失败应判 Unverifiable(hard=true)，实际 %v hard=%v", v, hard)
	}
}
