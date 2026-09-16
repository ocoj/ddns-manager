package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	mycrypto "github.com/ocoj/ddns-manager/internal/crypto"
	"github.com/ocoj/ddns-manager/internal/logger"
	"github.com/ocoj/ddns-manager/internal/store"
)

// ── helpers ──

func newCertConsistencyServer(t *testing.T) (*Server, *store.ManagerStore, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	logPath := filepath.Join(dir, "events.log")
	lm, err := logger.New(logPath, 100)
	if err != nil {
		t.Fatalf("logger.New: %v", err)
	}
	t.Cleanup(func() { _ = lm.Close() })
	return &Server{store: st, logMgr: lm}, st, dir
}

func genLeaf(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	certPEM, _, keyPEM = genLeafChain(t, cn, 0)
	return certPEM, keyPEM
}

func genLeafChain(t *testing.T, cn string, extraCA int) (certPEM, fullchainPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	fullchainPEM = append([]byte{}, certPEM...)
	for i := 0; i < extraCA; i++ {
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		caTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(2000 + i)),
			Subject:      pkix.Name{CommonName: cn + "-ca"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			IsCA:         true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
		fullchainPEM = append(fullchainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, fullchainPEM, keyPEM
}

func writeBundleDir(t *testing.T, dataDir, name string, files map[string][]byte, meta map[string]interface{}) {
	t.Helper()
	bd := filepath.Join(dataDir, "certs", name)
	if err := os.MkdirAll(bd, 0o700); err != nil {
		t.Fatal(err)
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(bd, n), c, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mb, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(bd, "meta.json"), mb, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFileOrNil(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

func countInLog(t *testing.T, dataDir, needle string) int {
	t.Helper()
	data := readFileOrNil(filepath.Join(dataDir, "events.log"))
	return strings.Count(string(data), needle)
}

// acmeBundle builds a realistic ACME bundle: PEMs from newCert, PFXs from pfxCert
// (so passing distinct certs simulates an external writer having replaced only
// the PEMs).
func acmeBundle(t *testing.T, dataDir, name string, newCert, pfxCert struct{ cert, chain, key []byte }, pfxPassword string, chainLen int, meta map[string]interface{}) {
	t.Helper()
	certPEM := pfxCert.cert
	if pfxCert.cert == nil {
		certPEM = newCert.cert
	}
	pfxSourceCert := certPEM
	pfxSourceKey := pfxCert.key
	if pfxSourceCert == nil {
		pfxSourceCert = newCert.cert
	}
	if pfxSourceKey == nil {
		pfxSourceKey = newCert.key
	}
	var pfxSource []byte
	if chainLen > 0 && pfxCert.chain != nil {
		pfxSource = pfxCert.chain
	} else {
		pfxSource = pfxSourceCert
	}
	legacy, err := mycrypto.GeneratePFX(pfxSource, pfxSourceKey, pfxPassword)
	if err != nil {
		t.Fatalf("GeneratePFX: %v", err)
	}
	modern, err := mycrypto.GeneratePFXModern(pfxSource, pfxSourceKey, pfxPassword)
	if err != nil {
		t.Fatalf("GeneratePFXModern: %v", err)
	}
	files := map[string][]byte{
		"fullchain.pem":   newCert.chain,
		"cert.pem":        newCert.cert,
		"privkey.pem":     newCert.key,
		"cert.pfx":        legacy,
		"cert-modern.pfx": modern,
	}
	writeBundleDir(t, dataDir, name, files, meta)
}

type certSet struct{ cert, chain, key []byte }

func newCertSet(t *testing.T, cn string, extraCA int) certSet {
	c, fc, k := genLeafChain(t, cn, extraCA)
	return certSet{cert: c, chain: fc, key: k}
}

func acmeMeta(provider string) map[string]interface{} {
	return map[string]interface{}{"acme": true, "provider": provider, "domains": []string{"x.example.com"}}
}

// ── T16 ──

func TestReconcilePFX_ContentMismatch_Rebuilds(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	const pw = "testpw123"
	// PEM = NEW cert; PFX = OLD cert (simulating external PEM overwrite).
	newC := newCertSet(t, "new.example.com", 2)
	oldC := newCertSet(t, "old.example.com", 2)
	acmeBundle(t, dir, "acme-x", newC, certSet{cert: oldC.cert, chain: oldC.chain, key: oldC.key}, pw, 1, acmeMeta("alidns"))
	if err := os.WriteFile(filepath.Join(dir, "certs", "acme-x", "meta.json"),
		[]byte(`{"acme":true,"provider":"alidns","domains":["new.example.com"],"pfx_password":"`+pw+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	before, err := st.LoadCertBundle("acme-x")
	if err != nil {
		t.Fatal(err)
	}
	oldPFX := append([]byte{}, before.Files["cert.pfx"]...)

	got := s.ensureBundlePFXFresh("acme-x", before)
	if got == nil {
		t.Fatal("nil bundle")
	}
	if string(got.Files["cert.pfx"]) == string(oldPFX) {
		t.Fatal("expected the PFX to be regenerated")
	}
	// leaf DER must now match the PEM
	wantLeaf := leafDER(got.Files["fullchain.pem"])
	lf, _, _, err := decodePFXWithCandidates(got.Files["cert.pfx"], []string{pw})
	if err != nil {
		t.Fatalf("decode rebuilt PFX: %v", err)
	}
	if string(lf.Raw) != string(wantLeaf) {
		t.Error("rebuilt PFX leaf does not match PEM")
	}
	if countInLog(t, dir, "已重建双 PFX") != 1 {
		t.Error("expected exactly one rebuild audit")
	}
	// I16: caller must use the returned hash
	if got.Hash != computeHashOf(got) {
		t.Error("returned bundle hash is stale")
	}
}

// ── T17: same cert, different mtime → no rebuild (I17) ──

func TestReconcilePFX_SameCertDifferentMtime_NoRebuild(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	const pw = "testpw123"
	c := newCertSet(t, "same.example.com", 0)
	acmeBundle(t, dir, "acme-x", c, certSet{}, pw, 0, acmeMeta("alidns"))
	if err := os.WriteFile(filepath.Join(dir, "certs", "acme-x", "meta.json"),
		[]byte(`{"acme":true,"provider":"alidns","domains":["same.example.com"],"pfx_password":"`+pw+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Touch fullchain.pem so its mtime is newer than the PFX (this is the state
	// SaveCertBundle always leaves behind, since it writes names in sorted order).
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(filepath.Join(dir, "certs", "acme-x", "fullchain.pem"), future, future); err != nil {
		t.Fatal(err)
	}

	b, _ := st.LoadCertBundle("acme-x")
	oldPFX := append([]byte{}, b.Files["cert.pfx"]...)
	s.ensureBundlePFXFresh("acme-x", b)

	after, _ := st.LoadCertBundle("acme-x")
	if string(after.Files["cert.pfx"]) != string(oldPFX) {
		t.Error("PFX must NOT be rebuilt when only mtime differs (I17)")
	}
	if countInLog(t, dir, "已重建双 PFX") != 0 {
		t.Error("unexpected rebuild audit")
	}
}

// ── T17b: chain-length difference with identical leaf → no rebuild (I19/R32) ──

func TestReconcilePFX_DiffChainCount_NoRebuild(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	const pw = "testpw123"
	// fullchain has 3 certs; PFX was generated from cert.pem (leaf only).
	c := newCertSet(t, "chain.example.com", 2)
	acmeBundle(t, dir, "acme-x", c, certSet{cert: c.cert, chain: c.cert, key: c.key}, pw, 1, acmeMeta("alidns"))
	if err := os.WriteFile(filepath.Join(dir, "certs", "acme-x", "meta.json"),
		[]byte(`{"acme":true,"provider":"alidns","domains":["chain.example.com"],"pfx_password":"`+pw+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	b, _ := st.LoadCertBundle("acme-x")
	oldPFX := append([]byte{}, b.Files["cert.pfx"]...)
	s.ensureBundlePFXFresh("acme-x", b)

	after, _ := st.LoadCertBundle("acme-x")
	if string(after.Files["cert.pfx"]) != string(oldPFX) {
		t.Error("chain-length difference alone must NOT trigger a rebuild (would oscillate after every renewal)")
	}
}

// ── T19: missing PFX → rebuild ──

func TestReconcilePFX_MissingPFX_Rebuilds(t *testing.T) {
	for _, missing := range []string{"cert.pfx", "cert-modern.pfx"} {
		t.Run(missing, func(t *testing.T) {
			s, st, dir := newCertConsistencyServer(t)
			const pw = "testpw123"
			c := newCertSet(t, "miss.example.com", 1)
			acmeBundle(t, dir, "acme-x", c, certSet{}, pw, 0, acmeMeta("alidns"))
			meta := filepath.Join(dir, "certs", "acme-x", "meta.json")
			if err := os.WriteFile(meta,
				[]byte(`{"acme":true,"provider":"alidns","domains":["miss.example.com"],"pfx_password":"`+pw+`"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, "certs", "acme-x", missing)); err != nil {
				t.Fatal(err)
			}
			b, _ := st.LoadCertBundle("acme-x")
			got := s.ensureBundlePFXFresh("acme-x", b)
			if len(got.Files["cert.pfx"]) == 0 || len(got.Files["cert-modern.pfx"]) == 0 {
				t.Fatalf("expected both PFX regenerated when %s is missing", missing)
			}
		})
	}
}

// ── T18/T31: undecodable → no rebuild + a single (deduped) error audit ──

func TestReconcilePFX_Undecodable_NoRebuildDedupedError(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	c := newCertSet(t, "undec.example.com", 1)
	// PFX encrypted with an unknown password; no candidates will match.
	acmeBundle(t, dir, "acme-x", c, certSet{}, "unknown-password-xyz", 0, acmeMeta("alidns"))
	if err := os.WriteFile(filepath.Join(dir, "certs", "acme-x", "meta.json"),
		[]byte(`{"acme":true,"provider":"alidns","domains":["undec.example.com"]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		b, _ := st.LoadCertBundle("acme-x")
		oldPFX := append([]byte{}, b.Files["cert.pfx"]...)
		s.ensureBundlePFXFresh("acme-x", b)
		after, _ := st.LoadCertBundle("acme-x")
		if string(after.Files["cert.pfx"]) != string(oldPFX) {
			t.Fatal("must NOT rebuild when the PFX cannot be decoded (would swap in a new password)")
		}
	}
	if got := countInLog(t, dir, "证书一致性不可判定"); got != 1 {
		t.Errorf("expected exactly 1 deduped error audit for 100 heartbeats, got %d", got)
	}
	if !strings.Contains(string(readFileOrNil(filepath.Join(dir, "events.log"))), `"status":"error"`) {
		t.Error("undecodable PFX audit must be error level")
	}

	// T31 recovery half: once the container is decodable again, exactly ONE
	// informational "恢复" entry appears (state change, not per heartbeat).
	bd := filepath.Join(dir, "certs", "acme-x")
	fc := readFileOrNil(filepath.Join(bd, "fullchain.pem"))
	key := readFileOrNil(filepath.Join(bd, "privkey.pem"))
	legacy, err := mycrypto.GeneratePFX(fc, key, mycrypto.DefaultPFXPassword)
	if err != nil {
		t.Fatal(err)
	}
	modern, err := mycrypto.GeneratePFXModern(fc, key, mycrypto.DefaultPFXPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bd, "cert.pfx"), legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bd, "cert-modern.pfx"), modern, 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		b, err := st.LoadCertBundle("acme-x")
		if err != nil {
			t.Fatal(err)
		}
		s.ensureBundlePFXFresh("acme-x", b)
	}
	if n := countInLog(t, dir, "证书一致性恢复"); n != 1 {
		t.Errorf("recovery must be reported exactly once, got %d", n)
	}
}

// ── T21: non-ACME (uploaded) bundles are never touched ──

func TestReconcilePFX_SkipsNonACMEBundle(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	newC := newCertSet(t, "up.example.com", 0)
	oldC := newCertSet(t, "old.example.com", 0)
	legacy, _ := mycrypto.GeneratePFX(oldC.cert, oldC.key, "pw")
	modern, _ := mycrypto.GeneratePFXModern(oldC.cert, oldC.key, "pw")
	writeBundleDir(t, dir, "acme-up", map[string][]byte{
		"fullchain.pem": newC.chain, "cert.pem": newC.cert, "privkey.pem": newC.key,
		"cert.pfx": legacy, "cert-modern.pfx": modern,
	}, map[string]interface{}{"acme": false, "domains": []string{"up.example.com"}})

	b, _ := st.LoadCertBundle("acme-up")
	oldPFX := append([]byte{}, b.Files["cert.pfx"]...)
	s.ensureBundlePFXFresh("acme-up", b)
	after, _ := st.LoadCertBundle("acme-up")
	if string(after.Files["cert.pfx"]) != string(oldPFX) {
		t.Error("uploaded (non-ACME) bundles must not be modified (I7)")
	}
}

// ── T20/T20b/T22: concurrent triggers rebuild exactly once (I18/I22) ──

func TestReconcilePFX_Concurrent_SingleRebuild(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	const pw = "testpw123"
	newC := newCertSet(t, "conc.example.com", 1)
	oldC := newCertSet(t, "old.example.com", 1)
	acmeBundle(t, dir, "acme-x", newC, certSet{cert: oldC.cert, chain: oldC.chain, key: oldC.key}, pw, 1, acmeMeta("alidns"))
	if err := os.WriteFile(filepath.Join(dir, "certs", "acme-x", "meta.json"),
		[]byte(`{"acme":true,"provider":"alidns","domains":["conc.example.com"],"pfx_password":"`+pw+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Each goroutine loads its own (stale) copy — exactly what concurrent
	// heartbeats do — then calls ensureBundlePFXFresh.
	const n = 8
	var wg sync.WaitGroup
	hashes := make([]string, n)
	for i := 0; i < n; i++ {
		b, err := st.LoadCertBundle("acme-x")
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(idx int, b *store.CertBundle) {
			defer wg.Done()
			got := s.ensureBundlePFXFresh("acme-x", b)
			if got != nil {
				hashes[idx] = got.Hash
			}
		}(i, b)
	}
	wg.Wait()

	if got := countInLog(t, dir, "已重建双 PFX"); got != 1 {
		t.Errorf("concurrent triggers must rebuild exactly once, got %d", got)
	}
	// All callers must end up with the same (current) hash and the on-disk PFX
	// must be self-consistent.
	final, _ := st.LoadCertBundle("acme-x")
	wantLeaf := leafDER(final.Files["fullchain.pem"])
	lf, _, _, err := decodePFXWithCandidates(final.Files["cert.pfx"], []string{pw})
	if err != nil {
		t.Fatalf("decode final PFX: %v", err)
	}
	if string(lf.Raw) != string(wantLeaf) {
		t.Error("final PFX leaf mismatch")
	}
	for i, h := range hashes {
		if h != "" && h != final.Hash {
			t.Errorf("goroutine %d returned a stale hash %s, want %s", i, h, final.Hash)
		}
	}
}

// ── T27: informational audits are deduped per state change (I21/I23) ──

func TestReconcilePFX_ChainDiffAuditDeduped(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	const pw = "testpw123"
	c := newCertSet(t, "dedup.example.com", 2)
	acmeBundle(t, dir, "acme-x", c, certSet{cert: c.cert, chain: c.cert, key: c.key}, pw, 1, acmeMeta("alidns"))
	if err := os.WriteFile(filepath.Join(dir, "certs", "acme-x", "meta.json"),
		[]byte(`{"acme":true,"provider":"alidns","domains":["dedup.example.com"],"pfx_password":"`+pw+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		b, _ := st.LoadCertBundle("acme-x")
		s.ensureBundlePFXFresh("acme-x", b)
	}
	// Chain-length difference only: it must be reported once, not once per heartbeat.
	if got := countInLog(t, dir, "PFX 链长与 fullchain 不同"); got != 1 {
		t.Errorf("chain-difference audit must be deduped to exactly 1 line, got %d", got)
	}
}

func computeHashOf(b *store.CertBundle) string {
	return computeBundleHash(b.Files)
}

// B4: "unverifiable, but not a hard error" — missing source files (no private
// key / no PEM) must be a warning, whereas an undecodable PFX is an error.
// Both are deduped, so neither can flood the audit log.
func TestReconcilePFX_MissingSourcePEM_WarningLevel(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	const pw = "testpw123"
	c := newCertSet(t, "soft.example.com", 0)
	acmeBundle(t, dir, "acme-x", c, certSet{}, pw, 0, acmeMeta("alidns"))
	if err := os.Remove(filepath.Join(dir, "certs", "acme-x", "privkey.pem")); err != nil {
		t.Fatal(err)
	}

	b, err := st.LoadCertBundle("acme-x")
	if err != nil {
		t.Fatal(err)
	}
	oldPFX := append([]byte{}, b.Files["cert.pfx"]...)
	s.ensureBundlePFXFresh("acme-x", b)

	after, _ := st.LoadCertBundle("acme-x")
	if string(after.Files["cert.pfx"]) != string(oldPFX) {
		t.Error("must not rebuild when the private key is unavailable")
	}
	logData := string(readFileOrNil(filepath.Join(dir, "events.log")))
	if !strings.Contains(logData, "证书一致性不可判定") {
		t.Error("expected an unverifiable audit")
	}
	if strings.Contains(logData, `"status":"error"`) {
		t.Error("missing source PEM/key must be warning level, not error (B4)")
	}
}

// T26（I20/R36）: the rebuilt PFX must carry the SAME chain as fullchain.pem
// (rebuild source is fullchain.pem), and cert.pem must stay leaf-only.
// If the rebuild used cert.pem instead, every renewal would produce a leaf-only
// PFX and reopen the chain-difference question.
func TestReconcilePFX_RebuildKeepsFullchainChain(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	const pw = "testpw123"
	newC := newCertSet(t, "chain2.example.com", 2) // fullchain = leaf + 2 CA
	oldC := newCertSet(t, "old.example.com", 1)
	acmeBundle(t, dir, "acme-x", newC, certSet{cert: oldC.cert, chain: oldC.chain, key: oldC.key}, pw, 1, acmeMeta("alidns"))
	if err := os.WriteFile(filepath.Join(dir, "certs", "acme-x", "meta.json"),
		[]byte(`{"acme":true,"provider":"alidns","domains":["chain2.example.com"],"pfx_password":"`+pw+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	b, err := st.LoadCertBundle("acme-x")
	if err != nil {
		t.Fatal(err)
	}
	got := s.ensureBundlePFXFresh("acme-x", b)

	fcLen := len(mycrypto.ParseCertChainPEM(got.Files["fullchain.pem"]))
	if fcLen != 3 {
		t.Fatalf("fixture: fullchain should have 3 certs, got %d", fcLen)
	}
	for _, name := range []string{"cert.pfx", "cert-modern.pfx"} {
		leaf, ca, _, err := decodePFXWithCandidates(got.Files[name], []string{pw})
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if leaf == nil {
			t.Fatalf("%s: nil leaf", name)
		}
		if chainLen := ca + 1; chainLen != fcLen { // ca = CA cert count from DecodeChain
			t.Errorf("%s chain length = %d, want %d (= fullchain length)", name, chainLen, fcLen)
		}
	}
	if n := len(mycrypto.ParseCertChainPEM(got.Files["cert.pem"])); n != 1 {
		t.Errorf("cert.pem must remain leaf-only after rebuild, got %d certs", n)
	}
}

// ── T28 ──

// T28（R39）: the PFX password is discovered by trying candidates. A bundle
// whose meta records a password that does NOT match the container must still be
// decoded (via DefaultPFXPassword) — otherwise S9 would rebuild on every
// heartbeat; and when no candidate works the error must be classified as a
// password mismatch rather than a corrupt container.
func TestParsePFXLeafChain_PasswordCandidates(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	const metaPw = "meta-pw-that-does-not-match"
	c := newCertSet(t, "pw.example.com", 1)

	// Container encrypted with DefaultPFXPassword, meta records something else.
	acmeBundle(t, dir, "acme-pw", c, certSet{}, mycrypto.DefaultPFXPassword, 1, acmeMeta("alidns"))
	if err := os.WriteFile(filepath.Join(dir, "certs", "acme-pw", "meta.json"),
		[]byte(`{"acme":true,"provider":"alidns","domains":["pw.example.com"],"pfx_password":"`+metaPw+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	b, err := st.LoadCertBundle("acme-pw")
	if err != nil {
		t.Fatal(err)
	}
	if b.PFXPassword != metaPw {
		t.Fatalf("precondition: bundle password should come from meta, got %q", b.PFXPassword)
	}
	oldPFX := append([]byte{}, b.Files["cert.pfx"]...)

	got := s.ensureBundlePFXFresh("acme-pw", b)

	if !bytes.Equal(got.Files["cert.pfx"], oldPFX) {
		t.Error("candidate iteration must decode the PFX and therefore NOT rebuild it")
	}
	if n := countInLog(t, dir, "已重建双 PFX"); n != 0 {
		t.Errorf("no rebuild expected, got %d", n)
	}
	if n := countInLog(t, dir, "证书一致性不可判定"); n != 0 {
		t.Errorf("no unverifiable audit expected, got %d", n)
	}

	// All candidates fail → classified as a password mismatch (not corruption).
	unrelated, err := mycrypto.GeneratePFX(c.chain, c.key, "pw-neither-candidate")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := mycrypto.ParsePFXLeafChain(unrelated, "yet-another-pw"); err == nil {
		t.Fatal("expected decode to fail with a wrong password")
	} else if cls := mycrypto.ClassifyPFXError(err); !strings.Contains(cls, "密码不符") {
		t.Errorf("ClassifyPFXError = %q, want it to mention 密码不符", cls)
	}
}

// ── T29 ──

// T29（I16/I22）: the bundle handed back to the heartbeat must be the RELOADED
// one, so its Hash matches disk (and therefore what gets encrypted/pushed).
func TestReconcilePFX_ReturnsReloadedBundle(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	const pw = "testpw123"
	newC := newCertSet(t, "reload.example.com", 2)
	oldC := newCertSet(t, "old.example.com", 2)
	acmeBundle(t, dir, "acme-r", newC, certSet{cert: oldC.cert, chain: oldC.chain, key: oldC.key}, pw, 1, acmeMeta("alidns"))
	if err := os.WriteFile(filepath.Join(dir, "certs", "acme-r", "meta.json"),
		[]byte(`{"acme":true,"provider":"alidns","domains":["reload.example.com"],"pfx_password":"`+pw+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	stale, err := st.LoadCertBundle("acme-r")
	if err != nil {
		t.Fatal(err)
	}
	staleHash := stale.Hash

	got := s.ensureBundlePFXFresh("acme-r", stale)
	disk, err := st.LoadCertBundle("acme-r")
	if err != nil {
		t.Fatal(err)
	}
	if got == stale {
		t.Error("a rebuilt bundle must be returned as the reloaded object, not the stale input")
	}
	if got.Hash == staleHash {
		t.Error("the returned hash must reflect the rebuilt content")
	}
	if got.Hash != disk.Hash {
		t.Errorf("returned hash %q != on-disk hash %q", got.Hash, disk.Hash)
	}
	meta, err := st.LoadCertMeta("acme-r")
	if err != nil {
		t.Fatal(err)
	}
	if meta["hash"] != got.Hash {
		t.Errorf("meta.hash %v != returned hash %q (I16: CertHash must match the encrypted content)", meta["hash"], got.Hash)
	}

	// A consistent bundle is returned unchanged, and its hash still matches disk.
	again := s.ensureBundlePFXFresh("acme-r", disk)
	if again.Hash != disk.Hash {
		t.Errorf("no-rebuild path must return a hash consistent with disk, got %q", again.Hash)
	}
}

// ── T30 ──

// T30（S12/R46）: every PFX generation point must take its certificate source
// from the single deterministic helper, so the PFX chain always matches
// fullchain.pem.
func TestCertSourceFullchain_AllPaths(t *testing.T) {
	t.Run("机制：优先 fullchain 且链长一致", func(t *testing.T) {
		const pw = "testpw123"
		c := newCertSet(t, "src.example.com", 2) // fullchain = leaf + 2 CA
		files := map[string][]byte{
			"fullchain.pem": c.chain,
			"cert.pem":      c.cert, // leaf-only variant must never win
			"privkey.pem":   c.key,
		}
		certPEM := mycrypto.PickCertPEM(files)
		if !bytes.Equal(certPEM, c.chain) {
			t.Fatal("PickCertPEM must prefer fullchain.pem when both variants exist")
		}
		wantLen := len(mycrypto.ParseCertChainPEM(c.chain))
		if wantLen != 3 {
			t.Fatalf("fixture: want 3 certs in fullchain, got %d", wantLen)
		}
		for _, gen := range []func(cert, key []byte, pw string) ([]byte, error){
			mycrypto.GeneratePFX, mycrypto.GeneratePFXModern,
		} {
			container, err := gen(certPEM, c.key, pw)
			if err != nil {
				t.Fatal(err)
			}
			leaf, caCerts, err := mycrypto.ParsePFXLeafChain(container, pw)
			if err != nil {
				t.Fatal(err)
			}
			if leaf == nil || len(caCerts)+1 != wantLen {
				t.Errorf("generated PFX chain length = %d, want %d (= fullchain)", len(caCerts)+1, wantLen)
			}
		}
	})

	t.Run("结构：每个 PFX 生成点都在同一函数内经 PickCertPEM", func(t *testing.T) {
		// Enforceable guard for S12/R46 (replaces the earlier occurrence-counting
		// check, which could not detect a NEW generation point that bypasses the
		// helper). A counting check passes as long as the existing 5 call sites
		// remain, so it proved nothing about additions.
		//
		// Scope: the two files that own the 5 generation points. The rebuild path
		// (internal/server/cert_consistency.go:rebuildBundlePFX) is deliberately
		// out of scope: per I20 it must use fullchain.pem directly, not PickCertPEM.
		for _, path := range []string{filepath.Join("..", "acme", "acme.go"), "handlers_certs.go"} {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			found := 0
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				var genPFX, pickCert bool
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					switch sel.Sel.Name {
					case "GeneratePFX", "GeneratePFXModern":
						genPFX = true
					case "PickCertPEM":
						pickCert = true
					}
					return true
				})
				if genPFX {
					found++
					if !pickCert {
						t.Errorf("%s: %s generates a PFX without resolving the cert source via PickCertPEM (S12/R46)",
							path, fd.Name.Name)
					}
				}
			}
			if found == 0 {
				t.Errorf("%s: expected at least one PFX generation point", path)
			}
		}
	})
}

// ── T33 ──

// T33（I25/R47）: the audit dedup signature lifecycle — cleared when a bundle is
// deleted, reset by a restart, and never duplicated when several nodes bind the
// same bundle concurrently.
func TestPFXAuditSigLifecycle(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)
	const pw = "testpw123"
	c := newCertSet(t, "sig.example.com", 1)
	// pfxCert=c + chainLen>0 makes the PFX carry the same chain as fullchain, so
	// the bundle lands on the plain "证书一致性" audit branch (not the
	// informational chain-length branch).
	acmeBundle(t, dir, "acme-sig", c, c, pw, 1, acmeMeta("alidns"))
	if err := os.WriteFile(filepath.Join(dir, "certs", "acme-sig", "meta.json"),
		[]byte(`{"acme":true,"provider":"alidns","domains":["sig.example.com"],"pfx_password":"`+pw+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	audit := func(srv *Server) {
		b, err := st.LoadCertBundle("acme-sig")
		if err != nil {
			t.Fatal(err)
		}
		meta, err := st.LoadCertMeta("acme-sig")
		if err != nil {
			t.Fatal(err)
		}
		v, r, h := srv.checkBundlePFXConsistency(b, meta)
		srv.auditBundleConsistency("acme-sig", b, meta, v, r, h)
	}

	audit(s)
	audit(s) // deduped
	if n := countInLog(t, dir, "证书一致性"); n != 1 {
		t.Errorf("repeated identical state must be deduped, got %d audits", n)
	}

	// (1) 删除清理 → 同状态可再报一次
	s.clearPFXAuditSig("acme-sig")
	audit(s)
	if n := countInLog(t, dir, "证书一致性"); n != 2 {
		t.Errorf("after clearing the signature the state must be reportable again, got %d audits", n)
	}

	// (2) 重启（新 Server 实例）→ 每 bundle 允许再报 1 条
	s2 := &Server{store: st, logMgr: s.logMgr}
	audit(s2)
	if n := countInLog(t, dir, "证书一致性"); n != 3 {
		t.Errorf("a fresh process must report each bundle once, got %d audits", n)
	}

	// (3) 并发多节点绑同一 bundle（不一致）→ 重建与恢复审计各仅 1 条
	newC := newCertSet(t, "conc.example.com", 2)
	oldC := newCertSet(t, "old.example.com", 2)
	acmeBundle(t, dir, "acme-conc", newC, certSet{cert: oldC.cert, chain: oldC.chain, key: oldC.key}, pw, 1, acmeMeta("alidns"))
	if err := os.WriteFile(filepath.Join(dir, "certs", "acme-conc", "meta.json"),
		[]byte(`{"acme":true,"provider":"alidns","domains":["conc.example.com"],"pfx_password":"`+pw+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	const nodes = 8
	var wg sync.WaitGroup
	for i := 0; i < nodes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := st.LoadCertBundle("acme-conc") // each node holds its own (stale) copy
			if err != nil {
				return
			}
			s.ensureBundlePFXFresh("acme-conc", b)
		}()
	}
	wg.Wait()

	if n := countInLog(t, dir, "已重建双 PFX"); n != 1 {
		t.Errorf("concurrent nodes binding one bundle must produce 1 rebuild audit, got %d", n)
	}
	if n := countInLog(t, dir, "证书内容不一致"); n > 1 {
		t.Errorf("the mismatch state must be deduped, got %d audits", n)
	}
}

// T56 [A6 / P4-G1]: 一致性告警的 detail 必须写明"疑似外部写入（PEM/PFX 不同源）"，
// 且该告警按**状态签名去重**（I23）⇒ 同一状态连续判定**只记 1 条**（扩写文案不增噪音）。
func TestT56_ConsistencyAudit_MentionsExternalWrite_AndDeduped(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)

	leaf, chain, key := genLeafChain(t, "t56.example.com", 0)
	older, _, olderKey := genLeafChain(t, "t56.example.com", 0) // PFX 内是**另一张**（不同源）
	acmeBundle(t, dir, "acme-t56.example.com",
		struct{ cert, chain, key []byte }{leaf, chain, key},
		struct{ cert, chain, key []byte }{older, chain, olderKey},
		"pw", 0, map[string]interface{}{"acme": true, "domains": []string{"t56.example.com"}, "pfx_password": "pw"})

	b, err := st.LoadCertBundle("acme-t56.example.com")
	if err != nil {
		t.Fatalf("LoadCertBundle: %v", err)
	}
	meta, err := st.LoadCertMeta("acme-t56.example.com")
	if err != nil {
		t.Fatalf("LoadCertMeta: %v", err)
	}

	// ① 判定应确为 NeedsRebuild（PFX 的叶证书与 PEM 不一致）
	if v, reason, _ := s.checkBundlePFXConsistency(b, meta); v != pfxNeedsRebuild {
		t.Fatalf("夹具应判为 NeedsRebuild，实际 %v（%s）", v, reason)
	}

	// ② 连续两次同状态判定 ⇒ detail 含"疑似外部写入"、且**只记 1 条**（去重 = 不增噪音）
	s.auditBundleConsistency("acme-t56.example.com", b, meta, pfxNeedsRebuild, "cert.pfx 的叶证书与 PEM 不一致", false)
	s.auditBundleConsistency("acme-t56.example.com", b, meta, pfxNeedsRebuild, "cert.pfx 的叶证书与 PEM 不一致", false)

	if n := countInLog(t, dir, "证书内容不一致"); n != 1 {
		t.Errorf("同一状态应只记 1 条一致性告警（去重），实际 %d", n)
	}
	if n := countInLog(t, dir, "疑似外部写入（PEM/PFX 不同源"); n != 1 {
		t.Errorf("告警 detail 必须写明「疑似外部写入（PEM/PFX 不同源）」且不增噪音，实际 %d 条", n)
	}
}
