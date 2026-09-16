package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── fake acme.sh harness ──
//
// The real acme.sh contract (env injection, --install-cert argument shape,
// exit-0-without-change) cannot be proven with unit-level stubs, so these tests
// drive the Manager against a fake script that records its argv and environment.
// FAKE_* variables are injected with t.Setenv, which puts them into os.Environ()
// and therefore into the environment the Manager forwards to the child.

func fakeAcmeSh(t *testing.T, dir string) string {
	t.Helper()
	script := filepath.Join(dir, "fake-acme.sh")
	body := `#!/bin/sh
if [ -n "$FAKE_LOG" ]; then echo run >> "$FAKE_LOG"; fi
printf '%s\n' "$@" > "$FAKE_ARGS"
env > "$FAKE_ENV"
printf 'RESOLVED_HOME=%s\nRESOLVED_LE_WORKING_DIR=%s\n' "$HOME" "$LE_WORKING_DIR" >> "$FAKE_ENV"
if [ -n "$FAKE_REPLACE" ]; then cp "$FAKE_REPLACE" ./fullchain.pem; fi
if [ -n "$FAKE_SKIP" ]; then
  echo "Skipping. Next renewal time is: 2026-10-06T06:44:45Z"
  echo "Add '--force' to force renewal."
  exit 2
fi
exit "${FAKE_EXIT:-0}"
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

type fakeHarness struct {
	argsFile string
	envFile  string
}

// setupHarness creates a manager whose acme.sh is the fake script, plus a test
// cert directory containing one ACME certificate.
func setupHarness(t *testing.T) (*Manager, fakeHarness, string) {
	t.Helper()
	root := t.TempDir()
	h := fakeHarness{argsFile: filepath.Join(root, "args.txt"), envFile: filepath.Join(root, "env.txt")}
	t.Setenv("FAKE_ARGS", h.argsFile)
	t.Setenv("FAKE_ENV", h.envFile)
	t.Setenv("FAKE_MARKER", "inherited")
	script := fakeAcmeSh(t, root)

	certsDir := filepath.Join(root, "certs")
	certDir := filepath.Join(certsDir, "x.example.com")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := selfSigned(t, "x.example.com")
	if err := os.WriteFile(filepath.Join(certDir, "fullchain.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "privkey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	meta := `{"acme":true,"provider":"alidns","dns_key":"权威","domains":["x.example.com"]}`
	if err := os.WriteFile(filepath.Join(certDir, "meta.json"), []byte(meta), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := New(certsDir, "test@example.com", ":80")
	if err != nil {
		t.Fatal(err)
	}
	// v1.6.71 N1: acme.sh home 必须显式固定，否则所有 acme.sh 调用都会 fail-fast。
	// 这里让 LE_WORKING_DIR（显式来源）指向一个含 account.conf 的目录。
	homeDir := filepath.Join(root, "acme-home")
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(homeDir, "account.conf"), []byte("SAVED_MARKER=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LE_WORKING_DIR", homeDir)
	m.SetAcmeShPath(script) // test-only: point at the fake
	if err := m.ResolveAcmeHome(true); err != nil {
		t.Fatalf("resolve acme home: %v", err)
	}
	return m, h, root
}

// setupHarnessNoHome 返回一个**无法确定 ACME home** 的 manager（用于 fail-fast 用例）。
func setupHarnessNoHome(t *testing.T) (*Manager, fakeHarness, string) {
	t.Helper()
	root := t.TempDir()
	h := fakeHarness{argsFile: filepath.Join(root, "args.txt"), envFile: filepath.Join(root, "env.txt")}
	t.Setenv("FAKE_ARGS", h.argsFile)
	t.Setenv("FAKE_ENV", h.envFile)
	t.Setenv("FAKE_MARKER", "inherited")
	t.Setenv("LE_WORKING_DIR", "") // 清空显式来源
	t.Setenv("HOME", "")           // 清空 HOME ⇒ ④ 不可用
	script := fakeAcmeSh(t, root)

	certsDir := filepath.Join(root, "certs")
	certDir := filepath.Join(certsDir, "x.example.com")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := selfSigned(t, "x.example.com")
	if err := os.WriteFile(filepath.Join(certDir, "fullchain.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "privkey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "meta.json"),
		[]byte(`{"acme":true,"provider":"alidns","dns_key":"权威","domains":["x.example.com"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := New(certsDir, "test@example.com", ":80")
	if err != nil {
		t.Fatal(err)
	}
	m.SetAcmeShPath(script)
	// 故意不调用 ResolveAcmeHome：解析失败必须体现在调用点
	if err := m.ResolveAcmeHome(true); err == nil {
		t.Fatal("预期 home 解析失败，但成功了")
	}
	return m, h, root
}

// pinTestHome 为测试中直接构造的 Manager 固定一个可解析的 ACME home（v1.6.71 N1）。
// 不固定 home 时所有 acme.sh 调用都会 fail-fast（这正是 T41d 要验证的行为）。
func pinTestHome(t *testing.T, m *Manager, root string) string {
	t.Helper()
	homeDir := filepath.Join(root, "acme-home")
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(homeDir, "account.conf"), []byte("SAVED_MARKER=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LE_WORKING_DIR", homeDir)
	if err := m.ResolveAcmeHome(true); err != nil {
		t.Fatalf("resolve acme home: %v", err)
	}
	return homeDir
}

func selfSigned(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	return selfSignedDays(t, cn, 90)
}

// selfSignedDays builds a self-signed certificate valid for the given number of
// days (a small value makes the certificate "due" for the 30-day threshold).
func selfSignedDays(t *testing.T, cn string, days int) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(days) * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func readOrFatal(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// requireAcmeShInvoked fails unless the fake acme.sh actually ran.
//
// Rationale (fix report §6.4): two tests were once vacuous — the certificate was
// not yet due, renewOne returned from the not-due pre-check, and the assertions
// were satisfied without acme.sh ever being executed. Any test that asserts the
// *result* of an acme.sh invocation must first witness that the invocation
// happened; this helper makes that convention explicit and reusable.
func requireAcmeShInvoked(t *testing.T, h fakeHarness) {
	t.Helper()
	if _, err := os.Stat(h.argsFile); err != nil {
		t.Fatalf("vacuous test: acme.sh was never invoked (%v)", err)
	}
}

// argvLines splits the recorded argv (the fake script writes one argument per line).
func argvLines(args string) []string {
	return strings.Split(strings.TrimRight(args, "\n"), "\n")
}

// countArg counts exact argv entries equal to want.
func countArg(args, want string) int {
	n := 0
	for _, a := range argvLines(args) {
		if a == want {
			n++
		}
	}
	return n
}

func withLookup(m *Manager) {
	m.SetDNSKeyLookup(func() map[string]*DNSProvider {
		return map[string]*DNSProvider{
			"权威": {Name: "alidns", KeyID: "AK_NEW", KeySecret: "SK_NEW", KeyName: "权威"},
		}
	})
}

// T5: end-to-end — the renewal path actually injects the resolved credentials.
func TestRenewByName_InjectsCredentials(t *testing.T) {
	m, h, _ := setupHarness(t)
	withLookup(m)

	if got := m.RenewByName(context.Background(), "x.example.com"); got {
		t.Fatal("fake acme.sh does not change the cert, so this must not report renewed")
	}

	env := readOrFatal(t, h.envFile)
	if !strings.Contains(env, "Ali_Key=AK_NEW") || !strings.Contains(env, "Ali_Secret=SK_NEW") {
		t.Error("renewal must inject the resolved DNS credentials (main fix)")
	}
	if !strings.Contains(env, "HOME=") || !strings.Contains(env, "FAKE_MARKER=inherited") {
		t.Error("injected environment must be based on os.Environ() (I2)")
	}
	args := readOrFatal(t, h.argsFile)
	if !strings.Contains(args, "--renew") || !strings.Contains(args, "--force") || !strings.Contains(args, "-d") {
		t.Errorf("unexpected renew argv: %q", args)
	}
}

// T6: without a resolver, cmd.Env must be left untouched so the child inherits
// the parent environment byte-for-byte (I1).
func TestRenewByName_NoLookupKeepsParentEnv(t *testing.T) {
	m, h, _ := setupHarness(t)

	m.RenewByName(context.Background(), "x.example.com")

	env := readOrFatal(t, h.envFile)
	if strings.Contains(env, "Ali_Key=") {
		t.Error("no resolver → no credential injection (I1)")
	}
	if !strings.Contains(env, "FAKE_MARKER=inherited") || !strings.Contains(env, "HOME=") {
		t.Error("parent environment must be preserved when no injection happens (I1/I2)")
	}
}

// T7: a key whose provider does not match meta.provider must not be injected;
// the renewal still runs, relying on acme.sh's own account.conf.
func TestRenewByName_ProviderMismatch_NoInjection(t *testing.T) {
	m, h, _ := setupHarness(t)
	m.SetDNSKeyLookup(func() map[string]*DNSProvider {
		return map[string]*DNSProvider{"CF": {Name: "cloudflare", KeyID: "CFTOKEN", KeyName: "CF"}}
	})

	m.RenewByName(context.Background(), "x.example.com")

	env := readOrFatal(t, h.envFile)
	if strings.Contains(env, "Ali_Key=") || strings.Contains(env, "CF_Token=") {
		t.Error("a provider-mismatched key must never be injected (I4)")
	}
}

// T8/T9: S4 — exit 0 without a content change is not success; and B1 — the
// reason must reach LastError() so the UI does not fall back to a 404.
func TestRenewByName_NotReplaced_ReportsReason(t *testing.T) {
	m, h, root := setupHarness(t)
	withLookup(m)

	// Case 1: script exits 0 but fullchain.pem is untouched.
	if m.RenewByName(context.Background(), "x.example.com") {
		t.Fatal("unchanged certificate must not be reported as renewed (S4)")
	}
	if err := m.LastError(); err == nil {
		t.Error("B1: KindNotReplaced must record lastRenewErr, otherwise the UI shows a misleading 404")
	} else if !strings.Contains(err.Error(), "未变化") {
		t.Errorf("lastRenewErr should explain the real cause, got %v", err)
	}

	// Case 2: script replaces fullchain.pem → genuine success, error cleared.
	newCert, _ := selfSigned(t, "x.example.com")
	replacement := filepath.Join(root, "replacement.pem")
	if err := os.WriteFile(replacement, newCert, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_REPLACE", replacement)
	if !m.RenewByName(context.Background(), "x.example.com") {
		t.Fatal("a real content change must be reported as renewed")
	}
	if err := m.LastError(); err != nil {
		t.Errorf("successful renewal must clear lastRenewErr, got %v", err)
	}
	_ = h
}

// T10/S6: the DNS key name is persisted into meta.json as valid JSON even when
// it contains a quote and non-ASCII characters.
func TestIssueWritesDNSKeyToMeta_JSONSafe(t *testing.T) {
	root := t.TempDir()
	h := fakeHarness{argsFile: filepath.Join(root, "args.txt"), envFile: filepath.Join(root, "env.txt")}
	t.Setenv("FAKE_ARGS", h.argsFile)
	t.Setenv("FAKE_ENV", h.envFile)
	script := fakeAcmeSh(t, root)

	m, err := New(filepath.Join(root, "certs"), "test@example.com", ":80")
	if err != nil {
		t.Fatal(err)
	}
	m.acmeShPath = script
	pinTestHome(t, m, root) // v1.6.71 N1: 固定 ACME home

	weirdName := `怪"名\号`
	if _, err := m.issueViaAcmeSh(context.Background(), []string{"y.example.com"},
		DNSProvider{Name: "alidns", KeyID: "AK", KeySecret: "SK", KeyName: weirdName},
		m.acmeShPath, m.ca, m.keyType); err != nil { // v1.6.72 P0-F1: 新增快照参数
		t.Fatalf("issueViaAcmeSh: %v", err)
	}

	raw := []byte(readOrFatal(t, filepath.Join(root, "certs", "y.example.com", "meta.json")))
	var meta map[string]interface{}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("meta.json must stay valid JSON even with a hostile key name: %v\n%s", err, raw)
	}
	if meta["dns_key"] != weirdName {
		t.Errorf("dns_key = %v, want %q", meta["dns_key"], weirdName)
	}
	if meta["acme"] != true {
		t.Error("acme flag must be preserved")
	}
}

// T13/S7: --install-cert must carry the bundle paths and the primary domain, and
// must NOT inject credentials (I11).
func TestInstallCert_PassesBundlePaths(t *testing.T) {
	m, h, root := setupHarness(t)
	target := filepath.Join(root, "bundle", "acme-x.example.com")

	if err := m.InstallCert(context.Background(), "x.example.com", target); err != nil {
		t.Fatalf("InstallCert: %v", err)
	}
	if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
		t.Errorf("InstallCert must create the target directory: %v", err)
	}

	requireAcmeShInvoked(t, h)
	args := readOrFatal(t, h.argsFile)
	for _, want := range []string{
		"--install-cert",
		"-d\nx.example.com",
		"--cert-file\n" + filepath.Join(target, "cert.pem"),
		"--key-file\n" + filepath.Join(target, "privkey.pem"),
		"--fullchain-file\n" + filepath.Join(target, "fullchain.pem"),
	} {
		if !strings.Contains(args, want) {
			t.Errorf("--install-cert argv missing %q\ngot:\n%s", want, args)
		}
	}
	// RT2a/RT2b: acme.sh resolves the certificate name from the FIRST -d. With a
	// non-cert-name first argument it fails outright; with another *valid* cert
	// name it exits 0 while silently installing THAT certificate. So passing more
	// than one -d is not merely redundant — it can install the wrong cert without
	// any error. Guard the shape at the argv level (cheaper and stricter than a
	// runtime check, and it survives future refactors of the caller).
	if n := countArg(args, "-d"); n != 1 {
		t.Errorf("InstallCert must pass exactly one -d (primary domain), got %d:\n%s", n, args)
	}

	env := readOrFatal(t, h.envFile)
	if strings.Contains(env, "Ali_Key=") {
		t.Error("InstallCert must not inject credentials (I11)")
	}
	if !strings.Contains(env, "HOME=") {
		t.Error("InstallCert must inherit HOME so acme.sh can find ~/.acme.sh (I11)")
	}
}

// RT1（回归）: acme.sh v3.1.4 在"未到自身续期时间"时返回非零退出码（实测 = 2）
// 并打印 "Skipping. Next renewal time is: ..."。这必须映射为 KindSkipped，
// 而不是记一条误导性的失败 —— 否则每 24h ticker 都会输出 error。
func TestRenewByName_AcmeShSkip_IsSkippedNotFailed(t *testing.T) {
	m, h, root := setupHarness(t)
	withLookup(m)
	makeCertDue(t, root, 10) // else the not-due pre-check skips before acme.sh runs
	t.Setenv("FAKE_SKIP", "1")

	out := m.renewOne(context.Background(), "x.example.com", false, m.loadDNSKeys())
	requireAcmeShInvoked(t, h)
	if out.Kind != KindSkipped {
		t.Fatalf("acme.sh skip must be KindSkipped, got %v (err=%v)", out.Kind, out.Err)
	}
	if err := m.LastError(); err != nil {
		t.Errorf("a skip must not be recorded as an error, got %v", err)
	}
}

// T15（I13）: the same certificate must not be renewed concurrently. The second
// caller waits for the lock, then re-checks expiry — and since the first caller
// already installed a long-lived certificate, it must return KindSkipped
// WITHOUT invoking acme.sh a second time.
func TestRenewSerializedPerCert_PostLockRecheckSkips(t *testing.T) {
	m, h, root := setupHarness(t)
	certDir := filepath.Join(root, "certs", "x.example.com")

	// Make the certificate "due" (10 days left < 30-day threshold).
	dueCert, _ := selfSignedDays(t, "x.example.com", 10)
	if err := os.WriteFile(filepath.Join(certDir, "fullchain.pem"), dueCert, 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(root, "fresh.pem")
	freshCert, _ := selfSignedDays(t, "x.example.com", 90)
	if err := os.WriteFile(fresh, freshCert, 0o600); err != nil {
		t.Fatal(err)
	}

	// Simulate a concurrent renewal that is already in progress: hold the
	// per-certificate lock, then release it after installing the fresh cert.
	unlock := m.lockCert(certDir)
	done := make(chan RenewOutcome, 1)
	go func() {
		done <- m.renewOne(context.Background(), "x.example.com", false, m.loadDNSKeys())
	}()

	time.Sleep(100 * time.Millisecond) // let the goroutine reach the lock
	if err := os.WriteFile(filepath.Join(certDir, "fullchain.pem"), freshCert, 0o600); err != nil {
		t.Fatal(err)
	}
	unlock()

	select {
	case out := <-done:
		if out.Kind != KindSkipped {
			t.Errorf("post-lock re-check must skip an already-renewed cert, got %v (err=%v)", out.Kind, out.Err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("renewOne did not return")
	}

	// The second caller must not have executed acme.sh at all.
	if _, err := os.Stat(h.argsFile); err == nil {
		t.Error("acme.sh must not be invoked when the certificate was renewed while waiting for the lock")
	}
}

// makeCertDue rewrites the harness certificate so it expires in `days` days.
// Without this, force=false returns KindSkipped from the not-due pre-check and
// never reaches the acme.sh invocation — which would make a test vacuous.
func makeCertDue(t *testing.T, root string, days int) {
	t.Helper()
	certDir := filepath.Join(root, "certs", "x.example.com")
	certPEM, keyPEM := selfSignedDays(t, "x.example.com", days)
	if err := os.WriteFile(filepath.Join(certDir, "fullchain.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "privkey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeAcmeCert creates a due (10-day) ACME certificate directory with meta.
func writeAcmeCert(t *testing.T, certsDir, name string, days int) {
	t.Helper()
	d := filepath.Join(certsDir, name)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := selfSignedDays(t, name, days)
	if err := os.WriteFile(filepath.Join(d, "fullchain.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "privkey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	meta := `{"acme":true,"provider":"alidns","dns_key":"权威","domains":["` + name + `"]}`
	if err := os.WriteFile(filepath.Join(d, "meta.json"), []byte(meta), 0o600); err != nil {
		t.Fatal(err)
	}
}

// T14（D12）: RenewWithOutcomes must not share mutable state between calls —
// concurrent invocations each get their own complete, correctly-labelled result
// set (run under -race).
func TestRenewWithOutcomes_NoSharedState(t *testing.T) {
	root := t.TempDir()
	h := fakeHarness{argsFile: filepath.Join(root, "args.txt"), envFile: filepath.Join(root, "env.txt")}
	t.Setenv("FAKE_ARGS", h.argsFile)
	t.Setenv("FAKE_ENV", h.envFile)
	freshCert, _ := selfSignedDays(t, "shared.example.com", 90)
	fresh := filepath.Join(root, "fresh.pem")
	if err := os.WriteFile(fresh, freshCert, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_REPLACE", fresh)
	script := fakeAcmeSh(t, root)

	certsDir := filepath.Join(root, "certs")
	names := []string{"a.example.com", "b.example.com", "c.example.com"}
	for _, n := range names {
		writeAcmeCert(t, certsDir, n, 10) // due: 10 days left < 30-day threshold
	}
	m, err := New(certsDir, "test@example.com", ":80")
	if err != nil {
		t.Fatal(err)
	}
	m.acmeShPath = script
	pinTestHome(t, m, root) // v1.6.71 N1: 固定 ACME home

	const workers = 8
	results := make([][]RenewOutcome, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = m.RenewWithOutcomes(context.Background())
		}(i)
	}
	wg.Wait()

	for i, rs := range results {
		if len(rs) != len(names) {
			t.Errorf("worker %d: got %d outcomes, want %d (shared state?)", i, len(rs), len(names))
			continue
		}
		seen := map[string]bool{}
		for _, o := range rs {
			if o.Name == "" {
				t.Errorf("worker %d: outcome with empty name (shared state?)", i)
				continue
			}
			if seen[o.Name] {
				t.Errorf("worker %d: duplicate outcome for %s (shared state?)", i, o.Name)
			}
			seen[o.Name] = true
		}
		for _, n := range names {
			if !seen[n] {
				t.Errorf("worker %d: missing outcome for %s", i, n)
			}
		}
	}

	renewed := false
	for _, rs := range results {
		for _, o := range rs {
			if o.Kind == KindOK {
				renewed = true
			}
		}
	}
	if !renewed {
		t.Error("expected at least one KindOK across the workers")
	}
}

// B8（验收加固）: the skip classification must not swallow a run that really did
// something. If acme.sh prints the skip wording (non-zero exit) but the
// certificate content DID change, the run must stay a failure — better one extra
// error than a silently missed renewal.
func TestRenewByName_AcmeShSkip_MarkerButContentChanged_IsFailed(t *testing.T) {
	m, h, root := setupHarness(t)
	withLookup(m)
	makeCertDue(t, root, 10) // else the not-due pre-check skips before acme.sh runs
	newCert, _ := selfSigned(t, "x.example.com")
	replacement := filepath.Join(root, "replaced.pem")
	if err := os.WriteFile(replacement, newCert, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_SKIP", "1")            // prints the skip wording and exits 2
	t.Setenv("FAKE_REPLACE", replacement) // …while still replacing the cert

	out := m.renewOne(context.Background(), "x.example.com", false, m.loadDNSKeys())
	requireAcmeShInvoked(t, h)
	if out.Kind != KindFailed {
		t.Errorf("skip wording with changed content must be KindFailed, got %v (err=%v)", out.Kind, out.Err)
	}
	if err := m.LastError(); err == nil {
		t.Error("a real failure must be recorded in lastRenewErr")
	}
}

// ── v1.6.71 N1 ──
// T34 [D]: 父环境**无 HOME**（模拟 systemd）时，子进程仍必须看到被显式固定的
// home 与"home 的父目录"作为 HOME（I26/I27）。修复前该场景下 acme.sh 会落到
// /.acme.sh —— 本用例在修复前必然 FAIL。
// 断言取 fake acme.sh **shell 内实际解析出的值**（RESOLVED_*），而非仅 dump 的 env 行。
func TestT34_Renew_PinnedHomeInChildEnv(t *testing.T) {
	m, h, root := setupHarness(t)
	homeDir := filepath.Join(root, "acme-home")

	freshCert, _ := selfSignedDays(t, "x.example.com", 90)
	fresh := filepath.Join(root, "fresh.pem")
	if err := os.WriteFile(fresh, freshCert, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_REPLACE", fresh)
	t.Setenv("HOME", "") // 模拟 systemd：父环境没有 HOME

	out := m.renewOne(context.Background(), "x.example.com", true, nil)
	if out.Kind != KindOK {
		t.Fatalf("renew failed: kind=%v err=%v", out.Kind, out.Err)
	}
	raw, err := os.ReadFile(h.envFile)
	if err != nil {
		t.Fatalf("fake acme.sh 未被调用（缺少 env dump）: %v", err)
	}
	env := string(raw)
	wantParent := filepath.Dir(homeDir)
	for _, want := range []string{
		"LE_WORKING_DIR=" + homeDir,
		"HOME=" + wantParent,
		"RESOLVED_HOME=" + wantParent,
		"RESOLVED_LE_WORKING_DIR=" + homeDir,
	} {
		if !strings.Contains(env, want) {
			t.Errorf("子进程环境缺少 %q\n--- env dump ---\n%s", want, env)
		}
	}
}

// T39: InstallCert 必须显式设置环境（固定 home）且**不含凭据**（S15）。
func TestT39_InstallCert_EnvHasHomeAndNoCredentials(t *testing.T) {
	m, h, root := setupHarness(t)
	homeDir := filepath.Join(root, "acme-home")
	t.Setenv("HOME", "")

	target := filepath.Join(root, "bundle")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := m.InstallCert(context.Background(), "x.example.com", target); err != nil {
		t.Fatalf("InstallCert: %v", err)
	}
	raw, err := os.ReadFile(h.envFile)
	if err != nil {
		t.Fatal(err)
	}
	env := string(raw)
	if !strings.Contains(env, "LE_WORKING_DIR="+homeDir) {
		t.Error("InstallCert 必须固定 LE_WORKING_DIR（否则 acme.sh 定位不到 home）")
	}
	if !strings.Contains(env, "RESOLVED_HOME="+filepath.Dir(homeDir)) {
		t.Error("InstallCert 的子进程 HOME 应为 home 的父目录")
	}
	for _, banned := range []string{"Ali_Key=", "Ali_Secret=", "CF_Token="} {
		if strings.Contains(env, banned) {
			t.Errorf("InstallCert 不得注入凭据：%s", banned)
		}
	}
}

// T41d [D]: home 不可判定 ⇒ fail-fast：不得调用 acme.sh，且不得创建任何目录。
func TestT41d_Renew_NoHome_FailFastAndAcmeShNeverCalled(t *testing.T) {
	m, h, _ := setupHarnessNoHome(t)

	out := m.renewOne(context.Background(), "x.example.com", true, nil)
	if out.Kind != KindFailed {
		t.Fatalf("home 不可判定应为 KindFailed（Q5），got %v", out.Kind)
	}
	if out.Err == nil {
		t.Error("必须给出失败原因（经 B1 可达 UI）")
	}
	if _, err := os.Stat(h.argsFile); err == nil {
		t.Fatal("acme.sh 不得被调用 —— fail-fast 必须发生在 exec 之前")
	}
}
