package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ocoj/ddns-manager/internal/acme"
)

// T23: the one-shot startup audit must make silent failure modes visible —
// an unwired credential resolver is an error, a missing meta.dns_key is a
// warning. T23b: the read-only consistency pre-check (B5) must pre-seed the
// dedup signature so the first heartbeat does not re-report the same state.
func TestStartupAudit_WiringAndData(t *testing.T) {
	s, st, dir := newCertConsistencyServer(t)

	// (1) an ACME bundle WITHOUT dns_key → warning "凭据未登记"
	c := newCertSet(t, "sa.example.com", 1)
	const pw = "testpw123"
	acmeBundle(t, dir, "acme-sa", c, certSet{}, pw, 0, map[string]interface{}{
		"acme": true, "provider": "alidns", "domains": []string{"sa.example.com"},
	})
	if err := os.WriteFile(filepath.Join(dir, "certs", "acme-sa", "meta.json"),
		[]byte(`{"acme":true,"provider":"alidns","domains":["sa.example.com"],"pfx_password":"`+pw+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// (2) an unwired manager → error "凭据解析器未挂载"
	mgr, err := acme.New(filepath.Join(dir, "certs"), "t@example.com", ":80")
	if err != nil {
		t.Fatal(err)
	}
	if mgr.KeyLookupConfigured() {
		t.Fatal("precondition: manager must start unwired")
	}
	s.acmeMgrs = []*acme.Manager{mgr}

	s.startupAudit()

	logData := string(readFileOrNil(filepath.Join(dir, "events.log")))
	if !strings.Contains(logData, "凭据未登记") {
		t.Error("missing meta.dns_key must produce a warning audit (I15)")
	}
	if !strings.Contains(logData, "凭据解析器未挂载") {
		t.Error("an unwired credential resolver must produce an error audit (I15)")
	}
	if !strings.Contains(logData, `"status":"error"`) {
		t.Error("the unwired-resolver audit must be error level")
	}

	// (3) B5: the pre-check seeded the signature → repeating the same check must
	// not emit another line.
	before := strings.Count(logData, "证书一致性")
	b, err := st.LoadCertBundle("acme-sa")
	if err != nil {
		t.Fatal(err)
	}
	meta, err := st.LoadCertMeta("acme-sa")
	if err != nil {
		t.Fatal(err)
	}
	verdict, reason, hard := s.checkBundlePFXConsistency(b, meta)
	s.auditBundleConsistency("acme-sa", b, meta, verdict, reason, hard)

	after := strings.Count(string(readFileOrNil(filepath.Join(dir, "events.log"))), "证书一致性")
	if after != before {
		t.Errorf("startup pre-check must pre-seed the dedup signature (before=%d after=%d)", before, after)
	}
}
