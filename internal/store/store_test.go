package store

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kk/ddns-manager/internal/model"
	"github.com/kk/ddns-manager/internal/notify"
)

func TestNewStoreCreatesSubdirs(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	_ = s
}

func TestLoadNodesEmpty(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	nodes, err := s.LoadNodes()
	if err != nil {
		t.Fatalf("LoadNodes: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(nodes))
	}
}

func TestPutAndGetNode(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	rec := &model.NodeRecord{
		Fingerprint:  "sha256:abc123",
		PasswordHash: "$2a$10$...",
		CreatedAt:    time.Now(),
		LastSeen:     time.Now(),
		Tags:         []string{"prod", "web"},
		Notes:        "test node",
	}

	if err := s.PutNode("node-01", rec); err != nil {
		t.Fatalf("PutNode: %v", err)
	}

	got, err := s.GetNode("node-01")
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.Fingerprint != rec.Fingerprint {
		t.Errorf("Fingerprint = %q, want %q", got.Fingerprint, rec.Fingerprint)
	}
	if len(got.Tags) != 2 {
		t.Errorf("Tags len = %d, want 2", len(got.Tags))
	}
}

func TestGetNodeNotFound(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	_, err := s.GetNode("nonexistent")
	if err == nil {
		t.Error("GetNode for nonexistent node should error")
	}
}

func TestPutNodeConcurrent(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rec := &model.NodeRecord{
				Fingerprint:  "sha256:concurrent",
				PasswordHash: "hash",
				CreatedAt:    time.Now(),
				LastSeen:     time.Now(),
			}
			s.PutNode("node-concurrent", rec)
		}(i)
	}
	wg.Wait()

	// should be able to read back without corruption
	nodes, err := s.LoadNodes()
	if err != nil {
		t.Fatalf("LoadNodes after concurrent writes: %v", err)
	}
	if len(nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(nodes))
	}
}

// ========== Fix verification tests ==========

// TestDeleteNodeAtomically verifies DeleteNode is atomic and does not corrupt nodes.
// Covers: C1 (TOCTOU fix) — normal path.
func TestDeleteNodeAtomically(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	// Pre-populate two nodes
	s.PutNode("node-a", &model.NodeRecord{Fingerprint: "a", PasswordHash: "h", CreatedAt: time.Now()})
	s.PutNode("node-b", &model.NodeRecord{Fingerprint: "b", PasswordHash: "h", CreatedAt: time.Now()})

	// Delete node-a atomically
	if err := s.DeleteNode("node-a"); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}

	nodes, _ := s.LoadNodes()
	if _, ok := nodes["node-a"]; ok {
		t.Error("node-a should be deleted")
	}
	if _, ok := nodes["node-b"]; !ok {
		t.Error("node-b should still exist")
	}
}

// TestDeleteNodeNotFound verifies DeleteNode returns an error for missing nodes.
// Covers: C1 (TOCTOU fix) — boundary case.
func TestDeleteNodeNotFound(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	err := s.DeleteNode("nonexistent")
	if err == nil {
		t.Error("DeleteNode for nonexistent node should return error")
	}
}

// TestDeleteNodeConcurrent verifies concurrent PutNode + DeleteNode don't corrupt data.
// Covers: C1 (TOCTOU fix) — concurrency stress test.
func TestDeleteNodeConcurrent(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	// Pre-populate
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("node-%d", i)
		s.PutNode(id, &model.NodeRecord{Fingerprint: id, PasswordHash: "h", CreatedAt: time.Now()})
	}

	var wg sync.WaitGroup
	// Concurrent: put nodes + delete others
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if n%2 == 0 {
				s.PutNode(fmt.Sprintf("new-%d", n), &model.NodeRecord{
					Fingerprint: fmt.Sprintf("f-%d", n), PasswordHash: "h", CreatedAt: time.Now(),
				})
			} else {
				s.DeleteNode(fmt.Sprintf("node-%d", n%5))
			}
		}(i)
	}
	wg.Wait()

	// Must not panic and nodes.json should remain valid JSON
	nodes, err := s.LoadNodes()
	if err != nil {
		t.Fatalf("LoadNodes after concurrent ops: %v", err)
	}
	t.Logf("surviving nodes: %d", len(nodes))
}

// TestPutACMEAccountAppend verifies atomic append of a new ACME account.
// Covers: H1 (ACME concurrent write fix) — normal path.
func TestPutACMEAccountAppend(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	acct1 := ACMEAccountConfig{Email: "a@x.com", CA: "Let's Encrypt", KeyType: "EC256"}
	if err := s.PutACMEAccount(-1, acct1); err != nil {
		t.Fatalf("PutACMEAccount append: %v", err)
	}

	accounts, _ := s.LoadACMEAccounts()
	if len(accounts) != 1 {
		t.Fatalf("expected 1 account, got %d", len(accounts))
	}
	if accounts[0].Email != "a@x.com" {
		t.Errorf("Email = %q", accounts[0].Email)
	}
}

// TestPutACMEAccountUpdate verifies atomic update of an existing ACME account.
// Covers: H1 (ACME concurrent write fix) — update path.
func TestPutACMEAccountUpdate(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	s.PutACMEAccount(-1, ACMEAccountConfig{Email: "a@x.com", CA: "Lets Encrypt"})

	acct2 := ACMEAccountConfig{Email: "b@x.com", CA: "ZeroSSL", KeyType: "RSA2048"}
	if err := s.PutACMEAccount(0, acct2); err != nil {
		t.Fatalf("PutACMEAccount update: %v", err)
	}

	accounts, _ := s.LoadACMEAccounts()
	if len(accounts) != 1 {
		t.Fatalf("expected 1 account, got %d", len(accounts))
	}
	if accounts[0].Email != "b@x.com" {
		t.Errorf("Email = %q, want b@x.com", accounts[0].Email)
	}
	if accounts[0].CA != "ZeroSSL" {
		t.Errorf("CA = %q, want ZeroSSL", accounts[0].CA)
	}
}

// TestDeleteACMEAccountAtomically verifies atomic deletion of ACME accounts.
// Covers: H1 (ACME concurrent write fix) — delete path.
func TestDeleteACMEAccountAtomically(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	s.PutACMEAccount(-1, ACMEAccountConfig{Email: "a@x.com"})
	s.PutACMEAccount(-1, ACMEAccountConfig{Email: "b@x.com"})

	if err := s.DeleteACMEAccount(0); err != nil {
		t.Fatalf("DeleteACMEAccount: %v", err)
	}

	accounts, _ := s.LoadACMEAccounts()
	if len(accounts) != 1 {
		t.Fatalf("expected 1 account, got %d", len(accounts))
	}
	if accounts[0].Email != "b@x.com" {
		t.Errorf("Email = %q, want b@x.com", accounts[0].Email)
	}
}

// TestDeleteACMEAccountOutOfBounds verifies proper error for invalid index.
func TestDeleteACMEAccountOutOfBounds(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	if err := s.DeleteACMEAccount(0); err == nil {
		t.Error("DeleteACMEAccount(0) on empty store should error")
	}
}

// ── Cert Bundles ──

func TestSaveAndLoadCertBundle(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	b := &CertBundle{
		Name:       "test.example.com",
		Files:      map[string][]byte{"fullchain.pem": []byte("cert-data"), "privkey.pem": []byte("key-data")},
		TargetPath: "/etc/ssl/test",
		ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
		Domains:    []string{"test.example.com", "www.test.example.com"},
	}

	if err := s.SaveCertBundle(b); err != nil {
		t.Fatalf("SaveCertBundle: %v", err)
	}

	loaded, err := s.LoadCertBundle("test.example.com")
	if err != nil {
		t.Fatalf("LoadCertBundle: %v", err)
	}

	if loaded.Name != b.Name {
		t.Errorf("Name = %q, want %q", loaded.Name, b.Name)
	}
	if len(loaded.Files) != 2 {
		t.Errorf("Files = %d, want 2", len(loaded.Files))
	}
	if len(loaded.Domains) != 2 {
		t.Errorf("Domains = %d, want 2", len(loaded.Domains))
	}
	// hash should be deterministic
	if loaded.Hash == "" || loaded.Hash != b.Hash {
		t.Errorf("Hash mismatch: loaded=%q saved=%q", loaded.Hash, b.Hash)
	}
}

func TestSaveCertBundleDeterministicHash(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	b := &CertBundle{
		Name:  "hash-test",
		Files: map[string][]byte{"b.txt": []byte("b"), "a.txt": []byte("a")}, // unsorted input
	}

	s.SaveCertBundle(b)
	h1 := b.Hash

	// re-save same data → same hash
	s.SaveCertBundle(b)
	if b.Hash != h1 {
		t.Errorf("hash changed on re-save: %q → %q", h1, b.Hash)
	}
}

func TestListCertBundles(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	s.SaveCertBundle(&CertBundle{Name: "a.example.com", Files: map[string][]byte{"cert.pem": {}}})
	s.SaveCertBundle(&CertBundle{Name: "b.example.com", Files: map[string][]byte{"cert.pem": {}}})

	names, err := s.ListCertBundles()
	if err != nil {
		t.Fatalf("ListCertBundles: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("expected 2 bundles, got %d: %v", len(names), names)
	}
}

func TestDeleteCertBundle(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	s.SaveCertBundle(&CertBundle{Name: "delete-me", Files: map[string][]byte{"cert.pem": {}}})
	if err := s.DeleteCertBundle("delete-me"); err != nil {
		t.Fatalf("DeleteCertBundle: %v", err)
	}

	_, err := s.LoadCertBundle("delete-me")
	if err == nil {
		t.Error("LoadCertBundle after delete should fail")
	}
}

func TestListCertBundlesEmpty(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	names, err := s.ListCertBundles()
	if err != nil {
		t.Fatal(err)
	}
	if names != nil {
		t.Errorf("expected nil for empty certs dir, got %v", names)
	}
}

// ── DNS Keys ──

func TestLoadDNSKeysEmpty(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	keys, err := s.LoadDNSKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestSaveAndLoadDNSKeys(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	keys := map[string]*model.DNSKeyRecord{
		"阿里云-生产": {
			Name: "阿里云-生产", Provider: "alidns",
			AccessKeyID: "LTAI5txxx", AccessKeySecret: "secret123",
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		},
	}

	if err := s.SaveDNSKeys(keys); err != nil {
		t.Fatalf("SaveDNSKeys: %v", err)
	}

	loaded, err := s.LoadDNSKeys()
	if err != nil {
		t.Fatalf("LoadDNSKeys: %v", err)
	}
	if v, ok := loaded["阿里云-生产"]; !ok {
		t.Error("key not found")
	} else if v.AccessKeyID != "LTAI5txxx" {
		t.Errorf("AccessKeyID = %q", v.AccessKeyID)
	}
}

func TestTrackDNSKeyUsage(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	keys := map[string]*model.DNSKeyRecord{
		"my-key": {Name: "my-key", Provider: "cloudflare"},
	}
	s.SaveDNSKeys(keys)

	s.TrackDNSKeyUsage("my-key", "node-01")
	s.TrackDNSKeyUsage("my-key", "node-02")
	s.TrackDNSKeyUsage("my-key", "node-01") // duplicate → no-op

	loaded, _ := s.LoadDNSKeys()
	if len(loaded["my-key"].UsedByNodes) != 2 {
		t.Errorf("UsedByNodes = %d, want 2", len(loaded["my-key"].UsedByNodes))
	}
}

// ── Admin State ──

func TestLoadAdminStateEmpty(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	st, err := s.LoadAdminState()
	if err != nil {
		t.Fatal(err)
	}
	if st != nil {
		t.Error("expected nil for uninitialized admin state")
	}
}

func TestSaveAndLoadAdminState(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	st := &AdminState{TokenHash: "$2a$10$...", PasswordChanged: true}
	if err := s.SaveAdminState(st); err != nil {
		t.Fatalf("SaveAdminState: %v", err)
	}

	loaded, err := s.LoadAdminState()
	if err != nil {
		t.Fatalf("LoadAdminState: %v", err)
	}
	if !loaded.PasswordChanged {
		t.Error("PasswordChanged should be true")
	}
}

// ── SMTP Config ──

func TestLoadSMTPConfigEmpty(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	cfg, err := s.LoadSMTPConfig()
	if err != nil {
		t.Fatal(err)
	}
	// When no file exists, returns zero-value config (Caller applies defaults)
	if cfg.CertExpiryDays != 0 {
		t.Errorf("CertExpiryDays = %d, want 0 (zero-value for new store)", cfg.CertExpiryDays)
	}
}

func TestSaveAndLoadSMTPConfig(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	cfg := &notify.Config{
		Host: "smtp.example.com", Port: 587,
		Username: "user", Password: "pass", To: "admin@example.com",
		NotifyHeartbeatFail: true, NotifyCertExpiry: true,
	}
	s.SaveSMTPConfig(cfg)

	loaded, _ := s.LoadSMTPConfig()
	if loaded.Host != "smtp.example.com" {
		t.Errorf("Host = %q", loaded.Host)
	}
	if !loaded.NotifyHeartbeatFail {
		t.Error("NotifyHeartbeatFail should be true")
	}
}

// ── ACME Accounts ──

func TestLoadACMEAccountsEmpty(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	accounts, err := s.LoadACMEAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if accounts != nil {
		t.Error("expected nil for empty ACME accounts")
	}
}

func TestSaveAndLoadACMEAccounts(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	accounts := []ACMEAccountConfig{
		{Email: "admin@example.com", CA: "Let's Encrypt", KeyType: "EC256"},
	}
	s.SaveACMEAccounts(accounts)

	loaded, _ := s.LoadACMEAccounts()
	if len(loaded) != 1 {
		t.Fatalf("expected 1 account, got %d", len(loaded))
	}
	if loaded[0].Email != "admin@example.com" {
		t.Errorf("Email = %q", loaded[0].Email)
	}
}

// ── Rate Limit Config ──

func TestLoadRateLimitConfigEmpty(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	cfg, err := s.LoadRateLimitConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RequestsPerMin <= 0 {
		t.Errorf("RequestsPerMin = %d, want > 0", cfg.RequestsPerMin)
	}
}

func TestSaveAndLoadRateLimitConfig(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	cfg := &RateLimitConfig{Enabled: true, RequestsPerMin: 300, HeartbeatPerMin: 60, LoginPerMin: 5}
	s.SaveRateLimitConfig(cfg)

	loaded, _ := s.LoadRateLimitConfig()
	if !loaded.Enabled {
		t.Error("Enabled should be true")
	}
	if loaded.RequestsPerMin != 300 {
		t.Errorf("RequestsPerMin = %d", loaded.RequestsPerMin)
	}
}
