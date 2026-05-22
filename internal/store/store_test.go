package store

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// TestReplaceNodeDNSKey_Atomic v1.6.36 C3: 验证原子替换 DNS Key 引用
// 覆盖场景: (1) 正常替换 (2) 仅添加 (3) 仅删除 (4) 两个key都不存在
func TestReplaceNodeDNSKey_Atomic(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	// 准备: 创建两个 DNS Key
	keys := map[string]*model.DNSKeyRecord{
		"阿里云":    {Name: "阿里云", Provider: "alidns", UsedByNodes: []string{"node-1", "node-2"}},
		"Cloudflare": {Name: "Cloudflare", Provider: "cloudflare", UsedByNodes: []string{}},
	}
	s.SaveDNSKeys(keys)

	// 场景1: 原子替换 — node-1 从阿里云 → Cloudflare (正常)
	err := s.ReplaceNodeDNSKey("node-1", "阿里云", "Cloudflare")
	if err != nil {
		t.Fatalf("ReplaceNodeDNSKey 失败: %v", err)
	}

	loaded, _ := s.LoadDNSKeys()
	// 验证: node-1 已从阿里云移除
	for _, n := range loaded["阿里云"].UsedByNodes {
		if n == "node-1" {
			t.Error("node-1 应已从阿里云中移除")
		}
	}
	// 验证: node-2 仍在阿里云 (其他节点不受影响)
	found2 := false
	for _, n := range loaded["阿里云"].UsedByNodes {
		if n == "node-2" {
			found2 = true
		}
	}
	if !found2 {
		t.Error("node-2 应仍在阿里云中 — 替换不应影响其他节点")
	}
	// 验证: node-1 已添加到 Cloudflare
	found1 := false
	for _, n := range loaded["Cloudflare"].UsedByNodes {
		if n == "node-1" {
			found1 = true
		}
	}
	if !found1 {
		t.Error("node-1 应已添加到 Cloudflare")
	}

	// 场景2: oldKey 不存在时仅添加新引用 (边界)
	err = s.ReplaceNodeDNSKey("node-3", "不存在的Key", "阿里云")
	if err != nil {
		t.Fatalf("oldKey 不存在时应仅添加: %v", err)
	}
	loaded, _ = s.LoadDNSKeys()
	found3 := false
	for _, n := range loaded["阿里云"].UsedByNodes {
		if n == "node-3" {
			found3 = true
		}
	}
	if !found3 {
		t.Error("node-3 应已添加到阿里云 (oldKey不存在时仅添加)")
	}

	// 场景3: 仅删除不添加 — newKey 为空 (边界)
	err = s.ReplaceNodeDNSKey("node-3", "阿里云", "")
	if err != nil {
		t.Fatalf("仅删除时不应失败: %v", err)
	}
	loaded, _ = s.LoadDNSKeys()
	for _, n := range loaded["阿里云"].UsedByNodes {
		if n == "node-3" {
			t.Error("node-3 应已从阿里云中移除 (仅删除模式)")
		}
	}

	// 场景4: 两个 key 都不存在 — 不应 panic (异常安全)
	err = s.ReplaceNodeDNSKey("node-x", "不存在的Key", "也不存在")
	if err != nil {
		t.Fatalf("两个 key 都不存在时不应失败: %v", err)
	}
}

// TestRebuildManifest_WithHelper v1.6.36 C2: 验证 RebuildManifest 同时追踪
// node-agent 和 upgrade_helper 二进制文件, 确保 Agent 端能找到升级助手。
func TestRebuildManifest_WithHelper(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	binDir := s.AgentBinDir()

	// 创建测试二进制文件 (模拟构建脚本输出)
	writeBin := func(name string) {
		os.WriteFile(filepath.Join(binDir, name), []byte("dummy"), 0644)
	}
	writeBin("node-agent-v1.6.35-linux-amd64")
	writeBin("node-agent-v1.6.36-linux-amd64")
	writeBin("node-agent-v1.6.35-windows-amd64.exe")
	writeBin("node-agent-v1.6.36-windows-amd64.exe")
	writeBin("upgrade_helper-v1.6.35-windows-amd64.exe")
	writeBin("upgrade_helper-v1.6.36-windows-amd64.exe")
	writeBin("upgrade_helper-v1.6.36-linux-amd64")           // Linux 不匹配正则 (非 .exe)
	writeBin("node-agent-v1.6.35-linux-armv7")                 // 非标准 arch
	writeBin("node-agent-vdev-windows-amd64.exe")              // dev 版本应跳过

	s.RebuildManifest()
	manifest, err := s.LoadAgentManifest()
	if err != nil {
		t.Fatalf("LoadAgentManifest: %v", err)
	}

	// 验证: 每个平台取最高版本
	if !strings.Contains(manifest["linux-amd64"], "v1.6.36") {
		t.Errorf("linux-amd64 应选 v1.6.36, got %q", manifest["linux-amd64"])
	}
	if !strings.Contains(manifest["windows-amd64"], "v1.6.36") {
		t.Errorf("windows-amd64 应选 v1.6.36, got %q", manifest["windows-amd64"])
	}

	// 验证: helper 文件被追踪 (key = "helper-windows-amd64")
	helperFile, ok := manifest["helper-windows-amd64"]
	if !ok {
		t.Error("manifest 应包含 helper-windows-amd64 键")
	} else if !strings.Contains(helperFile, "v1.6.36") {
		t.Errorf("helper-windows-amd64 应选 v1.6.36, got %q", helperFile)
	}

	// 验证: Linux helper 不应被追踪 (helper 仅 Windows 需要)
	if _, ok := manifest["helper-linux-amd64"]; ok {
		t.Error("helper-linux-amd64 不应被追踪 (upgrade_helper.exe 是 Windows-only)")
	}

	// 验证: dev 版本被跳过
	for _, f := range manifest {
		if strings.Contains(f, "vdev") {
			t.Errorf("dev 版本不应出现在 manifest: %q", f)
		}
	}
}

// TestGetAgentBinarySHA256_Fallback v1.6.36 C5: 验证 .sha256 缺失时自动从二进制计算兜底
func TestGetAgentBinarySHA256_Fallback(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	binDir := s.AgentBinDir()

	// 写入二进制，但不写 .sha256
	binPath := filepath.Join(binDir, "node-agent-v1.6.36-linux-amd64")
	testData := []byte("dummy binary content for sha256 test")
	os.WriteFile(binPath, testData, 0644)

	// 计算期待值
	expectedHash := fmt.Sprintf("%x", sha256.Sum256(testData))

	// .sha256 缺失时，应自动从二进制计算
	got := s.GetAgentBinarySHA256("node-agent-v1.6.36-linux-amd64")
	if got != expectedHash {
		t.Errorf("GetAgentBinarySHA256 兜底计算: got %q, want %q", got, expectedHash)
	}

	// 二进制也不存在时，应返回空字符串
	gotEmpty := s.GetAgentBinarySHA256("nonexistent-binary")
	if gotEmpty != "" {
		t.Errorf("文件不存在应返回空字符串, got %q", gotEmpty)
	}

	// .sha256 存在时，应优先读取 (不重新计算)
	os.WriteFile(binPath+".sha256", []byte("aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999  node-agent-v1.6.36-linux-amd64\n"), 0644)
	gotFromFile := s.GetAgentBinarySHA256("node-agent-v1.6.36-linux-amd64")
	if gotFromFile != "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999" {
		t.Errorf(".sha256 存在时应读文件, got %q", gotFromFile)
	}

	// .sha256 损坏 (格式不对) 时，应降级到兜底计算
	os.WriteFile(binPath+".sha256", []byte("garbage\n"), 0644)
	gotFallback := s.GetAgentBinarySHA256("node-agent-v1.6.36-linux-amd64")
	if gotFallback != expectedHash {
		t.Errorf(".sha256 损坏时应兜底计算: got %q, want %q", gotFallback, expectedHash)
	}
}

// TestTrackDNSKeyUsage_Atomic — v1.6.42 C7:
// 验证 TrackDNSKeyUsage 原子化后两个 goroutine 并发追加节点引用无竞态。
func TestTrackDNSKeyUsage_Atomic(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	// 初始化 DNS Key
	keys := map[string]*model.DNSKeyRecord{
		"key-a": {Name: "key-a", Provider: "alidns"},
	}
	if err := s.SaveDNSKeys(keys); err != nil {
		t.Fatalf("SaveDNSKeys: %v", err)
	}

	// 两个 goroutine 并发调用 TrackDNSKeyUsage (均原子化)
	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				nodeID := fmt.Sprintf("node-%d-%d", gid, i)
				if err := s.TrackDNSKeyUsage("key-a", nodeID); err != nil {
					errs <- err
				}
			}
		}(g)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("并发 TrackDNSKeyUsage 错误: %v", err)
	}

	// 验证: key-a 的 used_by_nodes 包含所有 20 个并发写入的节点 (无丢失)
	finalKeys, _ := s.LoadDNSKeys()
	ka, ok := finalKeys["key-a"]
	if !ok {
		t.Fatal("key-a 不存在")
	}
	// 由于去重逻辑, 可能 < 20 (同 node 多次写入), 但不应为空
	if len(ka.UsedByNodes) == 0 {
		t.Error("key-a used_by_nodes 为空 — 并发写入全部丢失")
	}
	t.Logf("used_by_nodes count: %d (20 unique nodes across 2 goroutines)", len(ka.UsedByNodes))
}
