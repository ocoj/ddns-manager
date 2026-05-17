// Package store provides file-system-based persistence.
package store

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kk/ddns-manager/internal/model"
	"github.com/kk/ddns-manager/internal/notify"
)

// ManagerStore is the central data store with in-memory cache.
// Nodes and DNS keys are cached in memory after first load; writes update both
// the cache and the backing file. This avoids per-heartbeat JSON file I/O.
// v1.6.10 L3: 两个独立标志, 防止并发场景下 loadNodesToCache 设置 cacheLoaded=true
// 导致 dnsKeysCache 被误标记为已加载 (两个 load 函数之前共享一个 cacheLoaded)
type ManagerStore struct {
	mu     sync.RWMutex
	dir    string

	// In-memory caches — populated on first read, kept in sync by write methods.
	// Protected by mu (reads hold RLock, writes hold Lock).
	nodesCache         map[string]*model.NodeRecord
	dnsKeysCache       map[string]*model.DNSKeyRecord
	nodesCacheLoaded   bool
	dnsKeysCacheLoaded bool
}

// NewStore opens or initialises the data directory.
func NewStore(dir string) (*ManagerStore, error) {
	for _, sub := range []string{"configs", "certs"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	return &ManagerStore{dir: dir}, nil
}

// ── Nodes ──

func (s *ManagerStore) nodesPath() string { return filepath.Join(s.dir, "nodes.json") }

// loadNodesToCache reads nodes.json into memory cache (called under write lock on first access).
func (s *ManagerStore) loadNodesToCache() error {
	nodes := map[string]*model.NodeRecord{}
	data, err := os.ReadFile(s.nodesPath())
	if os.IsNotExist(err) {
		s.nodesCache = nodes
		s.nodesCacheLoaded = true
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &nodes); err != nil {
		return fmt.Errorf("nodes.json: %w", err)
	}
	s.nodesCache = nodes
	s.nodesCacheLoaded = true
	return nil
}

func (s *ManagerStore) LoadNodes() (map[string]*model.NodeRecord, error) {
	s.mu.RLock()
	// Fast path: return shallow copy of cached map (no file I/O per heartbeat)
	if s.nodesCacheLoaded && s.nodesCache != nil {
		out := make(map[string]*model.NodeRecord, len(s.nodesCache))
		for k, v := range s.nodesCache {
			out[k] = v
		}
		s.mu.RUnlock()
		return out, nil
	}
	s.mu.RUnlock()

	// Slow path: first access — populate cache from disk
	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check: another goroutine may have loaded while we waited for write lock
	if s.nodesCacheLoaded && s.nodesCache != nil {
		out := make(map[string]*model.NodeRecord, len(s.nodesCache))
		for k, v := range s.nodesCache {
			out[k] = v
		}
		return out, nil
	}
	if err := s.loadNodesToCache(); err != nil {
		return nil, err
	}
	out := make(map[string]*model.NodeRecord, len(s.nodesCache))
	for k, v := range s.nodesCache {
		out[k] = v
	}
	return out, nil
}

// saveNodesLocked writes nodes to disk and updates in-memory cache.
// Caller must hold s.mu.Lock().
func (s *ManagerStore) saveNodesLocked(nodes map[string]*model.NodeRecord) error {
	data, err := json.MarshalIndent(nodes, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.nodesPath(), data, 0o600); err != nil {
		return err
	}
	// Update in-memory cache (the caller's map becomes the cache)
	s.nodesCache = nodes
	s.nodesCacheLoaded = true
	return nil
}

func (s *ManagerStore) SaveNodes(nodes map[string]*model.NodeRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveNodesLocked(nodes)
}

func (s *ManagerStore) GetNode(id string) (*model.NodeRecord, error) {
	nodes, err := s.LoadNodes()
	if err != nil {
		return nil, err
	}
	n, ok := nodes[id]
	if !ok {
		return nil, fmt.Errorf("node %q not found", id)
	}
	return n, nil
}

// PutNode atomically reads-modifies-writes a single node record.
// Holds write lock for the entire operation to prevent TOCTOU races
// between concurrent heartbeat handlers.
func (s *ManagerStore) PutNode(id string, rec *model.NodeRecord) error {
	return s.putNodeInternal(id, rec, false)
}

// DeleteNode atomically removes a node record under write lock.
// Prevents the TOCTOU race in handleDeleteNode (LoadNodes → delete → SaveNodes).
func (s *ManagerStore) DeleteNode(id string) error {
	return s.putNodeInternal(id, nil, true)
}

func (s *ManagerStore) putNodeInternal(id string, rec *model.NodeRecord, del bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure cache is loaded (first access after restart)
	if !s.nodesCacheLoaded || s.nodesCache == nil {
		if err := s.loadNodesToCache(); err != nil {
			return err
		}
	}

	// Operate on in-memory cache directly (no file I/O for read)
	nodes := s.nodesCache
	if del {
		if _, ok := nodes[id]; !ok {
			return fmt.Errorf("node %q not found", id)
		}
		delete(nodes, id)
	} else {
		nodes[id] = rec
	}
	// Write-through: persist to disk + update cache atomically
	return s.saveNodesLocked(nodes)
}

// ── Configs ── (removed - DNS keys managed via dns_keys.json)

// ── Certs ──

type CertBundle struct {
	Name       string            `json:"name"`
	Files      map[string][]byte `json:"-"`
	TargetPath string            `json:"target_path"`
	ExpiresAt  time.Time         `json:"expires_at"`
	Domains    []string          `json:"domains"`
	Hash       string            `json:"hash"`
	PFXPassword string           `json:"pfx_password,omitempty"` // PFX 证书密码
}

func (s *ManagerStore) LoadCertBundle(name string) (*CertBundle, error) {
	dir := filepath.Join(s.dir, "certs", name)
	metaPath := filepath.Join(dir, "meta.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	var b CertBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	// 确保 Name 总是从目录名获取（meta.json 可能缺失 name 字段）
	b.Name = name
	b.Files = map[string][]byte{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("readdir %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "meta.json" {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("readfile %s/%s: %w", dir, e.Name(), err)
		}
		b.Files[e.Name()] = content
	}
	return &b, nil
}

func (s *ManagerStore) SaveCertBundle(b *CertBundle) error {
	dir := filepath.Join(s.dir, "certs", b.Name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// write files in stable order, compute deterministic hash
	h := sha256.New()
	names := make([]string, 0, len(b.Files))
	for name := range b.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		content := b.Files[name]
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			return err
		}
		h.Write(content)
	}
	b.Hash = fmt.Sprintf("sha256:%x", h.Sum(nil))
	// preserve existing extra fields not in CertBundle struct (e.g. ACME metadata: acme/email/ca/key_type)
	extra := map[string]interface{}{}
	if data, err := os.ReadFile(filepath.Join(dir, "meta.json")); err == nil {
		if ex := map[string]interface{}{}; json.Unmarshal(data, &ex) == nil {
			structKeys := map[string]bool{"name":true,"files":true,"target_path":true,"expires_at":true,"domains":true,"hash":true,"pfx_password":true}
			for k, v := range ex {
				if !structKeys[k] {
					extra[k] = v
				}
			}
		}
	}
	// marshal bundle, then merge extra fields
	metaMap := map[string]interface{}{}
	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("marshal cert bundle: %w", err)
	}
	if err := json.Unmarshal(data, &metaMap); err != nil {
		return fmt.Errorf("unmarshal cert bundle: %w", err)
	}
	for k, v := range extra {
		metaMap[k] = v
	}
	meta, err := json.MarshalIndent(metaMap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cert meta: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0o600)
}

func (s *ManagerStore) ListCertBundles() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "certs"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

func (s *ManagerStore) DeleteCertBundle(name string) error {
	return os.RemoveAll(filepath.Join(s.dir, "certs", name))
}

// ── Admin State ──

type AdminState struct {
	TokenHash       string `json:"token_hash"`        // bcrypt of admin token
	PasswordChanged bool   `json:"password_changed"`
}

func (s *ManagerStore) adminPath() string { return filepath.Join(s.dir, "admin.json") }

func (s *ManagerStore) LoadAdminState() (*AdminState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.adminPath())
	if os.IsNotExist(err) {
		return nil, nil // not initialised
	}
	if err != nil {
		return nil, err
	}
	var st AdminState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *ManagerStore) SaveAdminState(st *AdminState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.adminPath(), data, 0o600)
}

// ── DNS Keys ──

func (s *ManagerStore) dnsKeysPath() string { return filepath.Join(s.dir, "dns_keys.json") }

// loadDNSKeysToCache reads dns_keys.json into memory cache (called under write lock).
func (s *ManagerStore) loadDNSKeysToCache() error {
	keys := map[string]*model.DNSKeyRecord{}
	data, err := os.ReadFile(s.dnsKeysPath())
	if os.IsNotExist(err) {
		s.dnsKeysCache = keys
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &keys); err != nil {
		return fmt.Errorf("dns_keys.json: %w", err)
	}
	// backward compat: old keys use provider as key, fill Name/Provider if empty
	for k, v := range keys {
		if v.Name == "" { v.Name = k }
		if v.Provider == "" { v.Provider = k }
	}
	s.dnsKeysCache = keys
	s.dnsKeysCacheLoaded = true
	return nil
}

func (s *ManagerStore) LoadDNSKeys() (map[string]*model.DNSKeyRecord, error) {
	s.mu.RLock()
	// Fast path: return shallow copy of cached map
	if s.dnsKeysCacheLoaded && s.dnsKeysCache != nil {
		out := make(map[string]*model.DNSKeyRecord, len(s.dnsKeysCache))
		for k, v := range s.dnsKeysCache {
			out[k] = v
		}
		s.mu.RUnlock()
		return out, nil
	}
	s.mu.RUnlock()

	// Slow path: populate from disk
	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check: another goroutine may have loaded while we waited for write lock
	if s.dnsKeysCacheLoaded && s.dnsKeysCache != nil {
		out := make(map[string]*model.DNSKeyRecord, len(s.dnsKeysCache))
		for k, v := range s.dnsKeysCache {
			out[k] = v
		}
		return out, nil
	}
	if err := s.loadDNSKeysToCache(); err != nil {
		return nil, err
	}
	out := make(map[string]*model.DNSKeyRecord, len(s.dnsKeysCache))
	for k, v := range s.dnsKeysCache {
		out[k] = v
	}
	return out, nil
}

func (s *ManagerStore) SaveDNSKeys(keys map[string]*model.DNSKeyRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}
	// Write-through: persist + update cache (v1.6.29 C4: 设置 loaded 标志)
	s.dnsKeysCache = keys
	s.dnsKeysCacheLoaded = true
	return os.WriteFile(s.dnsKeysPath(), data, 0o600)
}

// DeleteDNSKeyAtomic removes a DNS key under write lock.
// Prevents TOCTOU race between LoadDNSKeys→delete→SaveDNSKeys.
func (s *ManagerStore) DeleteDNSKeyAtomic(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure cache is loaded
	if s.dnsKeysCache == nil {
		if err := s.loadDNSKeysToCache(); err != nil {
			return err
		}
	}

	if _, ok := s.dnsKeysCache[name]; !ok {
		return fmt.Errorf("DNS key %q not found", name)
	}
	delete(s.dnsKeysCache, name)

	data, err := json.MarshalIndent(s.dnsKeysCache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.dnsKeysPath(), data, 0o600)
}

// TrackDNSKeyUsage adds nodeID to the used_by_nodes list of a DNS key (by name).
func (s *ManagerStore) TrackDNSKeyUsage(keyName, nodeID string) error {
	keys, err := s.LoadDNSKeys()
	if err != nil {
		return err
	}
	rec, ok := keys[keyName]
	if !ok {
		return nil
	}
	found := false
	for _, n := range rec.UsedByNodes {
		if n == nodeID {
			found = true
			break
		}
	}
	if !found {
		rec.UsedByNodes = append(rec.UsedByNodes, nodeID)
		return s.SaveDNSKeys(keys)
	}
	return nil
}

// RemoveNodeFromDNSKeys removes nodeID from all DNS key usage lists.
func (s *ManagerStore) RemoveNodeFromDNSKeys(nodeID string) error {
	keys, err := s.LoadDNSKeys()
	if err != nil {
		return err
	}
	changed := false
	for _, rec := range keys {
		for i, n := range rec.UsedByNodes {
			if n == nodeID {
				rec.UsedByNodes = append(rec.UsedByNodes[:i], rec.UsedByNodes[i+1:]...)
				changed = true
				break
			}
		}
	}
	if changed {
		return s.SaveDNSKeys(keys)
	}
	return nil
}

// ── Agent Version ──

func (s *ManagerStore) agentConfigPath() string { return filepath.Join(s.dir, "agent_config.json") }

type AgentConfig struct {
	LatestVersion string            `json:"latest_version"`
	UpgradeState  map[string]UpgJob `json:"upgrade_state,omitempty"` // nodeID → 升级任务
}

// UpgJob tracks an agent upgrade trigger for dedup and UI status.
// RetryCount limits push attempts (max 5) to prevent infinite 404 loops
// when the binary is missing from /bin/. An abandoned job is retried when
// handleSetAgentVersion is called (new version or same-version re-save).
type UpgJob struct {
	TargetVer  string `json:"target_ver"`             // 目标版本
	Triggered  string `json:"triggered"`              // 触发时间 RFC3339
	Completed  string `json:"completed,omitempty"`    // 完成时间 (agent 心跳确认后写入)
	RetryCount int    `json:"retry_count,omitempty"`  // 已推送次数 (用于永久放弃判定)
}

func (s *ManagerStore) agentManifestPath() string { return filepath.Join(s.dir, "agent_manifest.json") }

func (s *ManagerStore) LoadAgentManifest() (map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.agentManifestPath())
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (s *ManagerStore) SaveAgentManifest(m map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.agentManifestPath(), data, 0o644)
}

func (s *ManagerStore) LoadAgentConfig() (*AgentConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.agentConfigPath())
	if os.IsNotExist(err) {
		return &AgentConfig{}, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg AgentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (s *ManagerStore) SaveAgentConfig(cfg *AgentConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.agentConfigPath(), data, 0o600)
}

// UpdateAgentConfigAtomic reads the config, applies the mutation under write lock,
// and saves — preventing TOCTOU races between concurrent set-version operations.
func (s *ManagerStore) UpdateAgentConfigAtomic(fn func(*AgentConfig)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg := &AgentConfig{}
	data, err := os.ReadFile(s.agentConfigPath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("agent_config.json: %w", err)
		}
	}
	fn(cfg)
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.agentConfigPath(), out, 0o600)
}

// ── Agent Binaries ──

func (s *ManagerStore) AgentBinDir() string {
	dir := filepath.Join(s.dir, "bin")
	os.MkdirAll(dir, 0o755)
	return dir
}

func (s *ManagerStore) ListAgentBinaries() ([]map[string]interface{}, error) {
	entries, err := os.ReadDir(s.AgentBinDir())
	if err != nil {
		return nil, err
	}
	verRe := regexp.MustCompile(`-v(dev|\d+\.\d+\.\d+)-`)
	var result []map[string]interface{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "node-agent") {
			continue
		}
		// v1.5.28: 跳过符号链接 (如 node-agent-latest → node-agent-v1.5.28-*)
		// 符号链接在 Web UI 中显示 0KB 且无版本号, 造成混淆
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, _ := e.Info()
		version := ""
		if m := verRe.FindStringSubmatch(e.Name()); m != nil {
			version = m[1]
		}
		result = append(result, map[string]interface{}{
			"name":     e.Name(),
			"size":     info.Size(),
			"version":  version,
			"mod_time": info.ModTime().Format("2006-01-02 15:04"), // v1.5.33: 修改时间
		})
	}
	return result, nil
}

// ListAgentVersions returns distinct versions from uploaded agent binaries.
func (s *ManagerStore) ListAgentVersions() ([]string, error) {
	entries, err := os.ReadDir(s.AgentBinDir())
	if err != nil {
		return nil, err
	}
	verRe := regexp.MustCompile(`-v(dev|\d+\.\d+\.\d+)-`)
	seen := map[string]bool{}
	var versions []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "node-agent") {
			continue
		}
		// v1.5.28: 跳过符号链接
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		if m := verRe.FindStringSubmatch(e.Name()); m != nil {
			v := m[1]
			if !seen[v] {
				seen[v] = true
				versions = append(versions, v)
			}
		}
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	return versions, nil
}

func (s *ManagerStore) SaveAgentBinary(name string, data []byte) error {
	dir := s.AgentBinDir()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		return err
	}
	// v1.5.36 C3: 为每个上传的二进制计算并保存 SHA256 校验和, 供 Agent 升级时校验完整性
	h := sha256.Sum256(data)
	shaFile := filepath.Join(dir, name+".sha256")
	os.WriteFile(shaFile, []byte(fmt.Sprintf("%x  %s\n", h[:], name)), 0o644)
	s.RebuildManifest()
	return nil
}

func (s *ManagerStore) DeleteAgentBinary(name string) error {
	if err := os.Remove(filepath.Join(s.AgentBinDir(), name)); err != nil {
		return err
	}
	// v1.5.36 C3: 同时删除对应的 SHA256 文件
	os.Remove(filepath.Join(s.AgentBinDir(), name+".sha256"))
	s.RebuildManifest()
	return nil
}

// GetAgentBinarySHA256 读取已保存的二进制 SHA256 校验和 (v1.5.36 C3)。
// 返回 hex 字符串, 若文件不存在返回空字符串。
func (s *ManagerStore) GetAgentBinarySHA256(filename string) string {
	data, err := os.ReadFile(filepath.Join(s.AgentBinDir(), filename+".sha256"))
	if err != nil {
		return ""
	}
	// 标准格式: "hex  filename\n"
	fields := strings.Fields(string(data))
	if len(fields) >= 1 && len(fields[0]) == 64 {
		return fields[0]
	}
	return ""
}

// RebuildManifest 扫描 /bin/ 目录，按 os-arch 分组建 agent_manifest.json。
// 每个平台取版本号最高的二进制文件。上传/删除后自动调用。
// 文件名格式: node-agent-v{VERSION}-{os}-{arch}[.exe]
func (s *ManagerStore) RebuildManifest() {
	// 注意: RebuildManifest 不持锁扫描目录。
	// SaveAgentManifest 内部持写锁写文件，确保 manifest 原子性。
	// 读目录期间可能有 SaveAgentBinary 正在写入，极端情况下可能读到部分文件，
	// 但下次 RebuildManifest (上传/删除触发) 会自动修正。
	entries, err := os.ReadDir(s.AgentBinDir())
	if err != nil {
		return
	}
	// 正则: node-agent-v{VERSION}-{os}-{arch}[.exe]
	// 示例: node-agent-v1.5.8-windows-amd64.exe / node-agent-v1.5.8-linux-amd64
	re := regexp.MustCompile(`^node-agent-v([^-]+)-([^-]+)-([^\.]+)(?:\.exe)?$`)
	// platformKey → {version, filename}
	type candidate struct {
		version  string
		filename string
	}
	best := make(map[string]candidate)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := re.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		ver, goos, goarch := m[1], m[2], m[3]
		// 跳过 dev 版本和非标准版本号
		if ver == "dev" || goos == "" || goarch == "" {
			continue
		}
		key := goos + "-" + goarch
		cur, exists := best[key]
		if !exists || model.CompareSemVer(ver, cur.version) > 0 {
			best[key] = candidate{ver, e.Name()}
		}
	}
	// 写入 manifest
	manifest := make(map[string]string, len(best))
	for k, c := range best {
		manifest[k] = c.filename
	}
	s.SaveAgentManifest(manifest)
}

// ── SMTP Config ──

func (s *ManagerStore) smtpPath() string { return filepath.Join(s.dir, "smtp_config.json") }

func (s *ManagerStore) LoadSMTPConfig() (*notify.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.smtpPath())
	if os.IsNotExist(err) {
		return &notify.Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg notify.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.CertExpiryDays <= 0 {
		cfg.CertExpiryDays = 7
	}
	return &cfg, nil
}

func (s *ManagerStore) SaveSMTPConfig(cfg *notify.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.CertExpiryDays <= 0 {
		cfg.CertExpiryDays = 7
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.smtpPath(), data, 0o600)
}

type ACMEAccountConfig struct {
	Email       string `json:"email"`
	CA          string `json:"ca"`
	KeyType     string `json:"key_type"`
	AccountKey  string `json:"account_key,omitempty"`  // PEM-encoded private key
	EABKID      string `json:"eab_kid,omitempty"`
	EABKey      string `json:"eab_key,omitempty"`
	Updated     string `json:"updated,omitempty"`
}

func (s *ManagerStore) acmeConfigPath() string { return filepath.Join(s.dir, "acme_config.json") }

func (s *ManagerStore) LoadACMEAccounts() ([]ACMEAccountConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.acmeConfigPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var accounts []ACMEAccountConfig
	if err := json.Unmarshal(data, &accounts); err != nil {
		return nil, err
	}
	return accounts, nil
}

func (s *ManagerStore) SaveACMEAccounts(accounts []ACMEAccountConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveACMEAccountsLocked(accounts)
}

// saveACMEAccountsLocked writes to disk. Caller must hold s.mu.Lock().
func (s *ManagerStore) saveACMEAccountsLocked(accounts []ACMEAccountConfig) error {
	data, err := json.MarshalIndent(accounts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.acmeConfigPath(), data, 0o600)
}

// loadACMEAccountsLocked reads from disk. Caller must hold s.mu.Lock().
func (s *ManagerStore) loadACMEAccountsLocked() ([]ACMEAccountConfig, error) {
	data, err := os.ReadFile(s.acmeConfigPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var accounts []ACMEAccountConfig
	if err := json.Unmarshal(data, &accounts); err != nil {
		return nil, err
	}
	return accounts, nil
}

// PutACMEAccount atomically reads-modifies-writes an ACME account at index.
// If index < 0, appends a new account. Prevents concurrent write corruption.
func (s *ManagerStore) PutACMEAccount(index int, acct ACMEAccountConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	accounts, err := s.loadACMEAccountsLocked()
	if err != nil {
		return err
	}
	if index >= 0 && index < len(accounts) {
		accounts[index] = acct
	} else {
		accounts = append(accounts, acct)
	}
	return s.saveACMEAccountsLocked(accounts)
}

// DeleteACMEAccount atomically removes an ACME account at index.
func (s *ManagerStore) DeleteACMEAccount(index int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	accounts, err := s.loadACMEAccountsLocked()
	if err != nil {
		return err
	}
	if index < 0 || index >= len(accounts) {
		return fmt.Errorf("ACME account %d not found", index)
	}
	accounts = append(accounts[:index], accounts[index+1:]...)
	return s.saveACMEAccountsLocked(accounts)
}


// ── Rate Limit Config ──

type RateLimitConfig struct {
	Enabled          bool `json:"enabled"`
	RequestsPerMin   int  `json:"requests_per_min"`
	HeartbeatPerMin  int  `json:"heartbeat_per_min"`
	LoginPerMin      int  `json:"login_per_min"`
}

func (s *ManagerStore) rateLimitPath() string { return filepath.Join(s.dir, "rate_limit.json") }

func (s *ManagerStore) LoadRateLimitConfig() (*RateLimitConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.rateLimitPath())
	if os.IsNotExist(err) {
		return &RateLimitConfig{Enabled: false, RequestsPerMin: 600, HeartbeatPerMin: 120, LoginPerMin: 10}, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg RateLimitConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.RequestsPerMin <= 0 { cfg.RequestsPerMin = 600 }
	if cfg.HeartbeatPerMin <= 0 { cfg.HeartbeatPerMin = 120 }
	if cfg.LoginPerMin <= 0 { cfg.LoginPerMin = 10 }
	return &cfg, nil
}

func (s *ManagerStore) SaveRateLimitConfig(cfg *RateLimitConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.RequestsPerMin <= 0 { cfg.RequestsPerMin = 600 }
	if cfg.HeartbeatPerMin <= 0 { cfg.HeartbeatPerMin = 120 }
	if cfg.LoginPerMin <= 0 { cfg.LoginPerMin = 10 }
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.rateLimitPath(), data, 0o600)
}

// ── Timezone ──

type TimezoneConfig struct {
	Timezone string `json:"timezone"` // e.g. "Asia/Shanghai", "UTC"
}

func (s *ManagerStore) timezonePath() string { return filepath.Join(s.dir, "timezone.json") }

func (s *ManagerStore) LoadTimezoneConfig() (*TimezoneConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.timezonePath())
	if os.IsNotExist(err) {
		return &TimezoneConfig{Timezone: "Asia/Shanghai"}, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg TimezoneConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Timezone == "" {
		cfg.Timezone = "Asia/Shanghai"
	}
	return &cfg, nil
}

func (s *ManagerStore) SaveTimezoneConfig(cfg *TimezoneConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.Timezone == "" {
		cfg.Timezone = "Asia/Shanghai"
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.timezonePath(), data, 0o600)
}
