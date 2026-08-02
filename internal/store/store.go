// Package store provides file-system-based persistence.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	mycrypto "github.com/ocoj/ddns-manager/internal/crypto"
	"github.com/ocoj/ddns-manager/internal/model"
	"github.com/ocoj/ddns-manager/internal/notify"
)

// ManagerStore is the central data store with in-memory cache.
// Nodes and DNS keys are cached in memory after first load; writes update both
// the cache and the backing file. This avoids per-heartbeat JSON file I/O.
// v1.6.10 L3: 两个独立标志, 防止并发场景下 loadNodesToCache 设置 cacheLoaded=true
// 导致 dnsKeysCache 被误标记为已加载 (两个 load 函数之前共享一个 cacheLoaded)
type ManagerStore struct {
	mu         sync.RWMutex
	dir        string
	storageKey []byte // v1.6.56: at-rest encryption key for ACME secrets

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
	s := &ManagerStore{dir: dir}
	if err := s.initStorageKey(); err != nil {
		return nil, fmt.Errorf("storage key: %w", err)
	}
	// F8: 自动迁移明文 ACME 私钥（非致命 — 失败仅记录日志，不阻塞启动）
	if err := s.migrateACMEKeysIfNeeded(); err != nil {
		log.Printf("[store] ACME 密钥迁移失败（非致命）: %v", err)
	}
	return s, nil
}

// ── Nodes ──

// atomicWriteFile 原子写入：先写临时文件，确保落盘，再原子重命名
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	f, err := os.Open(tmp)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

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
	if err := atomicWriteFile(s.nodesPath(), data, 0o600); err != nil {
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
		// v1.6.46 H3: 字段级 merge — 心跳 handler 在 LoadNodes→PutNode 间可能被
		// 其他 handler (ApproveNode/SaveNodeConfig) 覆盖非心跳字段。
		// 若缓存中已有记录, 仅更新心跳相关字段, 保留其他 handler 写入的字段。
		if existing, ok := nodes[id]; ok {
			existing.LastSeen = rec.LastSeen
			existing.Status = rec.Status
			existing.Hardware = rec.Hardware
			existing.ConfigHash = rec.ConfigHash
			existing.ConfigSentAt = rec.ConfigSentAt
			existing.DNSConsecutiveFailures = rec.DNSConsecutiveFailures
		} else {
			nodes[id] = rec
		}
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
	if err := sanitizeBundleName(name); err != nil {
		return nil, err
	}
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
	if err := sanitizeBundleName(b.Name); err != nil {
		return err
	}
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

// sanitizeBundleName validates cert bundle name, preventing path traversal.
func sanitizeBundleName(name string) error {
	if name == "" || filepath.Base(name) != name {
		return fmt.Errorf("invalid cert bundle name: %q", name)
	}
	return nil
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
	if err := sanitizeBundleName(name); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(s.dir, "certs", name))
}

// ── Admin State ──

type AdminState struct {
	TokenHash       string `json:"token_hash"`        // bcrypt of admin token
	PasswordChanged bool   `json:"password_changed"`
	InstanceSalt    string `json:"instance_salt,omitempty"` // v1.6.46: 实例级随机 salt, 防跨实例 token 复用
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
	return atomicWriteFile(s.adminPath(), data, 0o600)
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
	// v1.6.56 M4: 先写文件，成功后再更新缓存（对齐 saveNodesLocked 模式）
	if err := atomicWriteFile(s.dnsKeysPath(), data, 0o600); err != nil {
		return err
	}
	s.dnsKeysCache = keys
	s.dnsKeysCacheLoaded = true
	return nil
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
	// v1.6.56 M4: 操作缓存副本，写文件成功后更新缓存
	cacheCopy := make(map[string]*model.DNSKeyRecord, len(s.dnsKeysCache))
	for k, v := range s.dnsKeysCache {
		if k != name {
			cacheCopy[k] = v
		}
	}
	data, err := json.MarshalIndent(cacheCopy, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(s.dnsKeysPath(), data, 0o600); err != nil {
		return err
	}
	s.dnsKeysCache = cacheCopy
	return nil
}

// TrackDNSKeyUsage adds nodeID to the used_by_nodes list of a DNS key (by name).
// v1.6.42 C7: 原子化 — 全程持写锁读-改-写, 消除 TOCTOU 竞态
func (s *ManagerStore) TrackDNSKeyUsage(keyName, nodeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 确保缓存已加载
	if s.dnsKeysCache == nil {
		if err := s.loadDNSKeysToCache(); err != nil {
			return err
		}
	}

	rec, ok := s.dnsKeysCache[keyName]
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
		data, err := json.MarshalIndent(s.dnsKeysCache, "", "  ")
		if err != nil {
			return err
		}
		return atomicWriteFile(s.dnsKeysPath(), data, 0o600)
	}
	return nil
}

// v1.6.46 H2: 全程持写锁, 操作缓存直接内存, 防止 Load→Modify→Save 竞态
func (s *ManagerStore) RemoveNodeFromDNSKeys(nodeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 确保缓存已加载
	if s.dnsKeysCache == nil {
		if err := s.loadDNSKeysToCache(); err != nil {
			return err
		}
	}

	changed := false
	for _, rec := range s.dnsKeysCache {
		for i, n := range rec.UsedByNodes {
			if n == nodeID {
				rec.UsedByNodes = append(rec.UsedByNodes[:i], rec.UsedByNodes[i+1:]...)
				changed = true
				break
			}
		}
	}

	if !changed {
		return nil
	}

	data, err := json.MarshalIndent(s.dnsKeysCache, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.dnsKeysPath(), data, 0o600)
}

// InvalidateConfigHashesForDNSKey 清空引用指定 DNS key 的所有节点 ConfigHash,
// 迫使下个心跳重新渲染并推送含新 key 的配置 (v1.6.61 配置变化感知)。
// 持写锁遍历所有节点, 用 JSON 解析提取 key 引用 (新格式 dns_confs[].dns_key +
// 旧格式 dns_key_name / dns_provider), 覆盖新旧两种配置格式。
// 由 handleSaveDNSKey / handleDeleteDNSKey 在写 key 成功后调用。
func (s *ManagerStore) InvalidateConfigHashesForDNSKey(keyName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 确保节点缓存已加载
	if s.nodesCache == nil {
		if err := s.loadNodesToCache(); err != nil {
			return err
		}
	}
	// 查 keyName 对应的 Provider — 旧格式 dns_provider 字段引用的是 provider 类型名
	// (handlers_nodes.go 旧格式渲染: v.Provider == DnsProvider 查找)
	if s.dnsKeysCache == nil {
		if err := s.loadDNSKeysToCache(); err != nil {
			return err
		}
	}
	providerName := ""
	if k, ok := s.dnsKeysCache[keyName]; ok {
		providerName = k.Provider
	}

	changed := false
	for _, rec := range s.nodesCache {
		if rec.ConfigYAML == "" {
			continue
		}
		if nodeUsesDNSKey(rec.ConfigYAML, keyName, providerName) {
			rec.ConfigHash = ""
			changed = true
		}
	}
	if changed {
		return s.saveNodesLocked(s.nodesCache)
	}
	return nil
}

// nodeUsesDNSKey 在 ConfigYAML JSON 中搜索指定 key 引用
// 新格式: dns_confs[].dns_key == keyName
// 旧格式: dns_key_name == keyName, 或 dns_provider == providerName (provider 类型名)
func nodeUsesDNSKey(configYAML, keyName, providerName string) bool {
	var cfg struct {
		DNSKeyName  string `json:"dns_key_name"`
		DNSProvider string `json:"dns_provider"`
		DNSConfs    []struct {
			DNSKey string `json:"dns_key"`
		} `json:"dns_confs"`
	}
	if json.Unmarshal([]byte(configYAML), &cfg) != nil {
		return false
	}
	if cfg.DNSKeyName == keyName {
		return true
	}
	if providerName != "" && cfg.DNSProvider == providerName {
		return true
	}
	for _, ci := range cfg.DNSConfs {
		if ci.DNSKey == keyName {
			return true
		}
	}
	return false
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
	return atomicWriteFile(s.agentManifestPath(), data, 0o644)
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
	return atomicWriteFile(s.agentConfigPath(), data, 0o600)
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
	return atomicWriteFile(s.agentConfigPath(), out, 0o600)
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
// 返回 hex 字符串。优先读预计算的 .sha256 文件；缺失时从二进制当场计算兜底。
// v1.6.36 C5: 兜底计算覆盖手动 SCP 部署忘记带 .sha256 的场景
func (s *ManagerStore) GetAgentBinarySHA256(filename string) string {
	data, err := os.ReadFile(filepath.Join(s.AgentBinDir(), filename+".sha256"))
	if err == nil {
		// 标准格式: "hex  filename\n"
		fields := strings.Fields(string(data))
		if len(fields) >= 1 && len(fields[0]) == 64 {
			return fields[0]
		}
	}
	// v1.6.36 C5: 兜底 — .sha256 缺失/损坏时当场计算
	// 覆盖手动 SCP 部署忘带 .sha256 或磁盘坏块导致文件损坏的场景
	bin, err := os.ReadFile(filepath.Join(s.AgentBinDir(), filename))
	if err != nil {
		return ""
	}
	h := sha256.Sum256(bin)
	return fmt.Sprintf("%x", h[:])
}

// RebuildManifest 扫描 /bin/ 目录，按 os-arch 分组建 agent_manifest.json。
// 每个平台取版本号最高的二进制文件。上传/删除后自动调用。
// 文件名格式: node-agent-v{VERSION}-{os}-{arch}[.exe]
// v1.6.36 C2: 同时追踪 upgrade_helper*.exe, 解决 Agent 端 helper 缺失导致升级降级到批处理
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
	// C2: 同时匹配 upgrade_helper-v{VERSION}-{os}-{arch}.exe
	reHelper := regexp.MustCompile(`^upgrade_helper-v([^-]+)-([^-]+)-([^\.]+)(?:\.exe)$`)
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
		if m != nil {
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
			continue
		}
		// C2: 追踪 upgrade_helper 文件, key 为 "helper-{os}-{arch}"
		mh := reHelper.FindStringSubmatch(e.Name())
		if mh != nil {
			ver, goos, goarch := mh[1], mh[2], mh[3]
			if ver == "dev" || goos == "" || goarch == "" {
				continue
			}
			key := "helper-" + goos + "-" + goarch
			cur, exists := best[key]
			if !exists || model.CompareSemVer(ver, cur.version) > 0 {
				best[key] = candidate{ver, e.Name()}
			}
		}
	}
	// v1.6.46 H5: 为缺失 .sha256 的二进制自动补全校验文件
	// 覆盖场景: SCP/SSH 手动部署遗漏 .sha256、Web UI 上传写 sha256 失败
	for _, e := range entries {
		if e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		name := e.Name()
		// 跳过非二进制: .sha256 / .txt / .bat / .sh / .new / .tmp
		if strings.HasSuffix(name, ".sha256") || strings.HasSuffix(name, ".txt") ||
			strings.HasSuffix(name, ".bat") || strings.HasSuffix(name, ".sh") ||
			strings.HasSuffix(name, ".new") || strings.HasSuffix(name, ".tmp") ||
			strings.HasSuffix(name, ".linktmp") {
			continue
		}
		shaPath := filepath.Join(s.AgentBinDir(), name+".sha256")
		// .sha256 已存在 → 跳过
		if _, err := os.Stat(shaPath); err == nil {
			continue
		}
		// 读取二进制, 计算 SHA256, 写入持久文件
		binPath := filepath.Join(s.AgentBinDir(), name)
		data, err := os.ReadFile(binPath)
		if err != nil {
			log.Printf("[bin] 读取 %s 失败, 跳过 sha256 补全: %v", name, err)
			continue
		}
		h := sha256.Sum256(data)
		content := fmt.Sprintf("%x  %s\n", h[:], name)
		if err := os.WriteFile(shaPath, []byte(content), 0o644); err != nil {
			log.Printf("[bin] 写入 %s 失败: %v", shaPath, err)
		}
	}

	// 写入 manifest (agent 节点 manifest + helper manifest 合并存储)
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
	return atomicWriteFile(s.smtpPath(), data, 0o600)
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
	return s.loadACMEAccountsLocked()
}

func (s *ManagerStore) SaveACMEAccounts(accounts []ACMEAccountConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveACMEAccountsLocked(accounts)
}

// UpdateACMEAccountsAtomic v1.6.30 H4: 原子化的 load→modify→save, 防止并发 TOCTOU 写覆盖
func (s *ManagerStore) UpdateACMEAccountsAtomic(fn func([]ACMEAccountConfig) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	accounts, err := s.loadACMEAccountsLocked()
	if err != nil {
		return err
	}
	if accounts == nil {
		accounts = []ACMEAccountConfig{}
	}
	if err := fn(accounts); err != nil {
		return err
	}
	return s.saveACMEAccountsLocked(accounts)
}

// saveACMEAccountsLocked writes to disk with at-rest encryption for sensitive fields (v1.6.56).
// Caller must hold s.mu.Lock().
func (s *ManagerStore) saveACMEAccountsLocked(accounts []ACMEAccountConfig) error {
	// Encrypt AccountKey and EABKey before persisting
	encrypted := make([]ACMEAccountConfig, len(accounts))
	for i, a := range accounts {
		encrypted[i] = a
		if a.AccountKey != "" {
			ciphertext, err := s.encryptSensitive([]byte(a.AccountKey))
			if err != nil {
				return fmt.Errorf("encrypt account_key: %w", err)
			}
			encrypted[i].AccountKey = ciphertext
		}
		if a.EABKey != "" {
			ciphertext, err := s.encryptSensitive([]byte(a.EABKey))
			if err != nil {
				return fmt.Errorf("encrypt eab_key: %w", err)
			}
			encrypted[i].EABKey = ciphertext
		}
	}
	data, err := json.MarshalIndent(encrypted, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.acmeConfigPath(), data, 0o600)
}

// loadACMEAccountsLocked reads from disk with at-rest decryption (v1.6.56).
// Caller must hold s.mu.Lock().
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
	// Decrypt AccountKey / EABKey (backward-compat: PEM headers = already plaintext)
	for i := range accounts {
		if accounts[i].AccountKey != "" && !strings.HasPrefix(accounts[i].AccountKey, "-----BEGIN") {
			plain, err := s.decryptSensitive(accounts[i].AccountKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt account_key[%d]: %w", i, err)
			}
			accounts[i].AccountKey = string(plain)
		}
		if accounts[i].EABKey != "" && !strings.HasPrefix(accounts[i].EABKey, "-----BEGIN") {
			plain, err := s.decryptSensitive(accounts[i].EABKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt eab_key[%d]: %w", i, err)
			}
			accounts[i].EABKey = string(plain)
		}
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
	return atomicWriteFile(s.rateLimitPath(), data, 0o600)
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
	return atomicWriteFile(s.timezonePath(), data, 0o600)
}

// ── Proxy (v1.6.58) ──

type ProxyConfig struct {
	TrustedProxy string `json:"trusted_proxy"` // 受信反向代理 IP (空=禁用)
}

func (s *ManagerStore) proxyConfigPath() string { return filepath.Join(s.dir, "proxy_config.json") }

func (s *ManagerStore) LoadProxyConfig() (*ProxyConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.proxyConfigPath())
	if os.IsNotExist(err) {
		return &ProxyConfig{}, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg ProxyConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (s *ManagerStore) SaveProxyConfig(cfg *ProxyConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.proxyConfigPath(), data, 0o600)
}

// ── v1.6.56: at-rest encryption helpers ──

func (s *ManagerStore) storageKeyPath() string {
	return filepath.Join(s.dir, ".storage_key")
}

// initStorageKey loads or generates the storage master key.
func (s *ManagerStore) initStorageKey() error {
	keyPath := s.storageKeyPath()
	data, err := os.ReadFile(keyPath)
	if err == nil {
		s.storageKey = data
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	// First run: generate 32 random bytes
	s.storageKey = make([]byte, 32)
	if _, err := rand.Read(s.storageKey); err != nil {
		return err
	}
	return os.WriteFile(keyPath, s.storageKey, 0o600)
}

// migrateACMEKeysIfNeeded checks for plaintext ACME account keys and re-encrypts them.
// Safe to call on every startup — only writes when plaintext PEM keys are detected.
// F8: auto-migration for keys originally created before v1.6.56 encryption support.
func (s *ManagerStore) migrateACMEKeysIfNeeded() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.acmeConfigPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	// Fast check: if file contains no PEM header, all keys are already encrypted
	if !strings.Contains(string(data), "-----BEGIN") {
		return nil
	}

	var accounts []ACMEAccountConfig
	if err := json.Unmarshal(data, &accounts); err != nil {
		return err
	}

	needMigration := false
	for i := range accounts {
		if accounts[i].AccountKey != "" && strings.HasPrefix(accounts[i].AccountKey, "-----BEGIN") {
			needMigration = true
			break
		}
	}
	if !needMigration {
		return nil
	}

	log.Printf("[store] 检测到明文 ACME 私钥，正在加密迁移...")
	return s.saveACMEAccountsLocked(accounts)
}

// encryptSensitive encrypts plaintext using AES-256-GCM with a derived key.
func (s *ManagerStore) encryptSensitive(plaintext []byte) (string, error) {
	key := mycrypto.DeriveKey(hex.EncodeToString(s.storageKey), "storage", "acme-at-rest")
	return mycrypto.Encrypt(plaintext, key)
}

// decryptSensitive decrypts a base64+GCM ciphertext.
func (s *ManagerStore) decryptSensitive(ciphertext string) ([]byte, error) {
	key := mycrypto.DeriveKey(hex.EncodeToString(s.storageKey), "storage", "acme-at-rest")
	return mycrypto.Decrypt(ciphertext, key)
}

// ResetCaches clears in-memory node/DNS-key caches so next reads reload from disk.
func (s *ManagerStore) ResetCaches() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodesCache = nil
	s.dnsKeysCache = nil
	s.nodesCacheLoaded = false
	s.dnsKeysCacheLoaded = false
}

// ReloadStorageKey re-reads .storage_key from disk into memory.
func (s *ManagerStore) ReloadStorageKey() error {
	data, err := os.ReadFile(s.storageKeyPath())
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.storageKey = data
	s.mu.Unlock()
	return nil
}
