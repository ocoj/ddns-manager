package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/kk/ddns-manager/internal/model"
	"github.com/kk/ddns-manager/internal/store"
	mycrypto "github.com/kk/ddns-manager/internal/crypto"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	// 限制心跳请求体最大 1MB，防止恶意节点发送超大 JSON 耗尽内存
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	nodeID, password, ok := parseAuth(r)
	if !ok {
		jsonErr(w, http.StatusUnauthorized, "认证信息无效")
		return
	}
	var req model.HeartbeatReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	nodes, err := s.store.LoadNodes()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rec, ok := nodes[nodeID]
	if !ok {
		s.logMgr.LogWithNode("heartbeat", "认证失败", nodeID, "未知节点ID", "warning")
		jsonErr(w, http.StatusUnauthorized, "未知节点")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(rec.PasswordHash), []byte(password)); err != nil {
		s.logMgr.LogWithNode("heartbeat", "认证失败", nodeID, fmt.Sprintf("密码错误 IP=%s", clientIP(r)), "warning")
		jsonErr(w, http.StatusUnauthorized, "密码错误")
		return
	}
	if subtle.ConstantTimeCompare([]byte(rec.Fingerprint), []byte(req.Fingerprint)) != 1 {
		s.logMgr.LogWithNode("heartbeat", "认证失败", nodeID, fmt.Sprintf("指纹不匹配 IP=%s", clientIP(r)), "warning")
		jsonErr(w, http.StatusForbidden, "指纹不匹配")
		return
	}
	rec.LastSeen = s.nowInTZ()
	if req.Status.IPv4 != "" {
		rec.Status.IPv4 = req.Status.IPv4
	}
	if req.Status.IPv6 != "" {
		rec.Status.IPv6 = req.Status.IPv6
	}
	rec.Status.AgentVersion = req.Status.AgentVersion
	rec.Status.CertHashes = req.Status.CertHashes
	if req.Status.DDNSHealth != nil {
		rec.Status.DDNSHealth = req.Status.DDNSHealth
	}
	h := rec.Status.DDNSHealth
	switch {
	case h == nil:
		h = &model.DDNSHealthInfo{Status: "DOWN", StatusMsg: "no health data"}
		rec.Status.DDNSHealth = h
	case h.Running && h.LastOK:
		h.Status, h.StatusMsg = "OK", ""
	case h.Running && !h.LastOK:
		h.Status, h.StatusMsg = "ERR", h.LastError
	default:
		h.Status, h.StatusMsg = "DOWN", "updater not running"
	}
	if req.Hardware != nil {
		rec.Hardware = req.Hardware
	}
	// 记录心跳: DDNS 健康状态变更或首次心跳（含 IPv4/IPv6）
	s.logMgr.LogWithNode("heartbeat", "收到心跳", nodeID,
		fmt.Sprintf("ddns=%s ipv4=%s ipv6=%s", h.Status, req.Status.IPv4, req.Status.IPv6), "info")
	resp := model.HeartbeatResp{OK: true, Timestamp: s.nowInTZ().Format(time.RFC3339)}

	// ── 升级推送（审批门控之前）──
	// 升级只下发二进制 URL，不含机密；未审批节点也应能接收升级。
	// 配置/证书推送仍在审批门控之后（含 DNS Key 等机密）。
	goos, goarch := detectPlatform(rec)
	if goos != "" && goarch != "" && req.Status.AgentVersion != "" {
		now := s.nowInTZ()
		// 在 UpdateAgentConfigAtomic 闭包外加载 manifest，避免闭包内 RLock 死锁
		// （UpdateAgentConfigAtomic 持 store.mu 写锁，LoadAgentManifest 需要 store.mu 读锁）
		manifest, _ := s.store.LoadAgentManifest()
		binKey := goos + "-" + goarch
		manifestFile := manifest[binKey]
		s.store.UpdateAgentConfigAtomic(func(agentCfg *store.AgentConfig) {
			// 标记已完成的升级 — 必须在版本匹配判断之前
			// （否则已升级节点走到版本匹配即 return，永远不会标记完成）
			if agentCfg.UpgradeState != nil {
				if job, ok := agentCfg.UpgradeState[nodeID]; ok {
					if job.Completed == "" && job.TargetVer == req.Status.AgentVersion {
						job.Completed = now.Format(time.RFC3339)
						agentCfg.UpgradeState[nodeID] = job
						s.logMgr.LogWithNode("upgrade", "升级已完成", nodeID,
							fmt.Sprintf("ver=%s", req.Status.AgentVersion), "success")
					}
				}
			}
			if agentCfg.LatestVersion == "" || agentCfg.LatestVersion == req.Status.AgentVersion {
				return
			}
			shouldPush := true
			abandon := false
			if agentCfg.UpgradeState != nil {
				if job, ok := agentCfg.UpgradeState[nodeID]; ok {
					if job.Completed != "" && job.TargetVer == agentCfg.LatestVersion {
						shouldPush = false
					}
					if t, err := time.Parse(time.RFC3339, job.Triggered); err == nil {
						if job.TargetVer == agentCfg.LatestVersion && now.Sub(t) < 30*time.Minute {
							shouldPush = false
						}
					}
					if job.TargetVer == agentCfg.LatestVersion && job.RetryCount >= 5 {
						shouldPush = false
						abandon = true
					}
				}
			}
			if abandon {
				s.logMgr.LogWithNode("upgrade", "升级已放弃", nodeID,
					fmt.Sprintf("ver=%s 5次推送均失败", agentCfg.LatestVersion), "error")
				return
			}
			if shouldPush {
				safeName := strings.ReplaceAll(strings.ReplaceAll(manifestFile, "..", ""), "/", "")
				if safeName != "" && safeName == manifestFile {
					if _, err := os.Stat(filepath.Join(s.store.AgentBinDir(), safeName)); err == nil {
						resp.AgentUpdate = &model.AgentUpdate{Version: agentCfg.LatestVersion, URL: "dl/" + safeName}
					s.logMgr.LogWithNode("upgrade", "升级已推送", nodeID,
						fmt.Sprintf("ver=%s url=dl/%s", agentCfg.LatestVersion, safeName), "info")
						if agentCfg.UpgradeState == nil {
							agentCfg.UpgradeState = make(map[string]store.UpgJob)
						}
						job := agentCfg.UpgradeState[nodeID]
						job.TargetVer = agentCfg.LatestVersion
						job.Triggered = now.Format(time.RFC3339)
						job.RetryCount++
						agentCfg.UpgradeState[nodeID] = job
					} else {
						// H4: log missing binary for ops troubleshooting
						s.logMgr.LogWithNode("upgrade", "二进制缺失", nodeID,
							fmt.Sprintf("manifest=%s file=%s", binKey, manifestFile), "warning")
					}
				}
			}
		})
	}

	// ── 审批门控（配置/证书推送，含机密）──
	// 升级推送已在上方执行（不含机密）；以下仅对已审批节点推送配置和证书。
	if !rec.Approved {
		s.store.PutNode(nodeID, rec)
		jsonOK(w, resp)
		return
	}

	// config push: render ddns-go YAML from saved config + DNS keys, push if changed
	if rec.ConfigYAML != "" {
		rendered, cfgHash, renderErr := renderDDNSConfig(rec.ConfigYAML, s.store)
		if renderErr != nil {
			s.logMgr.LogWithNode("config", "配置渲染失败", nodeID,
				renderErr.Error(), "error")
			// 回传错误给 Agent，便于诊断
			resp.ConfigError = renderErr.Error()
		} else if rendered != "" && req.ConfigHash != rec.ConfigHash {
			s.logMgr.LogWithNode("config", "配置已下发", nodeID,
				fmt.Sprintf("%d bytes", len(rendered)), "success")
			resp.Config = &model.ConfigPush{YAML: rendered, Hash: cfgHash}
			rec.ConfigHash = cfgHash
			rec.ConfigSentAt = s.nowInTZ()
		}
	}
	key := mycrypto.DeriveKey(password, rec.Fingerprint, "cert-transport")
	for _, binding := range rec.CertBindings {
		bundle, err := s.store.LoadCertBundle(binding.BundleName)
		if err != nil {
			// 证书加载失败记录日志，便于排查部署问题
			s.logMgr.LogWithNode("cert", "证书加载失败", nodeID,
				fmt.Sprintf("bundle=%s err=%v", binding.BundleName, err), "warning")
			continue
		}
		// C2: hash key 对齐 Agent 侧 collectCertHashes 的键名
		hashKey := binding.DeployPath
		if hashKey == "" {
			hashKey = req.Status.CertPath
		}
		if h, ok := req.Status.CertHashes[hashKey]; ok && h == bundle.Hash {
			continue
		}
		encFiles := map[string]string{}
		for name, content := range bundle.Files {
			if ct, err := mycrypto.Encrypt(content, key); err == nil {
				encFiles[name] = ct
			}
		}
		if len(encFiles) == 0 {
			// 所有文件加密失败 — 跳过此 binding，下个心跳重试
			s.logMgr.LogWithNode("cert", "加密失败", nodeID,
				fmt.Sprintf("bundle=%s 所有文件加密失败", binding.BundleName), "warning")
			continue
		}
		resp.CertUpdates = append(resp.CertUpdates, &model.CertUpdate{
			CertHash: bundle.Hash, BundleName: binding.BundleName,
			Files: encFiles, TargetPath: binding.DeployPath,
			ReloadServices: binding.ReloadServices, // v1.5.20 C1: 传播证书部署后需重载的服务列表
			PFXPassword: bundle.PFXPassword,        // v1.5.20: 传播证书级 PFX 密码
		})
		// H1: 证书下发成功记录审计日志，运维可追踪证书分发到哪些节点
		s.logMgr.LogWithNode("cert", "证书已下发", nodeID,
			fmt.Sprintf("bundle=%s hash=%s... path=%s", binding.BundleName, bundle.Hash[:14], binding.DeployPath), "success")
	}
	// persist all changes in a single write (LastSeen, Status, Hardware, ConfigHash)
	s.store.PutNode(nodeID, rec)
	jsonOK(w, resp)
}

// ── admin: dashboard ──


func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, _ := s.store.LoadNodes()
	// 超时检测: 超过5分钟未心跳的节点标记为不在线
	// （dashboard用handleStats独立计算，这里统一节点列表口径）
	now := time.Now()
	for _, n := range nodes {
		if n.Status.DDNSHealth != nil && now.Sub(n.LastSeen) > 5*time.Minute {
			n.Status.DDNSHealth.Running = false
			if n.Status.DDNSHealth.Status == "OK" || n.Status.DDNSHealth.Status == "ERR" {
				n.Status.DDNSHealth.Status = "DOWN"
				n.Status.DDNSHealth.StatusMsg = "节点无响应"
			}
		}
	}
	jsonOK(w, nodes)
}
func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	rec, err := s.store.GetNode(mux.Vars(r)["id"])
	if err != nil {
		jsonErr(w, http.StatusNotFound, "节点未找到")
		return
	}
	jsonOK(w, rec)
}
func (s *Server) handleApproveNode(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req struct {
		CertBindings []model.CertBinding `json:"cert_bindings"`
		Tags         []string            `json:"tags"`
		Notes        *string             `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	rec, err := s.store.GetNode(id)
	if err != nil {
		jsonErr(w, http.StatusNotFound, "节点未找到")
		return
	}
	if req.CertBindings != nil {
		rec.CertBindings = req.CertBindings
	}
	if req.Tags != nil {
		rec.Tags = req.Tags
	}
	if req.Notes != nil {
		rec.Notes = *req.Notes
	}
	rec.Approved = true // 审批通过，节点开始接收配置/证书推送
	s.store.PutNode(id, rec)
	s.logMgr.LogWithNode("节点", "已审批", id, "", "info")
	jsonOK(w, map[string]string{"status": "approved"})
}
func (s *Server) handleSaveNodeConfig(w http.ResponseWriter, r *http.Request) {
	// 限制请求体 1MB，防止大请求内存耗尽
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	id := mux.Vars(r)["id"]
	var req model.NodeConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	rec, err := s.store.GetNode(id)
	if err != nil {
		jsonErr(w, http.StatusNotFound, "节点未找到")
		return
	}
	// 校验 DNS Key 存在性 — 防止保存不存在的 key 导致后续渲染失败
	if req.DNSKeyName != "" {
		keys, _ := s.store.LoadDNSKeys()
		if _, ok := keys[req.DNSKeyName]; !ok {
			jsonErr(w, http.StatusBadRequest, fmt.Sprintf("DNS Key %q 不存在，请先在「DNS Key」页面创建", req.DNSKeyName))
			return
		}
	}
	data, err := json.Marshal(req)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "配置序列化失败")
		s.logMgr.LogWithNode("config", "配置序列化失败", id, err.Error(), "error")
		return
	}
	rec.ConfigYAML = string(data)
	// M6: nil=保留, empty slice=清空: 同步 ConfigYAML 中的 cert_bindings
	// 防止 ConfigYAML 已为 [] 但 CertBindings 残留旧值导致持续推送
	if req.CertBindings != nil && len(req.CertBindings) == 0 {
		rec.CertBindings = nil  // 显式清空
	} else if req.CertBindings != nil {
		rec.CertBindings = req.CertBindings
	}
	rec.ConfigHash = ""
	// 保存配置即审批 — 管理员已配置意味着信任该节点
	if !rec.Approved {
		rec.Approved = true
		s.logMgr.LogWithNode("节点", "配置已保存(自动审批)", id, "", "info")
	}
	s.store.PutNode(id, rec)
	s.logMgr.LogWithNode("config", "已保存", id, fmt.Sprintf("dnsKey=%s", req.DNSKeyName), "success")
	// track DNS key usage by name (new) or provider (old fallback)
	if req.DNSKeyName != "" {
		s.store.TrackDNSKeyUsage(req.DNSKeyName, id)
	} else if req.DnsProvider != "" {
		s.store.TrackDNSKeyUsage(req.DnsProvider, id)
	}
	jsonOK(w, map[string]string{"status": "saved"})
}
// handleNodeFingerprint returns the fingerprint of a registered node.
// Public endpoint (no auth) — used by the installer to check for name conflicts
// and distinguish same-machine reinstall (fingerprint match) from name hijacking.
// Only exposes node_id + fingerprint + exists; no secrets or configs.
func (s *Server) handleNodeFingerprint(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	nodes, err := s.store.LoadNodes()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rec, ok := nodes[id]
	if !ok {
		jsonOK(w, map[string]interface{}{"exists": false})
		return
	}
	jsonOK(w, map[string]interface{}{
		"exists":      true,
		"node_id":     id,
		"fingerprint": rec.Fingerprint,
	})
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	// Use atomic DeleteNode (write-locked read-modify-write) to prevent TOCTOU race
	if err := s.store.DeleteNode(id); err != nil {
		jsonErr(w, http.StatusNotFound, "节点未找到")
		return
	}
	s.store.RemoveNodeFromDNSKeys(id)
	s.logMgr.LogWithNode("节点", "已删除", id, "", "info")
	jsonOK(w, map[string]string{"deleted": id})
}

// ── admin: dns keys ──

func computeBundleHash(files map[string][]byte) string {
	h := sha256.New()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		h.Write(files[n])
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

// renderDDNSConfig converts NodeConfigRequest JSON into ddns-go YAML config.
// dnsConfItem mirrors ddns-go config file structure for safe YAML marshaling.
type dnsConfItem struct {
	DNS  dnsAuth    `yaml:"dns"`
	IPv4 ipConf     `yaml:"ipv4"`
	IPv6 ipv6Conf   `yaml:"ipv6"`
	TTL  string     `yaml:"ttl"`
}

type dnsAuth struct {
	Name   string `yaml:"name"`
	ID     string `yaml:"id"`
	Secret string `yaml:"secret"`
}

type ipConf struct {
	Enable       bool     `yaml:"enable"`
	GetType      string   `yaml:"gettype"`
	URL          string   `yaml:"url"`
	NetInterface string   `yaml:"netinterface"`
	Cmd          string   `yaml:"cmd"`
	Domains      []string `yaml:"domains"`
}

type ipv6Conf struct {
	Enable       bool     `yaml:"enable"`
	GetType      string   `yaml:"gettype"`
	URL          string   `yaml:"url"`
	NetInterface string   `yaml:"netinterface"`
	Cmd          string   `yaml:"cmd"`
	IPv6Reg      string   `yaml:"ipv6reg,omitempty"`
	Domains      []string `yaml:"domains"`
}

type ddnsGoConfig struct {
	NotAllowWanAccess bool          `yaml:"notallowwanaccess"`
	DNSConf           []dnsConfItem `yaml:"dnsconf"`
}

// renderDDNSConfig 将 NodeConfigRequest JSON 转换为 ddns-go YAML 配置。
// 返回 (yaml输出, sha256 hash, 错误)。DNS Key 缺失时返回明确错误供调用方处理。
func renderDDNSConfig(jsonCfg string, s *store.ManagerStore) (yamlOut string, hash string, err error) {
	type nc struct {
		DNSKeyName  string           `json:"dns_key_name"`
		DnsProvider string           `json:"dns_provider"`
		TTL         string           `json:"ttl"`
		IPv4        model.IPv4Config `json:"ipv4"`
		IPv6        model.IPv6Config `json:"ipv6"`
	}
	var c nc
	if err := json.Unmarshal([]byte(jsonCfg), &c); err != nil {
		return "", "", fmt.Errorf("JSON解析失败: %w", err)
	}
	keys, _ := s.LoadDNSKeys()
	var dk *model.DNSKeyRecord
	if c.DNSKeyName != "" {
		dk = keys[c.DNSKeyName]
	} else if c.DnsProvider != "" {
		// backward compat: find first key matching provider
		for _, v := range keys {
			if v.Provider == c.DnsProvider { dk = v; break }
		}
	}
	if dk == nil {
		return "", "", fmt.Errorf("DNS密钥未找到 (名称=%q 提供商=%q) — 请检查「DNS Key」页面是否已配置", c.DNSKeyName, c.DnsProvider)
	}

	if c.TTL == "" {
		c.TTL = "300"
	}

	// sensible defaults for IP detection service URLs
	if c.IPv4.Enable {
		if c.IPv4.GetType == "" {
			c.IPv4.GetType = "url"
		}
		if c.IPv4.GetType == "url" && c.IPv4.URL == "" {
			c.IPv4.URL = "http://ipv4.icanhazip.com,http://checkip.amazonaws.com,http://api.ipify.org"
		}
	}
	if c.IPv6.Enable {
		if c.IPv6.GetType == "" {
			c.IPv6.GetType = "url"
		}
		if c.IPv6.GetType == "url" && c.IPv6.URL == "" {
			c.IPv6.URL = "http://api6.ipify.org"
		}
	}

	cfg := ddnsGoConfig{
		NotAllowWanAccess: true,
		DNSConf: []dnsConfItem{{
			DNS: dnsAuth{
				Name:   dk.Provider,
				ID:     dk.AccessKeyID,
				Secret: dk.AccessKeySecret,
			},
			IPv4: ipConf{
				Enable:       c.IPv4.Enable,
				GetType:      c.IPv4.GetType,
				URL:          c.IPv4.URL,
				NetInterface: c.IPv4.NetInterface,
				Cmd:          c.IPv4.Cmd,
				Domains:      c.IPv4.Domains,
			},
			IPv6: ipv6Conf{
				Enable:       c.IPv6.Enable,
				GetType:      c.IPv6.GetType,
				URL:          c.IPv6.URL,
				NetInterface: c.IPv6.NetInterface,
				Cmd:          c.IPv6.Cmd,
				IPv6Reg:      c.IPv6.IPv6Reg,
				Domains:      c.IPv6.Domains,
			},
			TTL: c.TTL,
		}},
	}

	yamlBytes, err := yaml.Marshal(&cfg)
	if err != nil {
		return "", "", fmt.Errorf("YAML序列化失败: %w", err)
	}
	yamlOut = "# ddns-go config generated by ddns-manager v2\n" + string(yamlBytes)
	h := sha256.Sum256([]byte(yamlOut))
	hash = "sha256:" + fmt.Sprintf("%x", h[:])
	return
}


// detectPlatform 将节点硬件信息映射为 Go 标准平台字符串 (goos-goarch)。
// 用于 manifest (agent_manifest.json) 键查找和 AgentUpdate.URL 构建。
// ⚠️ 架构归一化: deb 命名 (x86_64/aarch64/armv7l) → Go 标准 (amd64/arm64/arm)。
// 构建脚本产出的文件名使用 Go 标准命名，manifest 键也为 Go 标准命名。
// 返回 ("", "") 表示硬件信息未知，调用方应跳过升级推送。
func detectPlatform(rec *model.NodeRecord) (goos, goarch string) {
	if rec.Hardware == nil {
		return "", ""
	}
	goos = "linux"
	if strings.Contains(strings.ToLower(rec.Hardware.OS), "windows") {
		goos = "windows"
	}
	// 归一化架构名: deb 命名 → Go 标准命名
	arch := strings.ToLower(rec.Hardware.Arch)
	switch arch {
	case "amd64", "x86_64":
		goarch = "amd64"
	case "arm64", "aarch64":
		goarch = "arm64"
	case "386", "i386", "i686":
		goarch = "i386"
	case "arm", "armv6l", "armv7l", "armv8l", "armhf":
		goarch = "arm"
	default:
		if rec.Hardware.Arch != "" {
			goarch = rec.Hardware.Arch
		}
	}
	return
}

func parseAuth(r *http.Request) (nodeID, password string, ok bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", "", false
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(data), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

