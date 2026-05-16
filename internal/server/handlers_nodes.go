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
	"regexp"
	"sort"
	"strconv"
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
		s.tryNotify("security", "未知节点心跳", fmt.Sprintf("node=%s ip=%s", nodeID, clientIP(r)))
		jsonErr(w, http.StatusUnauthorized, "未知节点")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(rec.PasswordHash), []byte(password)); err != nil {
		s.logMgr.LogWithNode("heartbeat", "认证失败", nodeID, fmt.Sprintf("密码错误 IP=%s", clientIP(r)), "warning")
		s.tryNotify("security", "心跳认证失败", fmt.Sprintf("node=%s 密码错误 ip=%s", nodeID, clientIP(r)))
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
	rec.Status.CertErrors = req.Status.CertErrors // v1.5.31 C1: 结构化存储证书部署错误, 供 WebUI 展示
	rec.Status.CertPath = req.Status.CertPath     // v1.5.37: 持久化证书路径, 供 WebUI 获取 Agent CertPath
	rec.Status.IISBoundSites = req.Status.IISBoundSites // v1.6.0: IIS 绑定快照
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
	// v1.5.29 M3: 记录心跳含 DDNS 错误详情和失败域名
	detail := fmt.Sprintf("ddns=%s ipv4=%s ipv6=%s", h.Status, req.Status.IPv4, req.Status.IPv6)
	if h.Status != "OK" {
		if h.LastError != "" {
			detail += fmt.Sprintf(" err=%s", h.LastError)
		}
		if len(h.FailedDomains) > 0 {
			detail += fmt.Sprintf(" failed=%s", strings.Join(h.FailedDomains, ","))
		}
		// v1.5.33: 记录 ddns-go API 详细错误原文
		if h.LastErrorDetail != "" {
			detail += fmt.Sprintf(" detail=%s", h.LastErrorDetail)
		}
	}
	// v1.5.31 C1: 证书部署错误计入心跳详情和结构化状态
	if len(req.Status.CertErrors) > 0 {
		detail += fmt.Sprintf(" cert_errs=%d", len(req.Status.CertErrors))
	}
	s.logMgr.LogWithNode("heartbeat", "收到心跳", nodeID, detail, "info")

	// v1.5.29 C2: 处理 Agent 上报的 DNS 更新日志和操作日志
	// 限制最多各 20 条，防止日志洪泛
	logLimit := 20
	for i, logLine := range req.Logs {
		if i >= logLimit {
			break
		}
		s.logMgr.LogWithNode("dns-update", "DNS日志", nodeID, logLine, "info")
	}
	for i, logLine := range req.AgentLogs {
		if i >= logLimit {
			break
		}
		s.logMgr.LogWithNode("agent", "Agent操作", nodeID, logLine, "info")
	}
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
			// v1.6.10 M4: Completed 检查 移到 shouldPush 确定之后
			// 仅在本次心跳 不会 推送升级时才标记完成, 防止推送后Agent未升级但已完成标记
			if agentCfg.LatestVersion == "" || agentCfg.LatestVersion == req.Status.AgentVersion {
				// 版本相同 → 标记完成 (如果之前有升级任务)
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
						if job.TargetVer == agentCfg.LatestVersion && now.Sub(t) < 10*time.Minute {
						// v1.5.22 H1: 退避窗口 10 分钟 (≥2 心跳周期)
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
			// v1.6.10 M4: 仅当本次不会推送升级时, 才检查 Agent 版本是否已匹配并标记完成
			// 若 shouldPush=true (即将推送), 则等 Agent 真正升级后下个心跳再标记
			if !shouldPush {
				if job, ok := agentCfg.UpgradeState[nodeID]; ok {
					if job.Completed == "" && job.TargetVer == req.Status.AgentVersion {
						job.Completed = now.Format(time.RFC3339)
						agentCfg.UpgradeState[nodeID] = job
						s.logMgr.LogWithNode("upgrade", "升级已完成", nodeID,
							fmt.Sprintf("ver=%s", req.Status.AgentVersion), "success")
					}
				}
			}
			if shouldPush {
				safeName := strings.ReplaceAll(strings.ReplaceAll(manifestFile, "..", ""), "/", "")
				if safeName != "" && safeName == manifestFile {
					if _, err := os.Stat(filepath.Join(s.store.AgentBinDir(), safeName)); err == nil {
						// v1.5.36 C3: 携带 SHA256 校验和, Agent 下载后验证完整性
						checksum := s.store.GetAgentBinarySHA256(safeName)
						resp.AgentUpdate = &model.AgentUpdate{Version: agentCfg.LatestVersion, URL: "dl/" + safeName, Checksum: checksum}
					s.logMgr.LogWithNode("upgrade", "升级已推送", nodeID,
						fmt.Sprintf("ver=%s url=dl/%s sum=%s", agentCfg.LatestVersion, safeName, truncate(checksum, 12)), "info")
						if agentCfg.UpgradeState == nil {
							agentCfg.UpgradeState = make(map[string]store.UpgJob)
						}
						job := agentCfg.UpgradeState[nodeID]
						job.TargetVer = agentCfg.LatestVersion
						job.Triggered = now.Format(time.RFC3339)
						job.RetryCount++
						job.Completed = "" // v1.5.33: 清除旧版本完成标记, 避免新推送立即被过滤
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
		} else if rendered != "" && (req.ConfigHash != rec.ConfigHash || rec.ConfigHash == "") {
			// v1.5.29: ConfigHash 为空时（首次推送）强制下发，避免双方都为空导致永不推送
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
		// v1.5.41: Agent 部署到 CertPath/{BundleName}/ 子目录, key 使用 BundleName
		hashKey := binding.DeployPath
		// v1.6.10 M2: 统一遍历所有 CertHashes 中的 hash 值比对, 不依赖 key 名称
		// 旧方案依赖 BundleName/"."/CertPath 三重硬编码兜底, 新方案直接值比对
		matched := false
		if hashKey != "" {
			// 精确 key 匹配优先 (性能优化)
			if h, ok := req.Status.CertHashes[hashKey]; ok && h == bundle.Hash {
				matched = true
			}
		}
		if !matched {
			// 值遍历兜底: 任何 key 下的 hash 值匹配即跳过
			for _, reportedHash := range req.Status.CertHashes {
				if reportedHash == bundle.Hash {
					matched = true
					break
				}
			}
		}
		if matched {
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
		// v1.5.32: DeployPath 为空时取 Agent 上报的真实 CertPath, 保证 Manager/Agent 路径一致
		targetPath := binding.DeployPath
		if targetPath == "" {
			targetPath = req.Status.CertPath
		}
		resp.CertUpdates = append(resp.CertUpdates, &model.CertUpdate{
			CertHash: bundle.Hash, BundleName: binding.BundleName,
			Files: encFiles, TargetPath: targetPath,
			ReloadServices: binding.ReloadServices,
			PFXPassword: bundle.PFXPassword,
		})
		// v1.5.22 H3: PFX 密码为空时记录日志
		if bundle.PFXPassword == "" {
			s.logMgr.LogWithNode("cert", "证书已下发", nodeID,
				fmt.Sprintf("bundle=%s (无PFX密码,Agent将用默认ddns) hash=%s...", binding.BundleName, bundle.Hash[:14]), "warning")
		}
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
	now := s.nowInTZ()  // v1.5.22 H4: 使用配置时区，与心跳时间源一致
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
	// v1.5.30 C1: 校验节点配置合法性（域名格式/TTL/URL/GetType 等）
	if err := validateNodeConfig(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// v1.5.30 H3: 校验证书绑定 DeployPath 防止路径穿越
	for i, binding := range req.CertBindings {
		if err := validateCertBinding(binding); err != nil {
			jsonErr(w, http.StatusBadRequest, fmt.Sprintf("证书绑定[%d]配置无效: %v", i, err))
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
	// v1.5.22 H5: nil=保留, empty slice=清空
	// CertBindings 优先于 ConfigYAML 中的 cert_bindings 用于证书推送判定
	if req.CertBindings != nil && len(req.CertBindings) == 0 {
		rec.CertBindings = nil  // 显式清空
		// 注: ConfigYAML 中可能残留旧 cert_bindings JSON, 但不影响证书推送逻辑
		// (Manager 使用 rec.CertBindings, 非解析 ConfigYAML)
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

	// v1.5.32: normalize getType to lowercase (ddns-go expects lowercase; frontend may send camelCase)
	c.IPv4.GetType = strings.ToLower(c.IPv4.GetType)
	c.IPv6.GetType = strings.ToLower(c.IPv6.GetType)

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
	// v1.5.36 L3: 限制 Authorization header 长度，防止恶意 base64 输入导致 CPU 耗尽
	if len(auth) > 2048 {
		return "", "", false
	}
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

// ── v1.5.30 输入验证 ──

// validDomainRE 域名格式校验：标准 FQDN 标签，不支持通配符和 IDN。
var validDomainRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

// validateNodeConfig 校验 NodeConfigRequest 的字段合法性，防止非法输入导致
// ddns-go YAML 渲染异常或 DNS API 调用失败。
func validateNodeConfig(req *model.NodeConfigRequest) error {
	// IPv4 域名校验
	if req.IPv4.Enable {
		if err := validateDomains(req.IPv4.Domains); err != nil {
			return fmt.Errorf("IPv4域名: %w", err)
		}
		if err := validateIPConfig(req.IPv4.GetType, req.IPv4.URL, req.IPv4.NetInterface, req.IPv4.Cmd); err != nil {
			return fmt.Errorf("IPv4获取方式: %w", err)
		}
	}
	// IPv6 域名校验
	if req.IPv6.Enable {
		if err := validateDomains(req.IPv6.Domains); err != nil {
			return fmt.Errorf("IPv6域名: %w", err)
		}
		if err := validateIPConfig(req.IPv6.GetType, req.IPv6.URL, req.IPv6.NetInterface, req.IPv6.Cmd); err != nil {
			return fmt.Errorf("IPv6获取方式: %w", err)
		}
	}
	// TTL 校验
	if req.TTL != "" {
		ttl, err := strconv.Atoi(req.TTL)
		if err != nil {
			return fmt.Errorf("TTL 不是有效整数: %q", req.TTL)
		}
		if ttl < 60 || ttl > 86400 {
			return fmt.Errorf("TTL 必须在 60-86400 之间，当前 %d", ttl)
		}
	}
	return nil
}

// validateDomains 校验域名列表格式。
func validateDomains(domains []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("至少需要1个域名")
	}
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			return fmt.Errorf("域名不能为空")
		}
		if len(d) > 253 {
			return fmt.Errorf("域名过长 (>253): %q", d)
		}
		if strings.HasPrefix(d, "*.") {
			return fmt.Errorf("不支持泛域名: %q", d)
		}
		if !validDomainRE.MatchString(d) {
			return fmt.Errorf("域名格式无效: %q", d)
		}
	}
	return nil
}

// validateIPConfig 校验 IP 获取方式的配置合法性。
// v1.5.32: getType 先转小写, 兼容前端 netInterface→netinterface 大小写差异。
func validateIPConfig(getType, url, netInterface, cmd string) error {
	getType = strings.ToLower(getType)
	switch getType {
	case "url", "": // 空值默认为 url
		if url != "" {
			// v1.5.31 M2: ddns-go 支持逗号分隔的多 URL 列表, 逐段校验每个 URL
			for _, u := range strings.Split(url, ",") {
				u = strings.TrimSpace(u)
				if u == "" {
					continue
				}
				if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
					return fmt.Errorf("URL %q 必须以 http:// 或 https:// 开头", u)
				}
				if strings.ContainsAny(u, "\x00\n\r") {
					return fmt.Errorf("URL %q 包含控制字符", u)
				}
			}
		}
	case "netinterface":
		if netInterface != "" && strings.ContainsAny(netInterface, "/\\\x00") {
			return fmt.Errorf("网卡名称不能包含路径分隔符")
		}
	case "cmd":
		if cmd == "" {
			return fmt.Errorf("GetType=cmd 时必须提供 Cmd 命令")
		}
		if strings.Contains(cmd, "\x00") {
			return fmt.Errorf("Cmd 命令包含控制字符")
		}
	default:
		return fmt.Errorf("不支持的 GetType: %q (仅支持 url/netinterface/cmd)", getType)
	}
	return nil
}

// validateCertBinding 校验证书绑定的配置合法性，防路径穿越。
func validateCertBinding(b model.CertBinding) error {
	if b.BundleName == "" {
		return fmt.Errorf("证书名称不能为空")
	}
	if b.DeployPath != "" {
		if filepath.IsAbs(b.DeployPath) {
			return fmt.Errorf("部署路径不能为绝对路径: %q", b.DeployPath)
		}
		cleaned := filepath.Clean(b.DeployPath)
		if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
			return fmt.Errorf("部署路径不能包含上级目录引用: %q", b.DeployPath)
		}
	}
	return nil
}

