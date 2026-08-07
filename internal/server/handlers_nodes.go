package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	mycrypto "github.com/ocoj/ddns-manager/internal/crypto"
	"github.com/ocoj/ddns-manager/internal/model"
	"github.com/ocoj/ddns-manager/internal/store"
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
		s.tryNotify("security", "未知节点心跳", fmt.Sprintf("node=%s ip=%s", nodeID, clientIP(r)), "unknown_node:"+nodeID)
		jsonErr(w, http.StatusUnauthorized, "未知节点")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(rec.PasswordHash), []byte(password)); err != nil {
		s.logMgr.LogWithNode("heartbeat", "认证失败", nodeID, fmt.Sprintf("密码错误 IP=%s", clientIP(r)), "warning")
		s.tryNotify("security", "心跳认证失败", fmt.Sprintf("node=%s 密码错误 ip=%s", nodeID, clientIP(r)), "auth_failure:"+nodeID)
		jsonErr(w, http.StatusUnauthorized, "密码错误")
		return
	}
	if subtle.ConstantTimeCompare([]byte(rec.Fingerprint), []byte(req.Fingerprint)) != 1 {
		s.logMgr.LogWithNode("heartbeat", "认证失败", nodeID, fmt.Sprintf("指纹不匹配 IP=%s", clientIP(r)), "security")
		jsonErr(w, http.StatusForbidden, "指纹不匹配")
		return
	}
	rec.LastSeen = s.nowInTZ()
	if req.Status.IPv4 != "" {
		rec.Status.IPv4 = sanitizeIP(req.Status.IPv4)
	}
	if req.Status.IPv6 != "" {
		rec.Status.IPv6 = sanitizeIP(req.Status.IPv6)
	}
	rec.Status.AgentVersion = req.Status.AgentVersion
	rec.Status.CertHashes = req.Status.CertHashes
	rec.Status.CertErrors = req.Status.CertErrors // v1.5.31 C1: 结构化存储证书部署错误, 供 WebUI 展示
	rec.Status.CertPath = req.Status.CertPath     // v1.5.37: 持久化证书路径, 供 WebUI 获取 Agent CertPath
	rec.Status.IISBoundSites = req.Status.IISBoundSites // v1.6.0: IIS 绑定快照
	oldStatus := ""
	if rec.Status.DDNSHealth != nil {
		oldStatus = rec.Status.DDNSHealth.Status
	}
	if req.Status.DDNSHealth != nil {
		rec.Status.DDNSHealth = req.Status.DDNSHealth
	}
	h := rec.Status.DDNSHealth
	switch {
	case h == nil:
		h = &model.DDNSHealthInfo{Status: "DOWN", StatusMsg: "no health data"}
		rec.Status.DDNSHealth = h
	case h.Running && h.LastOK:
		// 成功: 立即清零失败计数器, 状态恢复 OK
		rec.DNSConsecutiveFailures = 0
		// v1.6.46: 协议级独立判定 — IPv4/IPv6 各自检查, 一个好一个坏不隐藏故障
		var warnParts []string
		if h.IPv4Enabled && h.IPv4Msg == "获取失败" {
			warnParts = append(warnParts, "IPv4获取失败")
		}
		if h.IPv6Enabled && h.IPv6Msg == "获取失败" {
			warnParts = append(warnParts, "IPv6获取失败")
		}
		if len(warnParts) > 0 {
			h.Status, h.StatusMsg = "WARN", strings.Join(warnParts, ", ")+"(检查接口名/获取方式)"
		} else {
			h.Status, h.StatusMsg = "OK", ""
		}
	case h.Running && !h.LastOK:
		// v1.6.46: 连续失败防抖 — 单次失败→WARN, 连续≥2次→ERR
		// DNS API 偶发限流/超时不应立即标红, 给一次重试机会
		rec.DNSConsecutiveFailures++
		if rec.DNSConsecutiveFailures >= 2 {
			h.Status, h.StatusMsg = "ERR", fmt.Sprintf("连续%d次更新失败: %s", rec.DNSConsecutiveFailures, h.LastError)
		} else {
			h.Status, h.StatusMsg = "WARN", fmt.Sprintf("上次更新失败(第%d次): %s", rec.DNSConsecutiveFailures, h.LastError)
		}
	// v1.6.46: Running 永不置 false (DNSUpdater 对象存在即 Running=true),
	// 此分支为防御性代码 — 仅在数据结构异常时触发
	// 真实"DOWN"由心跳超时检测 (now.Sub(n.LastSeen) > 10min) 判定
	default:
		h.Status, h.StatusMsg = "UNKNOWN", "unexpected state"
	}
	// v1.6.49: 健康状态变更日志 — 好变坏、坏变好都记录
	if h.Status != oldStatus {
		st := "info"
		if h.Status == "ERR" || h.Status == "DOWN" {
			st = "error"
		} else if h.Status == "WARN" {
			st = "warning"
		} else if h.Status == "OK" {
			st = "success"
		}
		from := oldStatus
		if from == "" { from = "—" }
		msg := h.StatusMsg
		if msg == "" { msg = h.Status }
		s.logMgr.LogWithNode("节点", "健康状态变更", "管理端",
			fmt.Sprintf("%s 健康状态变更 %s → %s (%s)", nodeID, from, h.Status, msg), st)
	}
	if req.Hardware != nil {
		rec.Hardware = req.Hardware
	}
	// v1.6.11 B3: 心跳日志含 IP 获取状态, 便于诊断"无IP但DDNS=OK"问题
	detail := fmt.Sprintf("ddns=%s ipv4=%s(%s) ipv6=%s(%s)",
		h.Status, req.Status.IPv4, h.IPv4Msg, req.Status.IPv6, h.IPv6Msg)
	if h.Status != "OK" {
		if h.LastError != "" {
			detail += fmt.Sprintf(" err=%s", h.LastError)
		}
		if len(h.FailedDomains) > 0 {
			detail += fmt.Sprintf(" failed=%s", strings.Join(h.FailedDomains, ","))
		}
		// v1.5.33+v1.6.45 H4: 心跳 detail 仅含简短摘要 (LastError/FailedDomains), 
		// 完整错误详情仅通过独立日志记录 (下方 LogWithNode), 避免 events.log 中重复存储 500 字符 detail
		if h.LastErrorDetail != "" {
			detail += fmt.Sprintf(" detail(len=%d)", len(h.LastErrorDetail))
		}
		// v1.6.33 P4: DNS 更新失败时独立记录完整错误详情, 不依赖心跳 detail 的可能截断
		s.logMgr.LogWithNode("dns-update", "DNS更新失败", nodeID,
			fmt.Sprintf("err=%s failed=%v detail=%s", h.LastError, h.FailedDomains, h.LastErrorDetail), "error")
	}
	// v1.5.31 C1: 证书部署错误计入心跳详情和结构化状态
	if len(req.Status.CertErrors) > 0 {
		detail += fmt.Sprintf(" cert_errs=%d", len(req.Status.CertErrors))
	}
	s.logMgr.LogWithNode("heartbeat", "收到心跳", nodeID, detail, "info")

	// v1.5.29 C2: 处理 Agent 上报的 DNS 更新日志和操作日志
	// 限制最多各 20 条，防止日志洪泛
	logLimit := 100 // v1.6.44 H1: 20→100, 防升级/证书/配置操作日志被截断
	// v1.6.56: 限制单条日志行长度，防止 DoS
	const maxLogLineLen = 4096
	for i, logLine := range req.Logs {
		if i >= logLimit {
			break
		}
		s.logMgr.LogWithNode("dns-update", "DNS日志", nodeID, logLine, classifyLogStatus(logLine))
	}
	for i, logLine := range req.AgentLogs {
		if i >= logLimit {
			break
		}
		s.logMgr.LogWithNode("agent", "Agent操作", nodeID, logLine, classifyLogStatus(logLine))
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
			// v1.6.33 P7: 使用 CompareSemVer 替代字符串直接判等
			// 修复 Manager存"1.6.33" vs Agent报"v1.6.33" 导致的升级完成永不触发
			if agentCfg.LatestVersion == "" || model.CompareSemVer(agentCfg.LatestVersion, req.Status.AgentVersion) == 0 {
				// 版本相同 → 标记完成 (如果之前有升级任务)
				if agentCfg.UpgradeState != nil {
					if job, ok := agentCfg.UpgradeState[nodeID]; ok {
						if job.Completed == "" && model.CompareSemVer(job.TargetVer, req.Status.AgentVersion) == 0 {
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
					// v1.6.33 P7: CompareSemVer 替代字符串判等 (Manager无v前缀 vs Agent带v前缀)
					if job.Completed == "" && model.CompareSemVer(job.TargetVer, req.Status.AgentVersion) == 0 {
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
	// v1.6.61: 事件驱动 — 仅当 Agent 上报 hash 或 Manager 记录 hash 为空(首次/变更)时才渲染推送,
	// 避免 99% 稳定心跳的重渲染。rec.ConfigHash=="" 由"保存配置 / 保存/删除 DNS key"触发
	// (CHANGELOG:1192 首次推送兜底, 防止新节点双方 hash 均为空时永不推送)。
	// v1.6.64 方案B: 新增 rec.ConfigKeysVersion < curKeyVer — 持久化 DNS key 版本比对,
	// 修复关机/离线节点错过 Invalidate 瞬时信号导致配置永不推送的死锁 (win-test 案例)。
	curKeyVer := s.store.DNSKeysVersion()
	if rec.ConfigYAML != "" && (req.ConfigHash != rec.ConfigHash || rec.ConfigHash == "" ||
		rec.ConfigKeysVersion < curKeyVer) {
		rendered, cfgHash, renderErr := renderDDNSConfig(rec.ConfigYAML, s.store)
		if renderErr != nil {
			s.logMgr.LogWithNode("config", "配置渲染失败", nodeID,
				renderErr.Error(), "error")
			// 回传错误给 Agent，便于诊断
			resp.ConfigError = renderErr.Error()
		} else if rendered != "" {
			// v1.6.64 方案B: 渲染成功即同步 key 版本 (无论是否推送),
			// 避免版本永远落后导致每心跳重渲染
			rec.ConfigKeysVersion = curKeyVer
			// v1.6.64 方案B: 推送收紧为 cfgHash != req.ConfigHash —
			// 版本落后但 Agent 已是最新内容时只同步版本, 不冗余推送
			if cfgHash != req.ConfigHash {
				s.logMgr.LogWithNode("config", "配置已下发", nodeID,
					fmt.Sprintf("%d bytes", len(rendered)), "success")
				resp.Config = &model.ConfigPush{YAML: rendered, Hash: cfgHash}
				rec.ConfigHash = cfgHash
				rec.ConfigSentAt = s.nowInTZ()
			}
		}
	}
	key := mycrypto.DeriveKey(password, rec.Fingerprint, "cert-transport")
	for _, binding := range rec.CertBindings {
		bundle, err := s.store.LoadCertBundle(binding.BundleName)
		if err != nil {
			// v1.6.29 C2: 证书加载失败时保留旧 hash, 防止每心跳重推证书
			// 原因: LoadCertBundle 失败 (权限/磁盘满) → 清空 hash
			// → 下个心跳 hash 不匹配 → 重新推送 → 再次加载失败 → 永久死循环
			// 正确做法: 保留旧 hash, bundle 恢复后通过正常 hash 比对机制下发
			s.logMgr.LogWithNode("cert", "证书加载失败(保hash)", nodeID,
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
		// v1.6.65: 强制推送标记 — 跳过 matched 判定。解决"文件已写入但 IIS 绑定
		// 失败, 磁盘 hash 与 meta 匹配导致 Manager 永不重推"的死锁 (sp 事故:
		// 推送判定用 Agent 实时上报 hash, 旧版 force push 清空 cert_hashes 无效)。
		forcePush := false
		if rec.ForcePushBundles != nil && rec.ForcePushBundles[binding.BundleName] {
			forcePush = true
		}
		if matched && !forcePush {
			continue
		}
		// 存量上传证书从未存过 PFXPassword（上传 Bug 历史遗留）。
		// 首次心跳时检测到空密码 → 自动回填默认密码。
		// 这些证书的 PFX 文件在创建时就是用默认密码加密的，
		// 回填是陈述事实，hash 不变，不触发无意义部署。
		if bundle.PFXPassword == "" {
			bundle.PFXPassword = mycrypto.DefaultPFXPassword
			s.store.SaveCertBundle(bundle)
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
		// v1.6.34+v1.6.49: DeployPath 自动构造并消隐泛域名 * 号
		// 每个证书独立子目录, 避免多证书覆盖; Agent 端二次校验在 agentBaseDir 内
		targetPath := binding.DeployPath
		if targetPath == "" && req.Status.CertPath != "" && binding.BundleName != "" {
			targetPath = req.Status.CertPath + "/" + model.SanitizeCertDirName(binding.BundleName)
		} else if strings.Contains(targetPath, "*") {
			targetPath = strings.ReplaceAll(targetPath, "*", "_")
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
				fmt.Sprintf("bundle=%s (无PFX密码,Agent将用默认值) hash=%s...", binding.BundleName, bundle.Hash[:14]), "warning")
		}
		s.logMgr.LogWithNode("cert", "证书已下发", nodeID,
			fmt.Sprintf("bundle=%s hash=%s... path=%s", binding.BundleName, bundle.Hash[:14], targetPath), "success")
		// v1.6.65: 推送成功后清除强制推送标记, 下个心跳恢复正常 hash 比对
		if forcePush {
			delete(rec.ForcePushBundles, binding.BundleName)
		}
	}
	// persist all changes in a single write (LastSeen, Status, Hardware, ConfigHash)
	s.store.PutNode(nodeID, rec)
	jsonOK(w, resp)
}

// ── admin: dashboard ──


func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.LoadNodes()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "加载节点列表失败")
		return
	}
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
		// v1.6.56: 校验证书绑定引用的 Bundle 是否存在
		for _, cb := range req.CertBindings {
			if _, err := s.store.LoadCertBundle(cb.BundleName); err != nil {
				jsonErr(w, http.StatusBadRequest,
					fmt.Sprintf("证书集 %q 不存在", cb.BundleName))
				return
			}
		}
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
// classifyLogStatus 根据日志内容判定事件状态：含失败/错误关键词 → error，否则 info。
func classifyLogStatus(line string) string {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "失败") || strings.Contains(lower, "错误") ||
		strings.Contains(lower, "error") || strings.Contains(lower, "fail") ||
		strings.Contains(lower, "异常") ||
		strings.Contains(lower, "timed") || strings.Contains(lower, "refused") ||
		strings.Contains(lower, "denied") || strings.Contains(lower, "expired") ||
		strings.Contains(lower, "forbidden") || strings.Contains(lower, "invalid") {
		return "error"
	}
	return "info"
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
	keys, _ := s.store.LoadDNSKeys()
	if req.DNSKeyName != "" {
		if _, ok := keys[req.DNSKeyName]; !ok {
			jsonErr(w, http.StatusBadRequest, fmt.Sprintf("DNS Key %q 不存在，请先在「DNS Key」页面创建", req.DNSKeyName))
			return
		}
	}
	// v1.6.49: 同样校验多卡片 dns_confs 中的每个 key
	for _, ci := range req.DnsConfs {
		if ci.DnsKey != "" {
			if _, ok := keys[ci.DnsKey]; !ok {
				jsonErr(w, http.StatusBadRequest, fmt.Sprintf("DNS卡片 %q 引用的 Key %q 不存在，请先在「DNS Key」页面创建", ci.Name, ci.DnsKey))
				return
			}
		}
	}
	// v1.5.30 C1: 校验节点配置合法性（域名格式/TTL/URL/GetType 等）
	if err := validateNodeConfig(&req, keys); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// v1.6.54: 先自动填充 deploy_path，再校验 — 填充后绝对路径可在 certBase 白名单内通过
// 空路径 → 自动生成 {CertPath}/{sanitized_BundleName}
// 已有路径含 * → 替换为 _ (防止旧配置循环回带)
if rec.Status.CertPath != "" {
		for i := range req.CertBindings {
			if req.CertBindings[i].BundleName == "" {
				continue
			}
			safeName := model.SanitizeCertDirName(req.CertBindings[i].BundleName)
			if req.CertBindings[i].DeployPath == "" {
				req.CertBindings[i].DeployPath = rec.Status.CertPath + "/" + safeName
			} else if strings.Contains(req.CertBindings[i].DeployPath, "*") {
				req.CertBindings[i].DeployPath = strings.ReplaceAll(req.CertBindings[i].DeployPath, "*", "_")
			}
		}
	}
	// 填充后校验: 白名单 — 部署路径必须在 Agent 上报的证书目录下
	for i, binding := range req.CertBindings {
		if err := validateCertBinding(binding, rec.Status.CertPath); err != nil {
			jsonErr(w, http.StatusBadRequest, fmt.Sprintf("证书绑定[%d]配置无效: %v", i, err))
			return
		}
	}

	// v1.6.36 C1: 必须在覆盖 ConfigYAML 之前提取旧 DNS key 名称
	// v1.6.49: 同时从多卡片 dns_confs 提取旧 key 引用
	var oldDNSKeyNames []string
	if rec.ConfigYAML != "" {
		var oldReq model.NodeConfigRequest
		if json.Unmarshal([]byte(rec.ConfigYAML), &oldReq) == nil {
			if oldReq.DNSKeyName != "" {
				oldDNSKeyNames = append(oldDNSKeyNames, oldReq.DNSKeyName)
			}
			if oldReq.DnsProvider != "" {
				oldDNSKeyNames = append(oldDNSKeyNames, oldReq.DnsProvider)
			}
			for _, ci := range oldReq.DnsConfs {
				if ci.DnsKey != "" {
					oldDNSKeyNames = append(oldDNSKeyNames, ci.DnsKey)
				}
			}
		}
	}

	data, err := json.Marshal(req)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "配置序列化失败")
		s.logMgr.LogWithNode("config", "配置序列化失败", id, err.Error(), "error")
		return
	}
	rec.ConfigYAML = string(data)
	// v1.6.42 M7: cert_bindings 三层语义 (nil/[]空/[有值]):
	//   前端不发该字段 (nil)  → 保留现有绑定, 不修改
	//   前端发空数组 ([])      → 清空所有绑定, 节点不再接收证书
	//   前端发非空数组 ([...])  → 替换所有绑定
	// CertBindings 优先于 ConfigYAML 中的 cert_bindings 用于证书推送判定
	if req.CertBindings != nil && len(req.CertBindings) == 0 {
		rec.CertBindings = nil  // 显式清空
	} else if req.CertBindings != nil {
		rec.CertBindings = req.CertBindings
	}
	rec.ConfigHash = ""

	// v1.6.29 H5: 证书绑定验证对所有节点配置保存操作执行 (原仅未审批路径)
	// 已审批节点的证书被删除后, 若不验证则心跳时 LoadCertBundle 失败 → 推送循环
	for _, binding := range req.CertBindings {
		if _, err := s.store.LoadCertBundle(binding.BundleName); err != nil {
			s.logMgr.LogWithNode("节点", "配置保存失败", id,
				fmt.Sprintf("证书 %q 不存在: %v", binding.BundleName, err), "warning")
			jsonErr(w, http.StatusBadRequest,
				fmt.Sprintf("证书绑定 %q 不存在, 请先上传或申请该证书", binding.BundleName))
			return
		}
	}
	// 保存配置即审批 — 管理员已配置意味着信任该节点
	if !rec.Approved {
		rec.Approved = true
		s.logMgr.LogWithNode("节点", "配置已保存(自动审批)", id, "", "info")
	}
	s.store.PutNode(id, rec)
	// v1.6.49: 从多卡片 dns_confs 提取 DNS key 名称用于日志和引用追踪
	var dnsKeyNames []string
	seen := map[string]bool{}
	for _, ci := range req.DnsConfs {
		if ci.DnsKey != "" && !seen[ci.DnsKey] {
			dnsKeyNames = append(dnsKeyNames, ci.DnsKey)
			seen[ci.DnsKey] = true
		}
	}
	dnsKeyLog := strings.Join(dnsKeyNames, ",")
	if dnsKeyLog == "" {
		dnsKeyLog = req.DNSKeyName // 兼容旧格式
	}
	s.logMgr.LogWithNode("config", "已保存", id, fmt.Sprintf("dnsKey=%s", dnsKeyLog), "success")

	// v1.6.36 C3: 原子替换 DNS key 引用 — 全程持写锁读-删-加-写
	// v1.6.49: 追踪 dns_confs 中的所有 key（不再只看旧格式字段）
	s.store.RemoveNodeFromDNSKeys(id)
	for _, dn := range dnsKeyNames {
		s.store.TrackDNSKeyUsage(dn, id)
	}
	// 兼容旧格式: 顶层 DNSKeyName + 域名级 key
	newDNSKeyName := req.DNSKeyName
	if newDNSKeyName == "" {
		newDNSKeyName = req.DnsProvider
	}
	if newDNSKeyName != "" && !seen[newDNSKeyName] {
		s.store.TrackDNSKeyUsage(newDNSKeyName, id)
	}
	for _, d := range req.IPv4.Domains {
		if d.DNSKeyName != "" && !seen[d.DNSKeyName] {
			s.store.TrackDNSKeyUsage(d.DNSKeyName, id)
		}
	}
	for _, d := range req.IPv6.Domains {
		if d.DNSKeyName != "" && !seen[d.DNSKeyName] {
			s.store.TrackDNSKeyUsage(d.DNSKeyName, id)
		}
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
// v1.6.48: 支持新格式 dns_confs 数组，每段独立 DNS Key/IPv4/IPv6/TTL
func renderDDNSConfig(jsonCfg string, s *store.ManagerStore) (yamlOut string, hash string, err error) {
	type nc struct {
		DNSKeyName  string             `json:"dns_key_name"`
		DnsProvider string             `json:"dns_provider"`
		TTL         string             `json:"ttl"`
		IPv4        model.IPv4Config   `json:"ipv4"`
		IPv6        model.IPv6Config   `json:"ipv6"`
		DnsConfs    []model.DnsConfItem `json:"dns_confs"`
	}
	var c nc
	if err := json.Unmarshal([]byte(jsonCfg), &c); err != nil {
		return "", "", fmt.Errorf("JSON解析失败: %w", err)
	}
	keys, _ := s.LoadDNSKeys()

	// helper: render one DnsConfItem to dnsConfItem (YAML struct)
	renderOne := func(ci model.DnsConfItem) (*dnsConfItem, error) {
		dk, ok := keys[ci.DnsKey]
		if !ok {
			return nil, fmt.Errorf("DNS密钥 %q 未找到", ci.DnsKey)
		}
		if dk.Provider == "" {
			return nil, fmt.Errorf("DNS密钥 %q 的提供商字段为空", dk.Name)
		}
		ttl := ci.TTL
		if ttl == "" {
			ttl = "300"
		}
		// normalize getType
		normGT := func(gt string) string {
			gt = strings.ToLower(gt)
			if gt == "netinterface" {
				return "netInterface"
			}
			return gt
		}
		v4 := ci.IPv4
		v4.GetType = normGT(v4.GetType)
		v6 := ci.IPv6
		v6.GetType = normGT(v6.GetType)
		// defaults
		if v4.Enable && v4.GetType == "" {
			v4.GetType = "url"
		}
		if v4.Enable && v4.GetType == "url" && v4.URL == "" {
			v4.URL = "http://ipv4.icanhazip.com,http://checkip.amazonaws.com,http://api.ipify.org"
		}
		if v6.Enable && v6.GetType == "" {
			v6.GetType = "url"
		}
		if v6.Enable && v6.GetType == "url" && v6.URL == "" {
			v6.URL = "http://api6.ipify.org"
		}
		// domains: flatten DomainConfig → []string
		v4Domains := make([]string, 0, len(v4.Domains))
		for _, d := range v4.Domains {
			if d.Domain != "" {
				v4Domains = append(v4Domains, d.Domain)
			}
		}
		v6Domains := make([]string, 0, len(v6.Domains))
		for _, d := range v6.Domains {
			if d.Domain != "" {
				v6Domains = append(v6Domains, d.Domain)
			}
		}
		// v1.6.49: 防呆 — 启用但无域名 → 视为未启用
		if v4.Enable && len(v4Domains) == 0 { v4.Enable = false }
		if v6.Enable && len(v6Domains) == 0 { v6.Enable = false }
		return &dnsConfItem{
			DNS: dnsAuth{Name: dk.Provider, ID: dk.AccessKeyID, Secret: dk.AccessKeySecret},
			IPv4: ipConf{Enable: v4.Enable, GetType: v4.GetType, URL: v4.URL,
				NetInterface: v4.NetInterface, Cmd: v4.Cmd, Domains: v4Domains},
			IPv6: ipv6Conf{Enable: v6.Enable, GetType: v6.GetType, URL: v6.URL,
				NetInterface: v6.NetInterface, Cmd: v6.Cmd, IPv6Reg: v6.IPv6Reg, Domains: v6Domains},
			TTL: ttl,
		}, nil
	}

	// v1.6.48: 优先新格式 dns_confs
	if len(c.DnsConfs) > 0 {
		var items []dnsConfItem
		for _, ci := range c.DnsConfs {
			item, err := renderOne(ci)
			if err != nil {
				return "", "", err
			}
			items = append(items, *item)
		}
		cfg := ddnsGoConfig{NotAllowWanAccess: true, DNSConf: items}
		yamlBytes, _ := yaml.Marshal(&cfg)
		yamlOut = "# ddns-go config generated by ddns-manager v2\n" + string(yamlBytes)
		for i := range cfg.DNSConf {
			cfg.DNSConf[i].DNS.Secret = ""
		}
		hash = "sha256:" + fmt.Sprintf("%x", sha256.Sum256([]byte(yamlOut)))
		return
	}

	// ── 旧格式兼容 (ipv4/ipv6/dns_key_name 顶层字段) ──
	var dk *model.DNSKeyRecord
	if c.DNSKeyName != "" {
		dk = keys[c.DNSKeyName]
	} else if c.DnsProvider != "" {
		for _, v := range keys {
			if v.Provider == c.DnsProvider {
				dk = v
				break
			}
		}
	}
	if dk == nil {
		return "", "", fmt.Errorf("DNS密钥未找到 (名称=%q 提供商=%q)", c.DNSKeyName, c.DnsProvider)
	}
	if dk.Provider == "" {
		return "", "", fmt.Errorf("DNS密钥 %q 的提供商字段为空", dk.Name)
	}
	// migrate old format to single-item dns_confs
	migrated := model.DnsConfItem{
		Name:   dk.Name,
		DnsKey: dk.Name,
		IPv4:   c.IPv4,
		IPv6:   c.IPv6,
		TTL:    c.TTL,
	}
	item, err := renderOne(migrated)
	if err != nil {
		return "", "", err
	}
	cfg := ddnsGoConfig{NotAllowWanAccess: true, DNSConf: []dnsConfItem{*item}}
	yamlBytes, _ := yaml.Marshal(&cfg)
	yamlOut = "# ddns-go config generated by ddns-manager v2\n" + string(yamlBytes)
	cfg.DNSConf[0].DNS.Secret = ""
	hash = "sha256:" + fmt.Sprintf("%x", sha256.Sum256([]byte(yamlOut)))
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
		// v1.6.28 C5: default 分支归一化未知架构变体（如 "ARM64"→"arm64", "x86_64"→"amd64"）
		// 否则 manifest key "linux-ARM64" 不匹配 "linux-arm64" → 升级推送静默跳过
		if rec.Hardware.Arch != "" {
			goarch = strings.ToLower(rec.Hardware.Arch)
			// 二次归一化: 非标准别名映射
			switch goarch {
			case "x86_64":
				goarch = "amd64"
			case "aarch64":
				goarch = "arm64"
			case "i686", "i386":
				goarch = "i386"
			case "armv6l", "armv7l", "armv8l", "armhf":
				goarch = "arm"
			}
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

// sanitizeIP 规范化 Agent 上报的 IP 地址，非 IP 格式返回 "&lt;invalid&gt;"
func sanitizeIP(ip string) string {
	if ip == "" {
		return ""
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String()
	}
	return "&lt;invalid&gt;"
}

// ── v1.5.30 输入验证 ──

// validDomainRE 域名格式校验：标准 FQDN 标签，不支持通配符和 IDN。
var validDomainRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

// validateNodeConfig 校验 NodeConfigRequest 的字段合法性，防止非法输入导致
// ddns-go YAML 渲染异常或 DNS API 调用失败。
func validateNodeConfig(req *model.NodeConfigRequest, keys map[string]*model.DNSKeyRecord) error {
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
func validateDomains(domains []model.DomainConfig) error {
	if len(domains) == 0 {
		return fmt.Errorf("至少需要1个域名")
	}
	for _, d := range domains {
		dd := strings.TrimSpace(d.Domain)
		if dd == "" {
			return fmt.Errorf("域名不能为空")
		}
		if len(dd) > 253 {
			return fmt.Errorf("域名过长 (>253): %q", dd)
		}
		if strings.HasPrefix(dd, "*.") {
			return fmt.Errorf("不支持泛域名: %q", dd)
		}
		if !validDomainRE.MatchString(dd) {
			return fmt.Errorf("域名格式无效: %q", dd)
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

// validateCertBinding 校验证书绑定的配置合法性，白名单防路径穿越。
// certBase 为 Agent 上报的证书目录（如 /opt/ddns-agent/certs），
// DeployPath 必须在 certBase 子树内。
func validateCertBinding(b model.CertBinding, certBase string) error {
	if b.BundleName == "" {
		return fmt.Errorf("证书名称不能为空")
	}
	if b.DeployPath == "" {
		return fmt.Errorf("部署路径不能为空")
	}
	// 白名单: 只允许 certBase 或其子目录
	if certBase != "" && !strings.HasPrefix(b.DeployPath, certBase+"/") && b.DeployPath != certBase {
		return fmt.Errorf("部署路径必须在证书目录下: %q (当前: %q)", certBase, b.DeployPath)
	}
	return nil
}

