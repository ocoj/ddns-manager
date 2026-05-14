package server

import (
	"archive/zip"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/kk/ddns-manager/internal/model"
	"github.com/kk/ddns-manager/internal/store"
	"github.com/kk/ddns-manager/internal/logger"
	"github.com/kk/ddns-manager/internal/notify"
	"golang.org/x/crypto/bcrypt"
	"unicode/utf8"
)

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"status": "ok", "version": s.version})
}

func (s *Server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	st, _ := s.store.LoadAdminState()
	jsonOK(w, map[string]interface{}{"password_changed": st != nil && st.PasswordChanged})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Password string `json:"password"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	token := tokenFromPassword(req.Password)
	st, err := s.store.LoadAdminState()
	if err != nil || st == nil {
		jsonErr(w, http.StatusInternalServerError, "管理员状态不可用")
		return
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.getAdminToken())) != 1 {
		if err := bcrypt.CompareHashAndPassword([]byte(st.TokenHash), []byte(token)); err != nil {
			s.logMgr.LogAuth("登录失败", "admin", clientIP(r), "密码错误", "error")
			s.tryNotify("security", "管理员登录失败", fmt.Sprintf("ip=%s", clientIP(r)))
			jsonErr(w, http.StatusUnauthorized, "密码错误")
			return
		}
	}
	s.setAdminToken(token)
	s.logMgr.LogAuth("管理员登录", "admin", clientIP(r), "", "success")
	jsonOK(w, map[string]interface{}{"token": token, "password_changed": st.PasswordChanged})
}


func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID      string `json:"node_id"`
		Fingerprint string `json:"fingerprint"`
		Password    string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	if req.NodeID == "" || req.Fingerprint == "" {
		jsonErr(w, http.StatusBadRequest, "node_id 和 fingerprint 为必填项")
		return
	}
	nodes, _ := s.store.LoadNodes()
	if _, exists := nodes[req.NodeID]; exists {
		jsonErr(w, http.StatusConflict, "节点已注册")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logMgr.LogWithNode("节点", "注册", req.NodeID, "bcrypt 处理失败", "error")
		jsonErr(w, http.StatusInternalServerError, "服务器内部错误")
		return
	}
	rec := &model.NodeRecord{
		Fingerprint:  req.Fingerprint,
		PasswordHash: string(hash),
		CreatedAt:    s.nowInTZ(),
	}
	s.store.PutNode(req.NodeID, rec)
	s.logMgr.LogWithNode("节点", "注册", req.NodeID, "等待审批", "info")
	jsonOK(w, map[string]string{"node_id": req.NodeID, "status": "pending_approval"})
}

// ── heartbeat ──


func (s *Server) handleListDNSKeys(w http.ResponseWriter, r *http.Request) {
	keys, _ := s.store.LoadDNSKeys()
	jsonOK(w, keys)
}
func (s *Server) handleSaveDNSKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name            string `json:"name"`
		Provider        string `json:"provider"`
		AccessKeyID     string `json:"access_key_id"`
		AccessKeySecret string `json:"access_key_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	if req.Name == "" { req.Name = req.Provider } // backward compat
	if req.Name == "" || req.Provider == "" {
		jsonErr(w, http.StatusBadRequest, "名称和提供商为必填项")
		return
	}
	// 校验 DNS provider 名称 — 防止拼写错误导致后续配置渲染失败
	if !model.IsKnownDNSProvider(req.Provider) {
		jsonErr(w, http.StatusBadRequest, fmt.Sprintf("未知的DNS提供商: %q (支持的提供商: %s)", req.Provider, strings.Join(model.KnownDNSProviders(), ", ")))
		return
	}
	keys, _ := s.store.LoadDNSKeys()
	if keys == nil {
		keys = make(map[string]*model.DNSKeyRecord)
	}
	now := s.nowInTZ().Format(time.RFC3339)
	keyName := req.Name
	if existing, ok := keys[keyName]; ok {
		if req.Provider != "" { existing.Provider = req.Provider }
		if req.AccessKeyID != "" { existing.AccessKeyID = req.AccessKeyID }
		if req.AccessKeySecret != "" { existing.AccessKeySecret = req.AccessKeySecret }
		existing.UpdatedAt = now
	} else {
		keys[keyName] = &model.DNSKeyRecord{
			Name: req.Name, Provider: req.Provider,
			AccessKeyID: req.AccessKeyID, AccessKeySecret: req.AccessKeySecret, UpdatedAt: now,
		}
	}
	s.store.SaveDNSKeys(keys)
	s.logMgr.Log("dns-key", "已保存", keyName+" ("+req.Provider+")", "success")
	jsonOK(w, map[string]string{"status": "saved", "name": keyName, "provider": req.Provider})
}
func (s *Server) handleDeleteDNSKey(w http.ResponseWriter, r *http.Request) {
	p := mux.Vars(r)["name"]
	// 原子删除 — 持写锁读-删-写，防止并发覆盖
	if err := s.store.DeleteDNSKeyAtomic(p); err != nil {
		jsonErr(w, http.StatusNotFound, "密钥未找到")
		return
	}
	s.logMgr.Log("dns-key", "已删除", p, "info")
	jsonOK(w, map[string]string{"deleted": p})
}

// ── admin: cert bundles ──

func (s *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	if s.logMgr == nil {
		jsonOK(w, map[string]interface{}{"events": []interface{}{}, "total": 0, "categories": []string{}})
		return
	}
	category := r.URL.Query().Get("category")
	status := r.URL.Query().Get("status")
	node := r.URL.Query().Get("node")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	// date range: from/to in RFC3339 or "2006-01-02" format
	// 日期字符串按配置时区解析 (如 Asia/Shanghai → UTC+8)
	loc := s.GetTimezone()
	var from, to time.Time
	if fs := r.URL.Query().Get("from"); fs != "" {
		from, _ = time.Parse(time.RFC3339, fs)
		if from.IsZero() {
			from, _ = time.ParseInLocation("2006-01-02", fs, loc)
		}
	}
	if ts := r.URL.Query().Get("to"); ts != "" {
		to, _ = time.Parse(time.RFC3339, ts)
		if to.IsZero() {
			if t, err := time.ParseInLocation("2006-01-02", ts, loc); err == nil {
				to = t.Add(24*time.Hour - time.Second)
			}
		}
	}
	var events []logger.Event
	var total int
	if category != "" || status != "" || node != "" || !from.IsZero() || !to.IsZero() {
		events = s.logMgr.QueryByTime(category, status, node, from, to, limit, offset)
		// H2: 使用 CountByTime 获取真实匹配总数，而非 paginated 结果数量
		total = s.logMgr.CountByTime(category, status, node, from, to)
	} else {
		events = s.logMgr.Query(category, limit, offset)
		total = len(events) // 全量查询时 len(events) 即准确总数
	}
	// Convert event times from storage TZ to display TZ for Web UI
	tz := s.GetTimezone()
	for i := range events {
		events[i].Time = events[i].Time.In(tz)
	}
	categories := s.logMgr.Categories()
	jsonOK(w, map[string]interface{}{"events": events, "total": total, "limit": limit, "offset": offset, "categories": categories})
}

func (s *Server) handleLogsDownload(w http.ResponseWriter, r *http.Request) {
	// v1.5.20 H5: 日志下载审计追踪
	s.logMgr.Log("system", "日志已下载",
		fmt.Sprintf("ip=%s", clientIP(r)), "info")
	archivePath, err := s.logMgr.ArchiveLogs()
	if err != nil {
		// fallback: serve the main events.log directly
		logPath := filepath.Join(s.cfg.DataDir, "events.log")
		if _, err2 := os.Stat(logPath); os.IsNotExist(err2) {
			jsonErr(w, http.StatusNotFound, "日志文件不存在")
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename=ddns-manager-events.log")
		http.ServeFile(w, r, logPath)
		return
	}
	defer os.Remove(archivePath)
	f, err := os.Open(archivePath)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "打开归档失败")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=ddns-manager-logs.tar.gz")
	io.Copy(w, f)
}

func (s *Server) handleLogsCleanup(w http.ResponseWriter, r *http.Request) {
	// Always clean old rotated logs (older than retention days)
	// 使用配置时区计算日期边界
	delFiles, delMB := s.logMgr.EnsureDiskSpace()
	before := s.nowInTZ().AddDate(0, 0, -s.cfg.Logging.RetentionDays)
	oldFiles, oldMB := s.logMgr.CleanupBefore(before)
	s.logMgr.Log("system", "日志清理", "",
		fmt.Sprintf("deleted %d files (%.1f MB)", delFiles+oldFiles, delMB+oldMB))
	jsonOK(w, map[string]interface{}{
		"deleted_files": delFiles + oldFiles,
		"freed_mb":      delMB + oldMB,
	})
}

// ── admin: change password ──

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct{ NewPassword string `json:"new_password"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	if utf8.RuneCountInString(req.NewPassword) < 8 {
		jsonErr(w, http.StatusBadRequest, "密码至少需要8个字符")
		return
	}
	newToken := tokenFromPassword(req.NewPassword)
	hash, err := bcrypt.GenerateFromPassword([]byte(newToken), bcrypt.DefaultCost)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "服务器内部错误")
		return
	}
	s.store.SaveAdminState(&store.AdminState{TokenHash: string(hash), PasswordChanged: true})
	s.setAdminToken(newToken)
	s.logMgr.LogAuth("密码已修改", "admin", clientIP(r), "", "success")
	jsonOK(w, map[string]string{"status": "changed"})
}

// ── admin: agent version ──


// handleGetUpgradeState returns the server-side upgrade state for all nodes.
// Replaces localStorage-based per-browser tracking for cross-device consistency.
func (s *Server) handleGetUpgradeState(w http.ResponseWriter, r *http.Request) {
	cfg, _ := s.store.LoadAgentConfig()
	if cfg == nil || cfg.UpgradeState == nil {
		jsonOK(w, map[string]interface{}{})
		return
	}
	jsonOK(w, cfg.UpgradeState)
}

func (s *Server) handleGetAgentVersion(w http.ResponseWriter, r *http.Request) {
	cfg, _ := s.store.LoadAgentConfig()
	v := ""
	if cfg != nil {
		v = cfg.LatestVersion
	}
	jsonOK(w, map[string]string{"latest_version": v})
}
func (s *Server) handleSetAgentVersion(w http.ResponseWriter, r *http.Request) {
	var req struct{ LatestVersion string `json:"latest_version"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}

	// 原子更新 — 持写锁读-改-写，防止并发覆盖
	err := s.store.UpdateAgentConfigAtomic(func(cfg *store.AgentConfig) {
		prevVer := cfg.LatestVersion

		// 版本退避自动管理：
		// - 版本变更 → 全量清空退避（新版本一切重来）
		// - 同版本重设 → 仅清理已放弃节点（RetryCount>=5），已完成/进行中保留
		if req.LatestVersion != prevVer && prevVer != "" {
			cfg.UpgradeState = make(map[string]store.UpgJob)
		} else if req.LatestVersion == prevVer && cfg.UpgradeState != nil {
			var resetCount int
			for id, job := range cfg.UpgradeState {
				if job.Completed == "" && job.RetryCount >= 5 {
					delete(cfg.UpgradeState, id)
					resetCount++
				}
			}
			if resetCount > 0 {
				s.logMgr.Log("upgrade", "已重置",
					fmt.Sprintf("版本=%s 节点=%d(已放弃→重试)", req.LatestVersion, resetCount), "info")
			}
		}
		cfg.LatestVersion = req.LatestVersion
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "保存版本失败")
		return
	}
	// v1.5.20 H4: 强制版本设置完整审计日志
	s.logMgr.Log("upgrade", "强制版本已设置",
		fmt.Sprintf("ver=%s ip=%s", req.LatestVersion, clientIP(r)), "success")
	jsonOK(w, map[string]string{"status": "ok"})
}
func (s *Server) handleListAgentBinaries(w http.ResponseWriter, r *http.Request) {
	list, _ := s.store.ListAgentBinaries()
	jsonOK(w, list)
}
// v1.5.29: 上传后自动提取版本号 + 设置 Agent 版本 + Manager 自重启
var reVersionedBinary = regexp.MustCompile(`-v(\d+\.\d+\.\d+)-`)

func (s *Server) handleUploadAgentBinary(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		jsonErr(w, http.StatusBadRequest, "文件过大")
		return
	}
	var detectedVer string
	var hasManagerBinary bool
	for _, fh := range r.MultipartForm.File {
		for _, h := range fh {
			f, err := h.Open()
			if err != nil {
				s.logMgr.Log("agent", "上传二进制打开失败", h.Filename+": "+err.Error(), "warning")
				continue
			}
			data, err := io.ReadAll(f)
			f.Close()
			if err != nil {
				s.logMgr.Log("agent", "上传二进制读取失败", h.Filename+": "+err.Error(), "warning")
				continue
			}
			if len(data) == 0 {
				s.logMgr.Log("agent", "上传二进制为空", h.Filename, "warning")
				continue
			}
			s.store.SaveAgentBinary(h.Filename, data)
			s.logMgr.Log("agent", "已上传", fmt.Sprintf("%s (%d bytes)", h.Filename, len(data)), "success")

			// v1.5.29: 从文件名提取版本号
			if m := reVersionedBinary.FindStringSubmatch(h.Filename); m != nil && detectedVer == "" {
				detectedVer = m[1]
			}
			// 检测是否为 Manager 二进制
			if strings.HasPrefix(h.Filename, "ddns-manager-v") {
				hasManagerBinary = true
			}
		}
	}
	// Rebuild manifest after successful uploads
	s.store.RebuildManifest()

	// v1.5.29: 自动设置 Agent 版本，触发所有节点自升级
	if detectedVer != "" {
		s.store.UpdateAgentConfigAtomic(func(cfg *store.AgentConfig) {
			if cfg.LatestVersion != detectedVer {
				// 版本变更 → 全量清空退避状态
				cfg.UpgradeState = make(map[string]store.UpgJob)
			}
			cfg.LatestVersion = detectedVer
		})
		s.logMgr.Log("agent", "版本自动设置",
			fmt.Sprintf("ver=%s (从文件名自动提取)", detectedVer), "success")
	}

	// v1.5.29: Manager 二进制上传后自动部署
	if hasManagerBinary {
		go s.scheduleManagerRestart(detectedVer)
	}

	jsonOK(w, map[string]interface{}{
		"status":          "uploaded",
		"version_set":     detectedVer,
		"manager_restart": hasManagerBinary,
	})
}
func (s *Server) handleDeleteAgentBinary(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if err := s.store.DeleteAgentBinary(name); err != nil {
		jsonErr(w, http.StatusNotFound, "二进制文件未找到")
		return
	}
	// C4#1: 记录删除 Agent 二进制操作（安全关键操作）
	s.logMgr.Log("agent", "二进制已删除", name, "warning")
	// 删除后重建 manifest，防止已删除的二进制仍被推送
	s.store.RebuildManifest()
	jsonOK(w, map[string]string{"deleted": name})
}

// scheduleManagerRestart 在后台异步替换 Manager 自身二进制并重启服务。
// v1.5.29: 用户上传 ddns-manager-vX.Y.Z-linux-amd64 后自动触发。
// 原理: 写入 shell 脚本 → 后台执行 → 脚本等 HTTP 响应完成后 stop→cp→start。
func (s *Server) scheduleManagerRestart(newVer string) {
	binDir := s.store.AgentBinDir()
	// 查找刚上传的 manager 二进制
	entries, err := os.ReadDir(binDir)
	if err != nil {
		log.Printf("[deploy] readdir bin: %v", err)
		return
	}
	var newBin string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "ddns-manager-v") && strings.HasSuffix(e.Name(), "linux-amd64") {
			if newVer != "" && !strings.Contains(e.Name(), "-v"+newVer+"-") {
				continue
			}
			// 选最新的（按文件名排序，版本号最大的在最后）
			if e.Name() > newBin {
				newBin = e.Name()
			}
		}
	}
	if newBin == "" {
		log.Printf("[deploy] 未找到 manager 二进制文件")
		return
	}

	// 写入重启脚本，后台执行
	scriptPath := filepath.Join(os.TempDir(), "ddns-manager-restart.sh")
	script := fmt.Sprintf(`#!/bin/bash
# auto-generated by ddns-manager v1.5.29 — self-restart after binary upload
sleep 3  # wait for HTTP response to complete
systemctl stop ddns-manager
sleep 1
cp %s/%s /opt/ddns-manager/ddns-manager
chmod +x /opt/ddns-manager/ddns-manager
systemctl start ddns-manager
rm -f %s
`, binDir, newBin, scriptPath)

	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		log.Printf("[deploy] 写入重启脚本失败: %v", err)
		return
	}

	cmd := exec.Command("bash", scriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Printf("[deploy] 启动重启脚本失败: %v", err)
		return
	}
	log.Printf("[deploy] Manager 自重启已触发 (新版本: %s, 脚本: %s)", newBin, scriptPath)
	s.logMgr.Log("system", "Manager自重启",
		fmt.Sprintf("新版本=%s 脚本=%s", newBin, scriptPath), "success")
}

// ── admin: rate-limit ──

func (s *Server) handleGetRateLimit(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.LoadRateLimitConfig()
	if err != nil { jsonErr(w, 500, err.Error()); return }
	jsonOK(w, cfg)
}

func (s *Server) handleSaveRateLimit(w http.ResponseWriter, r *http.Request) {
	var cfg store.RateLimitConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil { jsonErr(w, 400, "请求体格式错误"); return }
	if err := s.store.SaveRateLimitConfig(&cfg); err != nil { jsonErr(w, 500, err.Error()); return }
	s.reloadRateLimit(&cfg)
	s.logMgr.Log("rate-limit", "配置已保存",
		fmt.Sprintf("全局=%d 心跳=%d 登录=%d 启用=%v", cfg.RequestsPerMin, cfg.HeartbeatPerMin, cfg.LoginPerMin, cfg.Enabled), "success")
	jsonOK(w, map[string]string{"status": "saved"})
}

// reloadRateLimit hot-reloads rate limiter config.

func (s *Server) handleGetSMTP(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.LoadSMTPConfig()
	if err != nil || cfg == nil {
		jsonOK(w, map[string]interface{}{"configured": false})
		return
	}
	masked := cfg.Masked()
	jsonOK(w, map[string]interface{}{
		"host": masked.Host, "port": masked.Port, "username": masked.Username,
		"password": masked.Password, "to": masked.To, "manager_url": masked.ManagerURL,
		"cert_expiry_days":        masked.CertExpiryDays,
		"notify_heartbeat_fail":   masked.NotifyHeartbeatFail,
		"notify_security":          masked.NotifySecurity,
		"notify_config_change":    masked.NotifyConfigChange,
		"notify_system_error":     masked.NotifySystemError,
		"notify_cert_expiry":      masked.NotifyCertExpiry,
		"configured":              true,
	})
}
func (s *Server) handleSaveSMTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host               string `json:"host"`
		Port               int    `json:"port"`
		Username           string `json:"username"`
		Password           string `json:"password"`
		To                 string `json:"to"`
		ManagerURL         string `json:"manager_url"`
		CertExpiryDays     int    `json:"cert_expiry_days"`
		NotifyHeartbeatFail bool  `json:"notify_heartbeat_fail"`
		NotifySecurity     bool   `json:"notify_security"`
		NotifyConfigChange bool   `json:"notify_config_change"`
		NotifySystemError  bool   `json:"notify_system_error"`
		NotifyCertExpiry   bool   `json:"notify_cert_expiry"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	// 密码保护: 前端二次保存时可能不传密码（或传掩码 ****）
	// 此时保留已存储的密码，避免授权码被静默清空
	password := req.Password
	if password == "" || isMaskedPassword(password) {
		if saved, _ := s.store.LoadSMTPConfig(); saved != nil && saved.Password != "" {
			password = saved.Password
		}
	}
	cfg := &notify.Config{
		Host: req.Host, Port: req.Port, Username: req.Username, Password: password, To: req.To,
		ManagerURL: req.ManagerURL, CertExpiryDays: req.CertExpiryDays, NotifyHeartbeatFail: req.NotifyHeartbeatFail,
		NotifySecurity: req.NotifySecurity, NotifyConfigChange: req.NotifyConfigChange,
		NotifySystemError: req.NotifySystemError, NotifyCertExpiry: req.NotifyCertExpiry,
	}
	// 注入时区 — 邮件中的时间戳据此显示
	if tzCfg, _ := s.store.LoadTimezoneConfig(); tzCfg != nil {
		cfg.Timezone = tzCfg.Timezone
	}
	if err := s.store.SaveSMTPConfig(cfg); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logMgr.Log("smtp", "配置已保存", req.Username+" → "+req.Host+":"+fmt.Sprint(req.Port), "success")
	jsonOK(w, map[string]string{"status": "saved"})
}

func (s *Server) handleSMTPTest(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.LoadSMTPConfig()
	if err != nil || cfg == nil {
		jsonErr(w, http.StatusBadRequest, "SMTP 未配置")
		return
	}
	if cfg.Host == "" || cfg.Username == "" {
		jsonErr(w, http.StatusBadRequest, "SMTP 服务器和发件人为必填项")
		return
	}
	if err := cfg.SendTest(); err != nil {
		errMsg := err.Error()
		// 常见错误加中文提示
		if strings.Contains(errMsg, "authentication failed") || strings.Contains(errMsg, "535") {
			errMsg += " (授权码不正确？163/QQ邮箱需使用专属授权码，非登录密码)"
		} else if strings.Contains(errMsg, "connection refused") || strings.Contains(errMsg, "timeout") {
			errMsg += " (服务器或端口无法连接，请检查SMTP服务器地址和端口)"
		}
		jsonErr(w, http.StatusInternalServerError, "发送失败: "+errMsg)
		return
	}
	s.logMgr.Log("smtp", "测试发送", cfg.Username+"->"+cfg.To, "success")
	jsonOK(w, map[string]string{"status": "sent"})
}

func (s *Server) handleBinFile(w http.ResponseWriter, r *http.Request) {
	filename := mux.Vars(r)["filename"]
	// M5: 强化路径穿越防护 — 拒绝绝对路径、..、反斜杠、空文件名
	if filename == "" || strings.Contains(filename, "..") ||
		strings.Contains(filename, "\\") || strings.HasPrefix(filename, "/") ||
		strings.ContainsAny(filename, "\x00") {
		http.NotFound(w, r)
		return
	}
	// 解析后用 Clean 二次防穿越（. 和多余 / 被规范化）
	binDir := filepath.Join(s.cfg.DataDir, "bin")
	resolved := filepath.Clean(filepath.Join(binDir, filename))
	if !strings.HasPrefix(resolved, binDir) {
		http.NotFound(w, r)
		return
	}
	// ZIP 文件强制下载，触发浏览器另存为对话框
	if strings.HasSuffix(strings.ToLower(filename), ".zip") {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		w.Header().Set("Content-Type", "application/zip")
	}
	http.ServeFile(w, r, resolved)
}

// handleDownloadInstaller 运行时动态打包 Windows 安装 ZIP。
// GET /api/admin/download-installer?ver=v1.5.7&os=windows-amd64
func (s *Server) handleDownloadInstaller(w http.ResponseWriter, r *http.Request) {
	ver := strings.TrimSpace(r.URL.Query().Get("ver"))
	osName := strings.TrimSpace(r.URL.Query().Get("os"))
	// v1.5.20 M4: 安装包下载审计日志
	s.logMgr.Log("agent", "安装包已下载",
		fmt.Sprintf("ver=%s os=%s ip=%s", ver, osName, clientIP(r)), "info")
	if ver == "" || osName == "" {
		jsonErr(w, http.StatusBadRequest, "ver 和 os 参数必填")
		return
	}
	// 安全校验: ver 仅允许 SEMVER 格式字符 (0-9.v-) + 最大 32 字符
	if len(ver) > 32 || strings.ContainsAny(ver, "\x00\\/&;`'\"|<>*?%!$#@~ ") {
		jsonErr(w, http.StatusBadRequest, "版本号格式非法")
		return
	}
	// 安全校验：仅允许 windows-amd64
	if osName != "windows-amd64" {
		jsonErr(w, http.StatusBadRequest, "当前仅支持 windows-amd64")
		return
	}
	binDir := filepath.Join(s.cfg.DataDir, "bin")

	// 查找 installer (通用，优先用无版本号的 latest，兜底用最新版本化)
	instName := "ddns-installer-" + osName + ".exe"
	instPath := filepath.Join(binDir, instName)
	if _, err := os.Stat(instPath); err != nil {
		// 兜底：找最新版本化的 installer
		entries, _ := os.ReadDir(binDir)
		for i := len(entries) - 1; i >= 0; i-- {
			n := entries[i].Name()
			if strings.HasPrefix(n, "ddns-installer-v") && strings.HasSuffix(n, "-"+osName+".exe") {
				instName = n
				instPath = filepath.Join(binDir, n)
				break
			}
		}
		if _, err2 := os.Stat(instPath); err2 != nil {
			jsonErr(w, http.StatusNotFound, "安装器二进制未找到，请上传 ddns-installer-"+osName+".exe")
			return
		}
	}

	// 查找 agent (版本化)
	agentName := "node-agent-v" + ver + "-" + osName + ".exe"
	agentPath := filepath.Join(binDir, agentName)
	if _, err := os.Stat(agentPath); err != nil {
		jsonErr(w, http.StatusNotFound, "客户端二进制未找到: "+agentName+"，请先上传")
		return
	}

	// 生成 install.bat 和 README.txt (占位符替换 + LF→CRLF)
	batContent := strings.ReplaceAll(installBatTemplate, "__VERSION__", ver)
	batContent = strings.ReplaceAll(batContent, "\n", "\r\n")
	readmeContent := strings.ReplaceAll(readmeTemplate, "__VERSION__", ver)
	readmeContent = strings.ReplaceAll(readmeContent, "\n", "\r\n")

	// M3: 移除预估算 Content-Length，实际压缩后大小与未压缩差异大导致传输截断
	zipName := "ddns-manager-install-v" + ver + "-" + osName + ".zip"
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", zipName))
	w.Header().Set("Content-Type", "application/zip")

	zw := zip.NewWriter(w)

	// 写入 agent 二进制 (流式，不缓冲)
	if fw, err := zw.Create(filepath.Base(agentPath)); err == nil {
		if f, err := os.Open(agentPath); err == nil {
			io.Copy(fw, f)
			f.Close()
		}
	}

	// 写入 installer 二进制 (流式，不缓冲)
	if fw, err := zw.Create("ddns-installer.exe"); err == nil {
		if f, err := os.Open(instPath); err == nil {
			io.Copy(fw, f)
			f.Close()
		}
	}

	// 写入小文件 (install.bat + README.txt 很小，内存缓冲无影响)
	for _, f := range []struct {
		name    string
		content []byte
	}{
		{"install.bat", []byte(batContent)},
		{"README.txt", []byte(readmeContent)},
	} {
		if fw, err := zw.Create(f.name); err == nil {
			fw.Write(f.content)
		}
	}
	// v1.5.22 H6: 检查 ZIP Close 错误，防止客户端收到损坏的 ZIP
	if closeErr := zw.Close(); closeErr != nil {
		s.logMgr.Log("installer", "ZIP打包失败", fmt.Sprintf("ver=%s err=%v", ver, closeErr), "error")
		return
	}
}

// install.bat 模板 — 与 build/install.bat.in 内容一致。
// __VERSION__ 运行时替换为实际版本号。
const installBatTemplate = `@echo off
chcp 65001 >nul
title ddns-manager v__VERSION__ 安装向导

echo ============================================
echo   ddns-manager Windows 节点安装
echo   Version: v__VERSION__  ^|  Lanxun CO.,Ltd.
echo ============================================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 请右键以管理员身份运行 install.bat
    echo.
    pause
    exit /b 1
)

set "INSTALLER=%~dp0ddns-installer.exe"
if not exist "%INSTALLER%" (
    echo [错误] 未找到 ddns-installer.exe
    echo        请确保所有文件在同一目录
    echo.
    pause
    exit /b 1
)

echo 启动安装向导...
echo.
"%INSTALLER%" %*

if %errorlevel% neq 0 (
    echo.
    echo [错误] 安装未完成 (错误码: %errorlevel%)
    pause
    exit /b %errorlevel%
)

echo.
echo 安装完成！
pause
`

// README.txt 模板 — __VERSION__ 运行时替换
const readmeTemplate = `============================================
  ddns-manager Windows 节点安装包
  Version: v__VERSION__
  Lanxun CO.,Ltd.
============================================

[功能介绍]
本安装包用于在 Windows 系统上安装 ddns-manager 节点客户端。
安装后将自动注册为 Windows 服务，每 5 分钟向管理端上报心跳。

[文件说明]
  install.bat            - 安装启动器（右键以管理员身份运行）
  ddns-installer.exe     - Go 安装向导（交互式）
  node-agent*.exe        - 节点守护进程

[安装步骤]
  1. 将 zip 内所有文件解压到同一目录
  2. 右键 install.bat 以管理员身份运行
  3. 按向导提示完成安装
  4. 登录管理端 WebUI 审批并配置节点

[注意事项]
  . 如已安装 ddns-go，向导会提示冲突并要求清除
  . 安装目录会自动创建，旧版会自动清理（配置保留）

[卸载]
  以管理员身份运行:
    C:\ddns-manager\ddns-installer.exe -uninstall
`


// ── Timezone ──

func (s *Server) handleGetTimezone(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.LoadTimezoneConfig()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonOK(w, map[string]string{"timezone": cfg.Timezone})
}

func (s *Server) handleSaveTimezone(w http.ResponseWriter, r *http.Request) {
	var req struct{ Timezone string `json:"timezone"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "格式错误")
		return
	}
	if req.Timezone == "" {
		jsonErr(w, 400, "时区不能为空")
		return
	}
	loc, err := time.LoadLocation(req.Timezone)
	if err != nil {
		jsonErr(w, 400, "无效时区: "+req.Timezone)
		return
	}
	cfg := &store.TimezoneConfig{Timezone: req.Timezone}
	if err := s.store.SaveTimezoneConfig(cfg); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s.SetTimezone(loc)
	// 同步更新 SMTP 配置中的时区，确保邮件时间戳与设置一致
	if smtpCfg, _ := s.store.LoadSMTPConfig(); smtpCfg != nil && smtpCfg.IsConfigured() {
		smtpCfg.Timezone = req.Timezone
		_ = s.store.SaveSMTPConfig(smtpCfg)
	}
	s.logMgr.Log("system", "时区已更改", req.Timezone, "success")
	jsonOK(w, map[string]string{"status": "saved", "timezone": req.Timezone})
}

// isMaskedPassword checks if a string looks like a masked password.
// Detects both fully masked (****) and partially masked (PP************pY).
// Frontend may send masked display value when user didn't modify the password field.
func isMaskedPassword(s string) bool {
	if len(s) < 4 {
		return false
	}
	// 检测连续4个以上*（全掩码或部分掩码如 PP****pY）
	starRun := 0
	for _, c := range s {
		if c == '*' {
			starRun++
			if starRun >= 4 {
				return true
			}
		} else {
			starRun = 0
		}
	}
	return false
}

// ── SMTP notification trigger helpers ──

// tryNotify sends an email notification if SMTP is configured and the event type is enabled.
// Runs in a background goroutine to avoid blocking the request handler.
func (s *Server) tryNotify(eventType, title, detail string) {
	go func() {
		cfg, err := s.store.LoadSMTPConfig()
		if err != nil || cfg == nil {
			log.Printf("[smtp] 通知跳过 (%s): SMTP未配置", eventType)
			return
		}
		if err := cfg.SendEventAlert(eventType, title, detail); err != nil {
			log.Printf("[smtp] 通知发送失败 (%s): %v", eventType, err)
		} else {
			log.Printf("[smtp] 通知已发送 (%s): %s", eventType, title)
		}
	}()
}

// tryNotifyCertExpiry sends certificate expiry alerts.
func (s *Server) tryNotifyCertExpiry(alerts []notify.CertAlert) {
	if len(alerts) == 0 {
		return
	}
	go func() {
		cfg, err := s.store.LoadSMTPConfig()
		if err != nil || cfg == nil {
			return
		}
		if err := cfg.SendCertAlert(alerts); err != nil {
			log.Printf("[smtp] 证书过期通知失败: %v", err)
		}
	}()
}
