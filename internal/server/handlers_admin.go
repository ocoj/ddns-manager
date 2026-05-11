package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
	jsonOK(w, map[string]string{"status": "ok"})
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
		CreatedAt:    time.Now().UTC(),
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
	keys, _ := s.store.LoadDNSKeys()
	if keys == nil {
		keys = make(map[string]*model.DNSKeyRecord)
	}
	now := time.Now().UTC().Format(time.RFC3339)
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
	keys, _ := s.store.LoadDNSKeys()
	if _, ok := keys[p]; !ok {
		jsonErr(w, http.StatusNotFound, "密钥未找到")
		return
	}
	delete(keys, p)
	s.store.SaveDNSKeys(keys)
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
	var from, to time.Time
	if fs := r.URL.Query().Get("from"); fs != "" {
		from, _ = time.Parse(time.RFC3339, fs)
		if from.IsZero() {
			from, _ = time.Parse("2006-01-02", fs)
		}
	}
	if ts := r.URL.Query().Get("to"); ts != "" {
		to, _ = time.Parse(time.RFC3339, ts)
		if to.IsZero() {
			// "2006-01-02" → end of that day
			if t, err := time.Parse("2006-01-02", ts); err == nil {
				to = t.Add(24*time.Hour - time.Second)
			}
		}
	}
	var events []logger.Event
	if category != "" || status != "" || node != "" || !from.IsZero() || !to.IsZero() {
		events = s.logMgr.QueryByTime(category, status, node, from, to, limit, offset)
	} else {
		events = s.logMgr.Query(category, limit, offset)
	}
	categories := s.logMgr.Categories()
	total := len(events)
	jsonOK(w, map[string]interface{}{"events": events, "total": total, "limit": limit, "offset": offset, "categories": categories})
}

func (s *Server) handleLogsDownload(w http.ResponseWriter, r *http.Request) {
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
	// and free disk space if critically low
	delFiles, delMB := s.logMgr.EnsureDiskSpace()
	before := time.Now().AddDate(0, 0, -s.cfg.Logging.RetentionDays)
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
	cfg, _ := s.store.LoadAgentConfig()
	if cfg == nil {
		cfg = &store.AgentConfig{}
	}

	// 版本退避自动管理：
	// - 版本变更 → 全量清空退避（新版本一切重来）
	// - 同版本重设 → 仅清理已放弃节点（RetryCount>=5），已完成/进行中保留
	if req.LatestVersion != cfg.LatestVersion && cfg.LatestVersion != "" {
		cfg.UpgradeState = make(map[string]store.UpgJob)
	} else if req.LatestVersion == cfg.LatestVersion && cfg.UpgradeState != nil {
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
	s.store.SaveAgentConfig(cfg)
	jsonOK(w, map[string]string{"status": "ok"})
}
func (s *Server) handleListAgentBinaries(w http.ResponseWriter, r *http.Request) {
	list, _ := s.store.ListAgentBinaries()
	jsonOK(w, list)
}
func (s *Server) handleUploadAgentBinary(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		jsonErr(w, http.StatusBadRequest, "文件过大")
		return
	}
	for _, fh := range r.MultipartForm.File {
		for _, h := range fh {
			f, _ := h.Open()
			data, _ := io.ReadAll(f)
			f.Close()
			s.store.SaveAgentBinary(h.Filename, data)
		}
	}
	jsonOK(w, map[string]string{"status": "uploaded"})
}
func (s *Server) handleDeleteAgentBinary(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteAgentBinary(mux.Vars(r)["name"]); err != nil {
		jsonErr(w, http.StatusNotFound, "二进制文件未找到")
		return
	}
	jsonOK(w, map[string]string{"deleted": mux.Vars(r)["name"]})
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
	cfg := &notify.Config{
		Host: req.Host, Port: req.Port, Username: req.Username, Password: req.Password, To: req.To,
		ManagerURL: req.ManagerURL, CertExpiryDays: req.CertExpiryDays, NotifyHeartbeatFail: req.NotifyHeartbeatFail,
		NotifySecurity: req.NotifySecurity, NotifyConfigChange: req.NotifyConfigChange,
		NotifySystemError: req.NotifySystemError, NotifyCertExpiry: req.NotifyCertExpiry,
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
	if strings.Contains(filename, "..") || filename == "" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.cfg.DataDir, "bin", filename))
}

