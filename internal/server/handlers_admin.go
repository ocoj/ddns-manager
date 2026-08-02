package server

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
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

	"unicode/utf8"

	"github.com/gorilla/mux"
	"github.com/ocoj/ddns-manager/internal/logger"
	"github.com/ocoj/ddns-manager/internal/model"
	"github.com/ocoj/ddns-manager/internal/notify"
	"github.com/ocoj/ddns-manager/internal/provider"
	"github.com/ocoj/ddns-manager/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// v1.6.58: 节点名字符白名单 — 仅允许字母、数字、连字符和下划线
var validNodeIDRegexp = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	// v1.6.36 M6: 未设置 Agent 版本时返回 "-" 占位, 避免前端显示空字符串
	agentVer := "-"
	if cfg, _ := s.store.LoadAgentConfig(); cfg != nil && cfg.LatestVersion != "" {
		agentVer = cfg.LatestVersion
	}
	jsonOK(w, map[string]interface{}{"status": "ok", "version": s.version, "agent_version": agentVer, "timezone": s.GetTimezone().String()})
}

func (s *Server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	st, _ := s.store.LoadAdminState()
	jsonOK(w, map[string]interface{}{"password_changed": st != nil && st.PasswordChanged})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	st, err := s.store.LoadAdminState()
	if err != nil || st == nil {
		jsonErr(w, http.StatusInternalServerError, "管理员状态不可用")
		return
	}
	// v1.6.46 H4: 使用实例 salt 派生 token (无 salt 时回退旧算法)
	var token string
	if st.InstanceSalt != "" {
		token = tokenFromPasswordWithSalt(req.Password, st.InstanceSalt)
	} else {
		token = tokenFromPassword(req.Password)
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.getAdminToken())) != 1 {
		if err := bcrypt.CompareHashAndPassword([]byte(st.TokenHash), []byte(token)); err != nil {
			s.logMgr.LogAuth("登录失败", "admin", clientIP(r), "密码错误", "error")
			s.tryNotify("security", "管理员登录失败", fmt.Sprintf("ip=%s", clientIP(r)), "")
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
	// v1.6.58: 限制节点名字符白名单，防止日志注入和 WebUI 显示异常
	if !validNodeIDRegexp.MatchString(req.NodeID) {
		jsonErr(w, http.StatusBadRequest, "节点名仅允许字母、数字、连字符和下划线 (1-64字符)")
		return
	}
	nodes, _ := s.store.LoadNodes()
	if existing, exists := nodes[req.NodeID]; exists {
		// v1.6.33 P10: 同节点+同指纹=旧机重装, 允许更新密码
		if existing.Fingerprint == req.Fingerprint {
			hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			if err != nil {
				s.logMgr.LogWithNode("节点", "重装-密码更新失败", req.NodeID, "bcrypt 处理失败", "error")
				jsonErr(w, http.StatusInternalServerError, "服务器内部错误")
				return
			}
			existing.PasswordHash = string(hash)
			s.store.PutNode(req.NodeID, existing)
			s.logMgr.LogWithNode("节点", "旧机重装(密码已更新)", req.NodeID, "指纹匹配, 已更新密码", "info")
			jsonOK(w, map[string]string{"node_id": req.NodeID, "status": "reinstalled"})
			return
		}
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
	if req.Name == "" {
		req.Name = req.Provider
	} // backward compat
	if req.Name == "" || req.Provider == "" {
		jsonErr(w, http.StatusBadRequest, "名称和提供商为必填项")
		return
	}
	// 校验 DNS provider 名称 — 防止拼写错误导致后续配置渲染失败
	if !provider.IsKnown(req.Provider) {
		jsonErr(w, http.StatusBadRequest, fmt.Sprintf("未知的DNS提供商: %q (支持的提供商: %s)", req.Provider, strings.Join(provider.Names(), ", ")))
		return
	}
	keys, _ := s.store.LoadDNSKeys()
	if keys == nil {
		keys = make(map[string]*model.DNSKeyRecord)
	}
	now := s.nowInTZ().Format(time.RFC3339)
	keyName := req.Name
	if existing, ok := keys[keyName]; ok {
		if req.Provider != "" {
			existing.Provider = req.Provider
		}
		if req.AccessKeyID != "" {
			existing.AccessKeyID = req.AccessKeyID
		}
		if req.AccessKeySecret != "" {
			existing.AccessKeySecret = req.AccessKeySecret
		}
		existing.UpdatedAt = now
	} else {
		keys[keyName] = &model.DNSKeyRecord{
			Name: req.Name, Provider: req.Provider,
			AccessKeyID: req.AccessKeyID, AccessKeySecret: req.AccessKeySecret, UpdatedAt: now,
		}
	}
	s.store.SaveDNSKeys(keys)
	// v1.6.61: 配置变化感知 — 清空引用该 key 节点的 ConfigHash, 下个心跳重新渲染推送
	if err := s.store.InvalidateConfigHashesForDNSKey(keyName); err != nil {
		s.logMgr.Log("dns-key", "清空引用节点配置hash失败", keyName, "warning")
	}
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
	// v1.6.61: 配置变化感知 — 删除后清空引用节点 hash, 触发重新渲染(引用节点将渲染失败提示改配)
	if err := s.store.InvalidateConfigHashesForDNSKey(p); err != nil {
		s.logMgr.Log("dns-key", "清空引用节点配置hash失败", p, "warning")
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
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
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
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	if utf8.RuneCountInString(req.NewPassword) < 8 {
		jsonErr(w, http.StatusBadRequest, "密码至少需要8个字符")
		return
	}
	st, _ := s.store.LoadAdminState()
	// v1.6.46 H4: 使用实例 salt 派生 token (无 salt 时回退旧算法)
	var salt string
	if st != nil {
		salt = st.InstanceSalt
	}
	var newToken string
	if salt != "" {
		newToken = tokenFromPasswordWithSalt(req.NewPassword, salt)
	} else {
		newToken = tokenFromPassword(req.NewPassword)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newToken), bcrypt.DefaultCost)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "服务器内部错误")
		return
	}
	s.store.SaveAdminState(&store.AdminState{TokenHash: string(hash), PasswordChanged: true, InstanceSalt: salt})
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
	var req struct {
		LatestVersion string `json:"latest_version"`
	}
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
	// v1.6.46 H6: 文件系统返回 UTC 时间, 转换为配置时区展示
	tz := s.GetTimezone()
	for _, item := range list {
		if mt, ok := item["mod_time"].(string); ok {
			if t, err := time.Parse("2006-01-02 15:04", mt); err == nil {
				item["mod_time"] = t.In(tz).Format("2006-01-02 15:04")
			}
		}
	}
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

			// v1.6.42 M6: 取所有上传文件中版本号最高者 (CompareSemVer), 避免只取首个文件版本
			if m := reVersionedBinary.FindStringSubmatch(h.Filename); m != nil {
				if detectedVer == "" || model.CompareSemVer(m[1], detectedVer) > 0 {
					detectedVer = m[1]
				}
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
// v1.6.42 H7: 增加日志记录, 使自重启操作可追踪
func (s *Server) scheduleManagerRestart(newVer string) {
	s.logMgr.Log("system", "Manager自重启", fmt.Sprintf("触发版本=%s", newVer), "info")

	// v1.6.59: 容器环境跳过 systemctl 自重启，改为提示重建镜像
	if _, err := os.Stat("/.dockerenv"); err == nil {
		log.Printf("[deploy] 容器环境检测到 /.dockerenv, 跳过自重启")
		s.logMgr.Log("system", "Manager自重启已跳过",
			"容器环境需重建镜像以更新二进制, 请执行: docker compose up -d --build", "info")
		return
	}

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

	newBinPath := filepath.Join(binDir, newBin)
	srcFile, err := os.Open(newBinPath)
	if err != nil {
		log.Printf("[deploy] 打开新二进制失败: %v", err)
		return
	}
	defer srcFile.Close()

	// v1.6.28 H7: 用 Go native 替代 shell 脚本 — 消除竞态和命令注入
	// 1. 解析当前可执行文件的真实路径 (符号链接 → 目标)
	curExe, exeErr := os.Executable()
	if exeErr != nil {
		log.Printf("[deploy] 获取当前二进制路径失败: %v", exeErr)
		return
	}
	realPath := curExe
	if resolved, err := filepath.EvalSymlinks(curExe); err == nil {
		realPath = resolved
	}

	// 2. 写入临时文件, 然后原子 mv (避免 cp 到运行中文件)
	tmpPath := realPath + ".new"
	dstFile, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		log.Printf("[deploy] 创建临时文件失败: %v", err)
		return
	}
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		dstFile.Close()
		os.Remove(tmpPath)
		log.Printf("[deploy] 复制二进制失败: %v", err)
		return
	}
	dstFile.Close()

	// 3. 后台 goroutine: 等待 HTTP 响应完成 → 停止服务 → 原子替换 → 启动
	go func() {
		time.Sleep(3 * time.Second) // 等待 HTTP 响应发送完毕

		// v1.6.46 H1: 检查 systemctl stop 错误 — 服务未正常运行时放弃自重启
		log.Printf("[deploy] 停止 ddns-manager 服务...")
		if out, err := exec.Command("systemctl", "stop", "ddns-manager").CombinedOutput(); err != nil {
			log.Printf("[deploy] systemctl stop 失败: %v (output=%s), 放弃自重启", err, string(out))
			os.Remove(tmpPath)
			return
		}
		time.Sleep(1 * time.Second)

		// 原子替换: mv 是同一文件系统内的原子操作
		if err := os.Rename(tmpPath, realPath); err != nil {
			log.Printf("[deploy] 原子替换失败: %v", err)
			// 尝试回退: 启动旧版本
			if startErr := exec.Command("systemctl", "start", "ddns-manager").Run(); startErr != nil {
				log.Printf("[deploy] 回退启动也失败: %v, 需人工介入!", startErr)
			}
			os.Remove(tmpPath)
			return
		}
		if err := os.Chmod(realPath, 0755); err != nil {
			log.Printf("[deploy] chmod 失败: %v", err)
		}

		log.Printf("[deploy] 启动 ddns-manager 服务 (新版本: %s)...", newVer)
		if out, err := exec.Command("systemctl", "start", "ddns-manager").CombinedOutput(); err != nil {
			log.Printf("[deploy] systemctl start 失败: %v (output=%s), 需人工介入!", err, string(out))
		}
	}()

	log.Printf("[deploy] Manager 自重启已触发 (新版本: %s, 路径: %s)", newBin, realPath)
	s.logMgr.Log("system", "Manager自重启",
		fmt.Sprintf("新版本=%s 路径=%s", newBin, realPath), "success")
}

// ── admin: rate-limit ──

func (s *Server) handleGetRateLimit(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.LoadRateLimitConfig()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonOK(w, cfg)
}

func (s *Server) handleSaveRateLimit(w http.ResponseWriter, r *http.Request) {
	var cfg store.RateLimitConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		jsonErr(w, 400, "请求体格式错误")
		return
	}
	if err := s.store.SaveRateLimitConfig(&cfg); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
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
		"cert_expiry_days":      masked.CertExpiryDays,
		"notify_heartbeat_fail": masked.NotifyHeartbeatFail,
		"notify_security":       masked.NotifySecurity,
		"notify_config_change":  masked.NotifyConfigChange,
		"notify_system_error":   masked.NotifySystemError,
		"notify_cert_expiry":    masked.NotifyCertExpiry,
		"configured":            true,
	})
}
func (s *Server) handleSaveSMTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host                string `json:"host"`
		Port                int    `json:"port"`
		Username            string `json:"username"`
		Password            string `json:"password"`
		To                  string `json:"to"`
		ManagerURL          string `json:"manager_url"`
		CertExpiryDays      int    `json:"cert_expiry_days"`
		NotifyHeartbeatFail bool   `json:"notify_heartbeat_fail"`
		NotifySecurity      bool   `json:"notify_security"`
		NotifyConfigChange  bool   `json:"notify_config_change"`
		NotifySystemError   bool   `json:"notify_system_error"`
		NotifyCertExpiry    bool   `json:"notify_cert_expiry"`
		// v1.6.53: cooldown configurable
		HeartbeatFailCooldown int `json:"heartbeat_fail_cooldown"`
		AuthFailCooldown      int `json:"auth_fail_cooldown"`
		UnknownNodeCooldown   int `json:"unknown_node_cooldown"`
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
		HeartbeatFailCooldown: req.HeartbeatFailCooldown,
		AuthFailCooldown:      req.AuthFailCooldown,
		UnknownNodeCooldown:   req.UnknownNodeCooldown,
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

	// v1.6.33 P13: install.sh 动态替换 __MANAGER_URL__ 为请求 Host
	// 下载 install.sh 时自动填入当前管理端地址, 无需用户手动输入
	if filename == "install.sh" {
		content, err := os.ReadFile(resolved)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		// v1.6.56: 仅受信代理传来的 X-Forwarded-* 头才信任，否则只用 Host
		scheme := "https"
		host := r.Host
		trustProxy := false
		if tp := s.GetTrustedProxy(); tp != "" {
			if rhost := remoteHost(r); rhost != "" && isTrustedProxyHost(rhost, tp) {
				trustProxy = true
			}
		}
		if trustProxy {
			if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
				scheme = proto
			}
			if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
				host = fwdHost
			}
		} else if r.TLS == nil && !strings.Contains(r.Host, ":30443") {
			scheme = "http"
		}
		managerURL := scheme + "://" + host
		if !strings.Contains(host, ":") && trustProxy {
			if port := r.Header.Get("X-Forwarded-Port"); port != "" && port != "80" && port != "443" {
				managerURL += ":" + port
			}
		}
		content = bytes.ReplaceAll(content, []byte("__MANAGER_URL__"), []byte(managerURL))
		content = bytes.ReplaceAll(content, []byte("__INSTALLER_VERSION__"), []byte("v"+s.installerVersion))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(content)
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
	// v1.6.31: 统一去除 v 前缀, 防止 ver=v1.6.30 → node-agent-vv1.6.30.exe
	ver = strings.TrimPrefix(ver, "v")
	// 安全校验: ver 仅允许 SEMVER 格式字符 (0-9.) + 最大 32 字符
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
			if _, copyErr := io.Copy(fw, f); copyErr != nil {
				log.Printf("[deploy] ZIP写入agent失败: %v", copyErr)
			}
			f.Close()
		}
	}

	// 写入 installer 二进制 (流式，不缓冲)
	if fw, err := zw.Create("ddns-installer.exe"); err == nil {
		if f, err := os.Open(instPath); err == nil {
			if _, copyErr := io.Copy(fw, f); copyErr != nil {
				log.Printf("[deploy] ZIP写入installer失败: %v", copyErr)
			}
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
// v1.6.33 P11: pushd + setlocal 防括号路径(如 "(1)")导致的 cmd 解析错误
const installBatTemplate = `@echo off
REM ddns-manager Windows 安装启动器
REM 用途: 提升管理员权限 → 启动 Go 安装向导

setlocal enabledelayedexpansion
chcp 65001 >nul
title ddns-manager v__VERSION__ 安装向导

REM ── 切换到脚本所在目录 (防止括号路径解析错误) ──
pushd "%~dp0"

echo ============================================
echo   ddns-manager Windows 节点安装
echo   Version: v__VERSION__  ^|  Lanxun CO.,Ltd.
echo ============================================
echo.

REM ── 检查管理员权限 ──
net session >nul 2>&1
if !errorlevel! neq 0 (
    echo [错误] 请右键以管理员身份运行 install.bat
    echo.
    pause
    popd
    exit /b 1
)

REM ── 定位安装器 (当前目录) ──
if not exist "ddns-installer.exe" (
    echo [错误] 未找到 ddns-installer.exe
    echo        请确保所有文件在同一目录
    echo        当前目录: %CD%
    echo.
    pause
    popd
    exit /b 1
)

REM ── 启动安装向导 ──
echo 启动安装向导...
echo.
"ddns-installer.exe" %*

if !errorlevel! neq 0 (
    echo.
    echo [错误] 安装未完成 (错误码: !errorlevel!)
    pause
    popd
    exit /b !errorlevel!
)

echo.
echo 安装完成！
pause
popd
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
    C:\ddns-agent\ddns-installer.exe -uninstall
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
	var req struct {
		Timezone string `json:"timezone"`
	}
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

// ── Trusted Proxy (v1.6.58) ──

func (s *Server) handleGetTrustedProxy(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"trusted_proxy": s.GetTrustedProxy()})
}

func (s *Server) handleSaveTrustedProxy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TrustedProxy string `json:"trusted_proxy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "格式错误")
		return
	}
	// 允许空值以禁用
	cfg := &store.ProxyConfig{TrustedProxy: req.TrustedProxy}
	if err := s.store.SaveProxyConfig(cfg); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s.SetTrustedProxy(req.TrustedProxy)
	if req.TrustedProxy != "" {
		s.logMgr.Log("system", "受信代理已设置", req.TrustedProxy, "success")
	} else {
		s.logMgr.Log("system", "受信代理已禁用", "将使用 RemoteAddr", "info")
	}
	jsonOK(w, map[string]string{"status": "saved"})
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
// cooldownNode is optional:
//
//	"unknown_node:actualID" → uses UnknownNodeCooldown (default 30)
//	"auth_failure:actualID"  → uses AuthFailCooldown (default 30)
//	"" or bare string        → no cooldown
func (s *Server) tryNotify(eventType, title, detail, cooldownNode string) {
	// v1.6.53: configurable cooldowns from SMTP config
	if eventType == "security" && cooldownNode != "" {
		cooldownMinutes := 0
		cfg, _ := s.store.LoadSMTPConfig()
		if strings.HasPrefix(cooldownNode, "unknown_node:") {
			cooldownMinutes = cfg.UnknownNodeCooldown
			if cooldownMinutes <= 0 {
				cooldownMinutes = 30
			}
		} else if strings.HasPrefix(cooldownNode, "auth_failure:") {
			cooldownMinutes = cfg.AuthFailCooldown
			if cooldownMinutes <= 0 {
				cooldownMinutes = 30
			}
		}
		if cooldownMinutes > 0 {
			s.notifyCooldownMu.Lock()
			last, ok := s.notifyCooldown[cooldownNode]
			if ok && time.Since(last) < time.Duration(cooldownMinutes)*time.Minute {
				s.notifyCooldownMu.Unlock()
				return
			}
			s.notifyCooldown[cooldownNode] = time.Now()
			s.notifyCooldownMu.Unlock()
		}
	}
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

// truncate 截断字符串到 n 字符, 超出部分替换为 ...
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ── Backup & Restore ──

// backupFiles lists files/dirs to include in the backup archive (relative to data dir).
var backupFiles = []string{
	"nodes.json",
	"dns_keys.json",
	"admin.json",
	"acme_config.json",
	".storage_key",
	"smtp_config.json",
	"rate_limit.json",
	"timezone.json",
	"proxy_config.json",
	"agent_config.json",
	"agent_manifest.json",
	"certs", // recursive directory
}

// handleBackupDownload creates a tar.gz of all configuration and streams it.
func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	s.logMgr.Log("system", "配置备份已下载", fmt.Sprintf("ip=%s", clientIP(r)), "info")

	ts := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("ddns-manager-backup-%s.tar.gz", ts)
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	gw := gzip.NewWriter(w)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	dataDir := s.cfg.DataDir

	for _, name := range backupFiles {
		fullPath := filepath.Join(dataDir, name)
		fi, err := os.Stat(fullPath)
		if os.IsNotExist(err) {
			continue // optional files may not exist
		}
		if err != nil {
			log.Printf("[backup] stat %s: %v", name, err)
			continue
		}

		if fi.IsDir() {
			filepath.Walk(fullPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					log.Printf("[backup] walk %s: %v", path, err)
					return nil
				}
				if info.IsDir() {
					return nil
				}
				rel, _ := filepath.Rel(dataDir, path)
				return addFileToTar(tw, path, rel, info)
			})
		} else {
			if err := addFileToTar(tw, fullPath, name, fi); err != nil {
				log.Printf("[backup] add %s: %v", name, err)
			}
		}
	}
}

func addFileToTar(tw *tar.Writer, fullPath, relPath string, fi os.FileInfo) error {
	f, err := os.Open(fullPath)
	if err != nil {
		return err
	}
	defer f.Close()

	hdr := &tar.Header{
		Name:    relPath,
		Size:    fi.Size(),
		Mode:    int64(fi.Mode()),
		ModTime: fi.ModTime(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// handleBackupRestore accepts a tar.gz backup and restores configuration.
func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 100<<20)

	if err := r.ParseMultipartForm(100 << 20); err != nil {
		jsonErr(w, http.StatusBadRequest, "文件过大或格式错误")
		return
	}

	file, _, err := r.FormFile("backup_file")
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "请选择备份文件")
		return
	}
	defer file.Close()

	tmpDir, err := os.MkdirTemp("", "ddns-restore-")
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "创建临时目录失败")
		return
	}
	defer os.RemoveAll(tmpDir)

	gz, err := gzip.NewReader(file)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "无法读取备份文件（不是有效的 gzip）")
		return
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	fileCount := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			jsonErr(w, http.StatusBadRequest, "备份文件损坏: "+err.Error())
			return
		}

		cleanName := filepath.Clean(hdr.Name)
		if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) {
			continue
		}

		targetPath := filepath.Join(tmpDir, cleanName)

		switch hdr.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(targetPath, 0700)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(targetPath), 0700)
			out, err := os.Create(targetPath)
			if err != nil {
				continue
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				continue
			}
			out.Close()
			os.Chmod(targetPath, os.FileMode(hdr.Mode))
			fileCount++
		}
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "nodes.json")); os.IsNotExist(err) {
		jsonErr(w, http.StatusBadRequest, "备份文件无效：缺少 nodes.json")
		return
	}
	if _, err := os.Stat(filepath.Join(tmpDir, ".storage_key")); os.IsNotExist(err) {
		jsonErr(w, http.StatusBadRequest, "备份文件无效：缺少 .storage_key（证书将无法解密）")
		return
	}

	// backup current data before overwriting
	backupDir, err := os.MkdirTemp("", "ddns-pre-restore-")
	if err == nil {
		for _, name := range backupFiles {
			src := filepath.Join(s.cfg.DataDir, name)
			if _, err := os.Stat(src); os.IsNotExist(err) {
				continue
			}
			copyPath(backupDir, s.cfg.DataDir, name)
		}
		cleanOldBackups(filepath.Dir(backupDir), 10)
	}

	dataDir := s.cfg.DataDir
	restored := 0
	for _, name := range backupFiles {
		src := filepath.Join(tmpDir, name)
		if _, err := os.Stat(src); os.IsNotExist(err) {
			continue
		}
		dest := filepath.Join(dataDir, name)
		os.RemoveAll(dest)
		if err := copyPath(dataDir, tmpDir, name); err != nil {
			log.Printf("[backup] restore %s: %v", name, err)
			jsonErr(w, http.StatusInternalServerError, fmt.Sprintf("恢复 %s 失败: %v", name, err))
			return
		}
		restored++
	}

	s.store.ResetCaches()
	if err := s.store.ReloadStorageKey(); err != nil {
		log.Printf("[backup] reload storage key: %v", err)
	}

	s.logMgr.Log("system", "配置已恢复",
		fmt.Sprintf("ip=%s files=%d", clientIP(r), restored), "warning")

	jsonOK(w, map[string]interface{}{
		"ok":      true,
		"message": fmt.Sprintf("已恢复 %d 个文件。建议重启服务以确保所有配置生效。", restored),
	})
}

func copyPath(destDir, baseDir, srcRel string) error {
	src := filepath.Join(baseDir, srcRel)
	dest := filepath.Join(destDir, srcRel)
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return copyDir(src, dest)
	}
	return copyFileContent(src, dest)
}

func copyFileContent(src, dest string) error {
	os.MkdirAll(filepath.Dir(dest), 0700)
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dest + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	out.Close()
	return os.Rename(tmp, dest)
}

func copyDir(src, dest string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dest, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		return copyFileContent(path, target)
	})
}

func cleanOldBackups(parentDir string, keep int) {
	entries, err := os.ReadDir(parentDir)
	if err != nil {
		return
	}
	var dirs []os.DirEntry
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "ddns-pre-restore-") {
			dirs = append(dirs, e)
		}
	}
	if len(dirs) <= keep {
		return
	}
	for i := 0; i < len(dirs)-keep; i++ {
		os.RemoveAll(filepath.Join(parentDir, dirs[i].Name()))
	}
}
