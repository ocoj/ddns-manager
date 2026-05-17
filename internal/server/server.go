package server

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/kk/ddns-manager/internal/acme"
	srvcfg "github.com/kk/ddns-manager/internal/config"
	"github.com/kk/ddns-manager/internal/logger"
	"github.com/kk/ddns-manager/internal/notify"
	"github.com/kk/ddns-manager/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const defaultAdminPassword = "Admin12345"
const maxUploadSize = 50 << 20

type Server struct {
	cfg             *srvcfg.ManagerConfig
	store           *store.ManagerStore
	acme            *acme.Manager   // default (backward compat)
	acmeMgrs        []*acme.Manager // multi-account managers (protected by acmeMu)
	logMgr          *logger.Manager
	adminToken      string // protected by adminTokenMu
	version         string // Manager version (from ldflags)
	accessCollector *accessStatsCollector
	// rate limiting
	globalLimiter    *rateLimiter
	heartbeatLimiter *rateLimiter
	loginLimiter     *rateLimiter
	pingLimiter      *rateLimiter // lightweight limit for /api/ping (1000 req/min)
	bcryptLimiter    *rateLimiter // H3: bcrypt fallback rate limit (5 req/min per IP)
	rateLock         sync.RWMutex
	// concurrency protection
	adminTokenMu sync.RWMutex
	acmeMu       sync.RWMutex
	// system info cache (updated by background goroutine)
	sysInfoMu   sync.RWMutex
	sysInfoCache map[string]interface{}
	// timezone cache (from timezone.json, defaults to Asia/Shanghai)
	timezoneMu sync.RWMutex
	timezone   *time.Location
}


func (s *Server) getAdminToken() string {
	s.adminTokenMu.RLock()
	defer s.adminTokenMu.RUnlock()
	return s.adminToken
}

func (s *Server) setAdminToken(token string) {
	s.adminTokenMu.Lock()
	defer s.adminTokenMu.Unlock()
	s.adminToken = token
}

func (s *Server) acmeMgrList() []*acme.Manager {
	s.acmeMu.RLock()
	defer s.acmeMu.RUnlock()
	out := make([]*acme.Manager, len(s.acmeMgrs))
	copy(out, s.acmeMgrs)
	return out
}

func (s *Server) addACMEMgr(mgr *acme.Manager) {
	s.acmeMu.Lock()
	defer s.acmeMu.Unlock()
	s.acmeMgrs = append(s.acmeMgrs, mgr)
}

func (s *Server) setACMEMgr(index int, mgr *acme.Manager) {
	s.acmeMu.Lock()
	defer s.acmeMu.Unlock()
	if index < len(s.acmeMgrs) {
		s.acmeMgrs[index] = mgr
	} else {
		s.acmeMgrs = append(s.acmeMgrs, mgr)
	}
}

func (s *Server) removeACMEMgr(index int) {
	s.acmeMu.Lock()
	defer s.acmeMu.Unlock()
	if index < len(s.acmeMgrs) {
		s.acmeMgrs = append(s.acmeMgrs[:index], s.acmeMgrs[index+1:]...)
	}
}

// GetTimezone returns the configured timezone location (thread-safe).
func (s *Server) GetTimezone() *time.Location {
	s.timezoneMu.RLock()
	defer s.timezoneMu.RUnlock()
	if s.timezone == nil {
		return time.Local
	}
	return s.timezone
}

// SetTimezone updates the timezone cache (called on startup and after settings change).
func (s *Server) SetTimezone(loc *time.Location) {
	s.timezoneMu.Lock()
	s.timezone = loc
	s.timezoneMu.Unlock()
	// propagate to sub-components that cache time
	if s.accessCollector != nil {
		s.accessCollector.SetTimezone(loc)
	}
	if s.logMgr != nil {
		s.logMgr.SetTimezone(loc)
	}
}

// nowInTZ returns current time in the configured timezone.
func (s *Server) nowInTZ() time.Time {
	return time.Now().In(s.GetTimezone())
}

// StartAutoRenew starts a background goroutine that renews ACME certs
// belonging to each registered account. Only ACME-issued certs with a
// matching email in meta.json are renewed; user-uploaded certs are skipped.

func (s *Server) StartAutoRenew(shutdown <-chan struct{}) {
	// ACME 自动续签 (每24小时)
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		// 启动时立即扫描证书过期
		s.scanCertExpiry()
		for {
			select {
			case <-ticker.C:
				mgrs := s.acmeMgrList()
				totalRenewed := 0
				// v1.5.31 H1: 每个 mgr 独立 context(5min), 防止多账号共享超时导致后续账号被截断
				for _, mgr := range mgrs {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
					renewed := mgr.Renew(ctx)
					for _, name := range renewed {
						if b, err := s.store.LoadCertBundle(name); err == nil {
							if saveErr := s.store.SaveCertBundle(b); saveErr != nil {
								log.Printf("[acme] SaveCertBundle %s: %v", name, saveErr)
							}
						}
						s.logMgr.Log("acme", "自动续期成功",
							fmt.Sprintf("%s (帐号=%s)", name, mgr.AccountInfo().Email), "success")
					}
					totalRenewed += len(renewed)
					cancel()
				}
				// v1.5.29 H2: ACME 空续签记录审计日志 (修复 v1.5.19 C4 回归)
				if totalRenewed == 0 {
					soonExpiring := s.countExpiringCerts(30)
					if soonExpiring > 0 {
						s.logMgr.Log("acme", "自动续期",
							fmt.Sprintf("无证书续签 (%d个证书30天内到期, 请检查acme.sh/证书配置)", soonExpiring), "warning")
					} else {
						s.logMgr.Log("acme", "自动续期", "无到期证书", "info")
					}
				}
				s.scanCertExpiry()
			case <-shutdown:
				log.Println("[acme] 续期协程已停止")
				return
			}
		}
	}()

	// 心跳失败检测 (每5分钟)
	go func() {
		heartbeatTicker := time.NewTicker(5 * time.Minute)
		defer heartbeatTicker.Stop()
		notified := make(map[string]time.Time)
		for {
			select {
			case <-heartbeatTicker.C:
				nodes, _ := s.store.LoadNodes()
				now := s.nowInTZ()
				for id, n := range nodes {
					if !n.Approved {
						continue
					}
					if now.Sub(n.LastSeen) > 10*time.Minute {
						// v1.6.10 H6: 记录详细时间差, 便于验证时区一致性
						diff := now.Sub(n.LastSeen)
						if lastNotified, ok := notified[id]; ok && now.Sub(lastNotified) < 1*time.Hour {
							continue
						}
						notified[id] = now
						s.logMgr.LogWithNode("heartbeat", "节点离线检测", id,
							fmt.Sprintf("diff=%v lastSeen=%s now=%s",
								diff, n.LastSeen.Format(time.RFC3339), now.Format(time.RFC3339)), "warning")
						s.tryNotify("heartbeat_fail", "节点离线",
							fmt.Sprintf("节点 %s 超过10分钟未心跳 (diff=%v, 最后心跳: %s)", id, diff, n.LastSeen.Format("01-02 15:04")))
					}
				}
			case <-shutdown:
				return
			}
		}
	}()
}

// scanCertExpiry checks all cert bundles and sends email alerts for those expiring within 30 days.
func (s *Server) scanCertExpiry() {
	names, err := s.store.ListCertBundles()
	if err != nil {
		return
	}
	var alerts []notify.CertAlert
	for _, name := range names {
		b, err := s.store.LoadCertBundle(name)
		if err != nil {
			continue
		}
		for _, content := range b.Files {
			if exp, _ := parseCertExpiry(content); exp != "" {
				expTime, err := time.Parse("2006-01-02", exp)
				if err != nil {
					continue
				}
				daysLeft := int(time.Until(expTime).Hours() / 24)
				if daysLeft <= 30 && daysLeft >= 0 {
					alerts = append(alerts, notify.CertAlert{
						BundleName: name,
						DaysLeft:   daysLeft,
						ExpiresAt:  exp,
					})
				}
				break
			}
		}
	}
	s.tryNotifyCertExpiry(alerts)
}

// countExpiringCerts 统计指定天数内过期的证书数量 (v1.5.29 H2)
func (s *Server) countExpiringCerts(days int) int {
	names, err := s.store.ListCertBundles()
	if err != nil {
		return 0
	}
	count := 0
	for _, name := range names {
		b, err := s.store.LoadCertBundle(name)
		if err != nil {
			continue
		}
		for _, content := range b.Files {
			if exp, _ := parseCertExpiry(content); exp != "" {
				expTime, err := time.Parse("2006-01-02", exp)
				if err != nil {
					continue
				}
				daysLeft := int(time.Until(expTime).Hours() / 24)
				if daysLeft <= days && daysLeft >= 0 {
					count++
				}
				break
			}
		}
	}
	return count
}

func New(cfg *srvcfg.ManagerConfig, s *store.ManagerStore, acmeMgr *acme.Manager, logMgr *logger.Manager, version string) *Server {
	svr := &Server{
		cfg: cfg, store: s, acme: acmeMgr, logMgr: logMgr,
		version:         version,
		accessCollector: newAccessStatsCollector(cfg.DataDir),
		pingLimiter:     newRateLimiter(1000), // /api/ping 轻量限流 1000 req/min
		bcryptLimiter:   newRateLimiter(5),    // H3: bcrypt 回退限流 5 req/min per IP
	}
	st, err := s.LoadAdminState()
	if err != nil {
		log.Fatalf("加载管理员状态失败: %v", err)
	}
	if st == nil {
		defaultToken := tokenFromPassword(defaultAdminPassword)
		hash, err := bcrypt.GenerateFromPassword([]byte(defaultToken), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("bcrypt 加密失败: %v", err)
		}
		st = &store.AdminState{TokenHash: string(hash), PasswordChanged: false}
		if err := s.SaveAdminState(st); err != nil {
			log.Fatalf("保存管理员状态失败: %v", err)
		}
		log.Println("[admin] 首次运行 — 已设置默认密码（请立即登录修改）")
	}
	if !st.PasswordChanged {
		svr.adminToken = tokenFromPassword(defaultAdminPassword)
	}
	// init multi-account ACME managers
	svr.initACMEManagers()
	// 加载时区配置，应用到流量统计、日志轮转、和所有时间展示
	tzCfg, _ := s.LoadTimezoneConfig()
	loc, err := time.LoadLocation(tzCfg.Timezone)
	if err != nil {
		loc = time.Local
	}
	// 统一设置：Server自身缓存 + accessCollector + logger
	svr.SetTimezone(loc)
	return svr
}

// initACMEManagers initializes multi-account ACME managers from stored config.
// 
// ⚠️ 锁顺序规范: acmeMu 和 store.mu 是独立锁，任何代码路径不得同时持有两者。
// handleACMESaveAccountIndex 持有 store.mu → acmeMu (PutACMEAccount → addACMEMgr)，
// 因此 initACMEManagers 不能持有 acmeMu 时调用 store 方法（反序死锁）。
// 本函数在受保护的环境下构建 mgr 列表，释放 acmeMu 后才启动后台 goroutine。
func (s *Server) initACMEManagers() {
	// 阶段1: 构建 ACME manager 列表 (持 acmeMu)
	s.acmeMu.Lock()
	accounts, err := s.store.LoadACMEAccounts()
	if err != nil || len(accounts) == 0 {
		if s.acme != nil {
			s.acmeMgrs = []*acme.Manager{s.acme}
		}
		s.acmeMu.Unlock()
		return
	}
	certsDir := filepath.Join(s.cfg.DataDir, "certs")
	type mgrInit struct {
		mgr   *acme.Manager
		idx   int
		email string
		ac    store.ACMEAccountConfig
	}
	var inits []mgrInit
	for _, ac := range accounts {
		mgr, err := acme.NewWithKey(certsDir, ac.Email, ":80", []byte(ac.AccountKey))
		if err != nil {
			log.Printf("[acme] 初始化 %s/%s 失败: %v", ac.Email, ac.CA, err)
			continue
		}
		for _, ca := range acme.AllCAs {
			if strings.EqualFold(ca.Name, ac.CA) {
				mgr.SetCA(ca)
				break
			}
		}
		if ac.KeyType != "" {
			mgr.SetKeyType(acme.ParseKeyType(ac.KeyType))
		}
		if ac.EABKID != "" && ac.EABKey != "" {
			mgr.SetEAB(&acme.EAB{KID: ac.EABKID, HMACKey: ac.EABKey})
		}
		s.acmeMgrs = append(s.acmeMgrs, mgr)
		inits = append(inits, mgrInit{
			mgr: mgr, idx: len(s.acmeMgrs) - 1,
			email: ac.Email, ac: ac,
		})
	}
	mgrCount := len(s.acmeMgrs)
	s.acmeMu.Unlock() // ← 释放 acmeMu，允许 handleACMESaveAccountIndex 并发执行

	// 阶段2: 后台注册账号 (不持任何锁，避免与 store.mu 形成反序)
	for _, init := range inits {
		mgr, idx, email, ac := init.mgr, init.idx, init.email, init.ac
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := mgr.RegisterAccount(ctx); err != nil {
				log.Printf("[acme] 注册帐号 %s 失败: %v", email, err)
				return
			}
			keyPEM, _ := mgr.AccountKeyPEM()
			if keyPEM != nil && ac.AccountKey == "" {
				// 持久化密钥: 仅持 store.mu (LoadACMEAccounts → SaveACMEAccounts)
				// 不触碰 acmeMu，避免与 handleACMESaveAccountIndex 形成反序
				s.updateACMEMgrKey(idx, string(keyPEM))
			}
			log.Printf("[acme] 帐号已就绪: %s", email)
		}()
	}
	log.Printf("[acme] 已加载 %d 个 ACME 帐号", mgrCount)
}

// v1.6.30 H4: 原子化 updateACMEMgrKey, 使用 store 级写锁保护 Load→Modify→Save
// 防止多 goroutine 并发注册 ACME 账号时的 TOCTOU 写覆盖
func (s *Server) updateACMEMgrKey(index int, keyPEM string) {
	err := s.store.UpdateACMEAccountsAtomic(func(accounts []store.ACMEAccountConfig) error {
		if index >= len(accounts) {
			return fmt.Errorf("index out of range: %d >= %d", index, len(accounts))
		}
		accounts[index].AccountKey = keyPEM
		return nil
	})
	if err != nil {
		log.Printf("[acme] 持久化密钥失败: %v", err)
	}
}

func (s *Server) Router() *mux.Router {
	r := mux.NewRouter()
	// public (with rate limiting)
	r.HandleFunc("/api/ping", s.pingRateLimitMiddleware(s.handlePing)).Methods("GET")
	r.HandleFunc("/api/auth/login", s.rateLimitMiddleware(s.handleLogin, false, true)).Methods("POST")
	r.HandleFunc("/api/admin/status", s.handleAdminStatus).Methods("GET")
	r.HandleFunc("/api/heartbeat", s.rateLimitMiddleware(s.handleHeartbeat, true, false)).Methods("POST")
	r.HandleFunc("/api/register", s.rateLimitMiddleware(s.handleRegister, false, false)).Methods("POST")
	// fingerprint lookup (public) — installer pre-check for node name conflicts
	r.HandleFunc("/api/nodes/{id}/fingerprint", s.handleNodeFingerprint).Methods("GET")

	// admin (auth required)
	a := r.PathPrefix("/api/admin").Subrouter()
	a.Use(s.adminMiddleware)

	// dashboard
	a.HandleFunc("/stats", s.handleStats).Methods("GET")
	a.HandleFunc("/access-stats", s.handleAccessStats).Methods("GET")
	a.HandleFunc("/system-info", s.handleSystemInfo).Methods("GET")
	// nodes
	a.HandleFunc("/nodes", s.handleListNodes).Methods("GET")
	a.HandleFunc("/nodes/{id}", s.handleGetNode).Methods("GET")
	a.HandleFunc("/nodes/{id}/approve", s.handleApproveNode).Methods("POST")
	a.HandleFunc("/nodes/{id}/config", s.handleSaveNodeConfig).Methods("PUT")
	a.HandleFunc("/nodes/{id}", s.handleDeleteNode).Methods("DELETE")
	// dns keys
	a.HandleFunc("/dns-keys", s.handleListDNSKeys).Methods("GET")
	a.HandleFunc("/dns-keys", s.handleSaveDNSKey).Methods("POST")
	a.HandleFunc("/dns-keys/{name}/test", s.handleTestDNSKey).Methods("POST") // v1.5.33: 在线核验
	a.HandleFunc("/dns-keys/{name}", s.handleDeleteDNSKey).Methods("DELETE")
	// certs
	a.HandleFunc("/certs", s.handleListCerts).Methods("GET")
	a.HandleFunc("/certs/{name}", s.handleGetCert).Methods("GET")
	a.HandleFunc("/certs", s.handleUploadCert).Methods("POST")
	a.HandleFunc("/certs/{name}", s.handleDeleteCert).Methods("DELETE")
	a.HandleFunc("/certs/{name}/download", s.handleDownloadCert).Methods("GET")
	a.HandleFunc("/certs/{name}/pfx", s.handleDownloadPFX).Methods("GET")
	a.HandleFunc("/certs/{name}/pfx-password", s.handleSetCertPFXPassword).Methods("POST")
	a.HandleFunc("/certs/{name}/renew", s.handleRenewCert).Methods("POST")
	a.HandleFunc("/certs/{name}/push/{id}", s.handleForcePushCert).Methods("POST")  // v1.6.0: 测试用强制推送
	// acme (multi-account)
	a.HandleFunc("/acme/all", s.handleACMEList).Methods("GET")
	a.HandleFunc("/acme/accounts/{index}", s.handleACMESaveAccountIndex).Methods("PUT")
	a.HandleFunc("/acme/accounts/{index}", s.handleACMEDeleteAccount).Methods("DELETE")
	a.HandleFunc("/acme/issue", s.handleACMEIssue).Methods("POST")
	// logs
	a.HandleFunc("/logs", s.handleGetLogs).Methods("GET")
	a.HandleFunc("/logs/download", s.handleLogsDownload).Methods("GET")
	a.HandleFunc("/logs/cleanup", s.handleLogsCleanup).Methods("POST")
	// admin
	a.HandleFunc("/change-password", s.handleChangePassword).Methods("POST")
	// agent version
	a.HandleFunc("/agent-version", s.handleGetAgentVersion).Methods("GET")
	a.HandleFunc("/agent-version", s.handleSetAgentVersion).Methods("POST")
	a.HandleFunc("/agent-upgrade-state", s.handleGetUpgradeState).Methods("GET")
	a.HandleFunc("/agent-binaries", s.handleListAgentBinaries).Methods("GET")
	a.HandleFunc("/agent-binaries", s.handleUploadAgentBinary).Methods("POST")
	a.HandleFunc("/agent-binaries/{name}", s.handleDeleteAgentBinary).Methods("DELETE")
	// 运行时打包 Windows 安装 ZIP
	a.HandleFunc("/download-installer", s.handleDownloadInstaller).Methods("GET")
	// smtp
	a.HandleFunc("/smtp", s.handleGetSMTP).Methods("GET")
	a.HandleFunc("/smtp", s.handleSaveSMTP).Methods("POST")
	a.HandleFunc("/smtp/test", s.handleSMTPTest).Methods("POST")
	// rate-limit
	a.HandleFunc("/rate-limit", s.handleGetRateLimit).Methods("GET")
	a.HandleFunc("/rate-limit", s.handleSaveRateLimit).Methods("POST")
	// timezone
	a.HandleFunc("/timezone", s.handleGetTimezone).Methods("GET")
	a.HandleFunc("/timezone", s.handleSaveTimezone).Methods("POST")

	// static

	// /bin/ file server — explicit HandleFunc avoids PathPrefix("/") conflict
	r.HandleFunc("/bin/{filename:.*}", s.handleBinFile).Methods("GET", "HEAD")
	// /dl/ alternative download path — some proxies (NPM) block /bin/
	r.HandleFunc("/dl/{filename:.*}", s.handleBinFile).Methods("GET", "HEAD")

	// static SPA served by cmd/manager/main.go
	return r
}

// ── middleware ──
