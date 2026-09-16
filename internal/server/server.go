package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocoj/ddns-manager/internal/acme"
	srvcfg "github.com/ocoj/ddns-manager/internal/config"
	"github.com/ocoj/ddns-manager/internal/logger"
	"github.com/ocoj/ddns-manager/internal/notify"
	"github.com/ocoj/ddns-manager/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const defaultAdminPassword = "Admin12345"
const maxUploadSize = 50 << 20

type Server struct {
	cfg              *srvcfg.ManagerConfig
	store            *store.ManagerStore
	acme             *acme.Manager   // default (backward compat)
	acmeMgrs         []*acme.Manager // multi-account managers (protected by acmeMu)
	logMgr           *logger.Manager
	adminToken       string // protected by adminTokenMu
	version          string // Manager version (from ldflags)
	installerVersion string // Installer version (from ldflags)
	accessCollector  *accessStatsCollector
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
	// v1.6.71 N1: acme.sh 路径/home 接线（I26/I27/I29）。
	// acmeHasCerts 必须在**未持有 acmeMu** 时求值 —— 锁顺序规范禁止同时持有
	// acmeMu 与 store.mu，故 attachAcmeShPath 全程不触碰 store。
	acmeHasCerts     bool
	acmeWireMu       sync.Mutex
	acmeWireIssues   []acmeWireIssue
	acmeHomeNotified bool
	// acmeCaveatSeen 只增不退：键为 (action, detail)，其中 detail 含 home 路径。
	// 前提 = home 路径集合有界（实际 ≤ 候选数），故不构成内存泄漏；tick 场景亦不会增长。
	acmeCaveatSeen map[string]bool
	// system info cache (updated by background goroutine)
	sysInfoMu    sync.RWMutex
	sysInfoCache map[string]interface{}
	// timezone cache (from timezone.json, defaults to Asia/Shanghai)
	timezoneMu sync.RWMutex
	timezone   *time.Location
	// notification cooldown (v1.6.53): 安全事件 30min 冷却
	notifyCooldown   map[string]time.Time
	notifyCooldownMu sync.Mutex
	// trusted proxy config (from proxy_config.json, runtime modifiable via Web UI)
	proxyConfigMu sync.RWMutex
	proxyConfig   *store.ProxyConfig
	// v1.6.70 S9: per-bundle serialisation of PFX reconciliation (I18/I22)
	certRebuildMu sync.Mutex
	certRebuild   map[string]*sync.Mutex
	// v1.6.70 S9: state-change dedup for bundle consistency audits (I23/I25).
	// Keyed by bundle name; guarded by its own lock, never by the rebuild lock.
	pfxAuditMu  sync.Mutex
	pfxAuditSig map[string]string
}

// attachDNSKeyLookup wires the DNS key resolver into an ACME manager.
//
// Every registered Manager must be wired, otherwise renewals silently fall back
// to acme.sh's global account.conf credentials — the sp incident root cause.
// It only touches the manager's own mutex, so it is safe to call while holding
// acmeMu (sync.RWMutex is not reentrant, so routing through addACMEMgr inside
// the lock would self-deadlock — invariant I10).
// acmeWireIssue 记录一次 acme.sh 接线问题：在 acmeMu 锁内只做收集，
// 统一在锁外落审计（锁顺序规范）。
type acmeWireIssue struct {
	action, detail string
	level          string // "error"（默认/接线故障）或 "warning"（B-2 非判定性提示）
}

// detectLocalACMECerts 判定本地是否已管理 ACME 证书（用于候选判定表的"语义分层"）。
// ⚠️ 必须在不持有 acmeMu 时调用。
func (s *Server) detectLocalACMECerts() bool {
	names, err := s.store.ListCertBundles()
	if err != nil {
		// v1.6.71 G4: 读失败时**保守**按"已有证书"处理 —— 返回 false 会等价于"全新安装"，
		// 从而解锁判定表中"未初始化路径被采用"的分支（异常场景下把 home 建到非预期位置）。
		s.reportAcmeWireIssue("无法判定本地 ACME 证书集合（按“已有证书”保守处理）", err.Error())
		return true
	}
	readErr := 0
	for _, n := range names {
		meta, err := s.store.LoadCertMeta(n)
		if err != nil {
			readErr++
			continue
		}
		if is, _ := meta["acme"].(bool); is {
			return true
		}
	}
	if readErr > 0 {
		// 同理：有 meta 不可读 ⇒ 无法排除"存在 ACME 证书" ⇒ 保守处理 + 审计
		s.reportAcmeWireIssue("部分证书 meta 不可读（按“已有证书”保守处理）",
			fmt.Sprintf("%d 个 bundle 的 meta 读取失败", readErr))
		return true
	}
	return false
}

// resolveAcmeShPath 解析 acme.sh 可执行路径（C5/I29）：
// 优先 cfg.Cert.Provider（须绝对路径 + 存在 + 可执行），否则回退 exec.LookPath。
func (s *Server) resolveAcmeShPath() (string, *acmeWireIssue) {
	if p := strings.TrimSpace(s.cfg.Cert.Provider); p != "" {
		switch {
		case !filepath.IsAbs(p):
			return s.lookPathAcmeSh(), &acmeWireIssue{action: "cert.provider 非绝对路径，已回退 PATH 查找", detail: p, level: "error"}
		default:
			fi, err := os.Stat(p)
			if err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
				return s.lookPathAcmeSh(), &acmeWireIssue{action: "cert.provider 不可用（不存在/非文件/不可执行），已回退 PATH 查找", detail: p, level: "error"}
			}
			return p, nil
		}
	}
	return s.lookPathAcmeSh(), nil
}

func (s *Server) lookPathAcmeSh() string {
	if p, err := exec.LookPath("acme.sh"); err == nil {
		return p
	}
	return ""
}

// attachAcmeShPath 注入 acme.sh 路径并显式固定 ACME home（I26/I29）。
//
// 覆盖全部 Manager 构造点；只调用 Manager 自身方法与 acmeWireMu，因此可在 acmeMu
// 锁内安全调用。解析失败不阻断启动，但该 Manager 的所有 acme.sh 调用都会 fail-fast。
func (s *Server) attachAcmeShPath(mgr *acme.Manager) {
	if mgr == nil {
		return
	}
	if path, issue := s.resolveAcmeShPath(); issue != nil {
		s.reportAcmeWireIssue(issue.action, issue.detail)
	} else if path != "" {
		mgr.SetAcmeShPath(path)
	}
	if err := mgr.ResolveAcmeHome(s.acmeHasCerts); err != nil {
		s.reportAcmeWireIssue("acme.sh home 解析失败（已拒绝执行 acme.sh）", err.Error())
	}
	// v1.6.73 B-2：非判定性提示走独立 warning 通道（跨 flush 去重），不影响 fail-fast 判定。
}

func (s *Server) reportAcmeWireIssue(action, detail string) {
	s.acmeWireMu.Lock()
	s.acmeWireIssues = append(s.acmeWireIssues, acmeWireIssue{action: action, detail: detail})
	s.acmeWireMu.Unlock()
}

// reportAcmeCaveats 记录**非判定性**提示（B-2）：一律 warning 级，
// 且**跨 flush 去重**（同一 (action, detail) 只记一次），避免每次 attach 重复噪音。
// 注：去重键含 detail（其中含 home 路径）⇒ 不同路径各自成条（正确）。
func (s *Server) reportAcmeCaveats(caveats []string) {
	if len(caveats) == 0 {
		return
	}
	s.acmeWireMu.Lock()
	defer s.acmeWireMu.Unlock()
	if s.acmeCaveatSeen == nil {
		s.acmeCaveatSeen = map[string]bool{}
	}
	for _, c := range caveats {
		if strings.TrimSpace(c) == "" {
			continue
		}
		key := "home 告警\x00" + c
		if s.acmeCaveatSeen[key] {
			continue
		}
		s.acmeCaveatSeen[key] = true
		s.acmeWireIssues = append(s.acmeWireIssues, acmeWireIssue{action: "home 告警", detail: c, level: "warning"})
	}
}

// flushAcmeWireIssues 在锁外落审计，并对 home 解析失败做**一次性**通知（Q4）。
func (s *Server) flushAcmeWireIssues() {
	s.acmeWireMu.Lock()
	issues := s.acmeWireIssues
	s.acmeWireIssues = nil
	notified := s.acmeHomeNotified
	s.acmeWireMu.Unlock()
	if len(issues) == 0 {
		return
	}
	failFast, detail := false, ""
	seen := make(map[string]bool, len(issues))
	for _, is := range issues {
		// v1.6.71 G5: 多账号共用同一故障 ⇒ 审计只记一条（与通知去重口径一致）
		key := is.action + "\x00" + is.detail
		if seen[key] {
			continue
		}
		seen[key] = true
		lvl := is.level
		if lvl == "" {
			lvl = "error"
		}
		if s.logMgr != nil {
			s.logMgr.Log("acme", is.action, is.detail, lvl)
		}
		if strings.Contains(is.action, "home 解析失败") {
			failFast, detail = true, is.detail
		}
	}
	if failFast && !notified {
		s.acmeWireMu.Lock()
		s.acmeHomeNotified = true
		s.acmeWireMu.Unlock()
		s.tryNotify("acme", "acme.sh home 不可用 — 已拒绝执行 acme.sh（证书续期将失效）", detail, "")
	}
}

func (s *Server) attachDNSKeyLookup(mgr *acme.Manager) {
	if mgr == nil {
		return
	}
	mgr.SetDNSKeyLookup(func() map[string]*acme.DNSProvider {
		keys, err := s.store.LoadDNSKeys()
		if err != nil {
			log.Printf("[acme] 读取 DNS Key 失败: %v", err)
			return nil
		}
		out := make(map[string]*acme.DNSProvider, len(keys))
		for name, k := range keys {
			out[name] = &acme.DNSProvider{
				Name: k.Provider, KeyID: k.AccessKeyID,
				KeySecret: k.AccessKeySecret, KeyName: name,
			}
		}
		return out
	})
}

// lockBundleRebuild serialises PFX reconciliation for a single bundle (I18).
// Returns the unlock func. Must never be acquired while holding a store lock.
func (s *Server) lockBundleRebuild(name string) func() {
	s.certRebuildMu.Lock()
	if s.certRebuild == nil {
		s.certRebuild = map[string]*sync.Mutex{}
	}
	mu, ok := s.certRebuild[name]
	if !ok {
		mu = &sync.Mutex{}
		s.certRebuild[name] = mu
	}
	s.certRebuildMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

// clearPFXAuditSig drops the dedup signature of a deleted bundle (I25).
func (s *Server) clearPFXAuditSig(name string) {
	s.pfxAuditMu.Lock()
	delete(s.pfxAuditSig, name)
	s.pfxAuditMu.Unlock()
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
	s.attachDNSKeyLookup(mgr) // v1.6.70: 挂载点 4/4
	s.attachAcmeShPath(mgr)   // v1.6.71 N1: acme.sh 路径 + home（I29）
	s.acmeMgrs = append(s.acmeMgrs, mgr)
}

func (s *Server) setACMEMgr(index int, mgr *acme.Manager) {
	s.acmeMu.Lock()
	defer s.acmeMu.Unlock()
	s.attachDNSKeyLookup(mgr) // v1.6.70: 挂载点 4/4
	s.attachAcmeShPath(mgr)   // v1.6.71 N1: acme.sh 路径 + home（I29）
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

// GetTrustedProxy returns the runtime trusted proxy IP (empty = disabled, use RemoteAddr).
func (s *Server) GetTrustedProxy() string {
	s.proxyConfigMu.RLock()
	defer s.proxyConfigMu.RUnlock()
	if s.proxyConfig != nil {
		return s.proxyConfig.TrustedProxy
	}
	return ""
}

// SetTrustedProxy updates the runtime trusted proxy IP (called after Web UI save).
func (s *Server) SetTrustedProxy(ip string) {
	s.proxyConfigMu.Lock()
	s.proxyConfig = &store.ProxyConfig{TrustedProxy: ip}
	s.proxyConfigMu.Unlock()
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
				// v1.6.45 C2: 用匿名函数包裹每次迭代, defer cancel() 在 Renew 返回后立即执行
				// defer 在 for 循环内会堆积到 goroutine 退出(24h后)才释放, 造成 context 泄漏
				for _, mgr := range mgrs {
					func() {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
						defer cancel()
						email := mgr.AccountInfo().Email
						// v1.6.70: 改为按次返回 outcomes —— 每个证书独立结果，
						// 不再依赖共享 lastRenewErr（并发下互相覆盖），
						// 并按 RenewKind 分级落审计（S4）。
						for _, o := range mgr.RenewWithOutcomes(ctx) {
							switch o.Kind {
							case acme.KindOK:
								if b, err := s.store.LoadCertBundle(o.Name); err == nil {
									if saveErr := s.store.SaveCertBundle(b); saveErr != nil {
										log.Printf("[acme] SaveCertBundle %s: %v", o.Name, saveErr)
									}
								}
								s.logMgr.Log("acme", "自动续期成功",
									fmt.Sprintf("%s (帐号=%s)", o.Name, email), "success")
								totalRenewed++
							case acme.KindNotReplaced:
								s.logMgr.Log("acme", "自动续期未替换证书",
									fmt.Sprintf("%s: acme.sh 返回成功但 fullchain.pem 未变化", o.Name), "warning")
							case acme.KindFailed:
								s.logMgr.Log("acme", "自动续期失败",
									fmt.Sprintf("%s: %v", o.Name, o.Err), "error")
							}
						}
					}()
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
					if now.Sub(n.LastSeen) > 5*time.Minute && n.Status.DDNSHealth != nil && n.Status.DDNSHealth.Running {
						n.Status.DDNSHealth.Running = false
						old := n.Status.DDNSHealth.Status
						n.Status.DDNSHealth.Status = "DOWN"
						s.logMgr.LogWithNode("节点", "健康状态变更", "管理端",
							fmt.Sprintf("%s 健康状态变更 %s → DOWN (离线 %v)", id, old, now.Sub(n.LastSeen).Round(time.Second)), "error")
					}
					if now.Sub(n.LastSeen) > 10*time.Minute {
						// v1.6.10 H6: 记录详细时间差, 便于验证时区一致性
						diff := now.Sub(n.LastSeen)
						// v1.6.53: 离线通知冷却从 SMTP 配置读取（默认 60 分钟）
						heartbeatCooldown := 60
						if smtpCfg, _ := s.store.LoadSMTPConfig(); smtpCfg != nil && smtpCfg.HeartbeatFailCooldown > 0 {
							heartbeatCooldown = smtpCfg.HeartbeatFailCooldown
						}
						if lastNotified, ok := notified[id]; ok && now.Sub(lastNotified) < time.Duration(heartbeatCooldown)*time.Minute {
							continue
						}
						notified[id] = now
						s.logMgr.LogWithNode("heartbeat", "节点离线检测", id,
							fmt.Sprintf("diff=%v lastSeen=%s now=%s",
								diff, n.LastSeen.Format(time.RFC3339), now.Format(time.RFC3339)), "warning")
						s.tryNotify("heartbeat_fail", "节点离线",
							fmt.Sprintf("节点 %s 超过10分钟未心跳 (diff=%v, 最后心跳: %s)", id, diff, n.LastSeen.Format("01-02 15:04")), "")
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

// StartBinWatcher v1.6.41: 轮询 bin/ 目录, 检测到文件变化时自动重建 manifest
// 30s 间隔, 零依赖, 兼容所有文件系统 (NFS/CIFS)
// 解决手动 SCP 部署 Agent 二进制后 manifest 未更新的问题
// v1.6.42 C3: 全量扫描记录 maxModTime, 循环结束后一次 rebuild, 避免 break 遗漏后续文件
func (s *Server) StartBinWatcher(shutdown <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		var lastMod time.Time
		binDir := s.store.AgentBinDir()
		for {
			select {
			case <-ticker.C:
				entries, err := os.ReadDir(binDir)
				if err != nil {
					continue
				}
				// 全量扫描记录目录内最新修改时间, 避免 break 遗漏文件
				var maxModTime time.Time
				for _, e := range entries {
					if e.IsDir() {
						continue
					}
					info, err := e.Info()
					if err != nil {
						continue
					}
					if info.ModTime().After(maxModTime) {
						maxModTime = info.ModTime()
					}
				}
				if maxModTime.After(lastMod) {
					s.store.RebuildManifest()
					lastMod = maxModTime
					log.Printf("[bin-watcher] 检测到 bin/ 变化, manifest 已重建")
				}
			case <-shutdown:
				log.Println("[bin-watcher] 已停止")
				return
			}
		}
	}()
}

func New(cfg *srvcfg.ManagerConfig, s *store.ManagerStore, acmeMgr *acme.Manager, logMgr *logger.Manager, version string, installerVersion string) *Server {
	svr := &Server{
		cfg: cfg, store: s, acme: acmeMgr, logMgr: logMgr,
		version:          version,
		installerVersion: installerVersion,
		accessCollector:  newAccessStatsCollector(cfg.DataDir),
		pingLimiter:      newRateLimiter(1000), // /api/ping 轻量限流 1000 req/min
		bcryptLimiter:    newRateLimiter(5),    // H3: bcrypt 回退限流 5 req/min per IP
		notifyCooldown:   make(map[string]time.Time),
	}
	st, err := s.LoadAdminState()
	if err != nil {
		log.Fatalf("加载管理员状态失败: %v", err)
	}
	if st == nil {
		// v1.6.46 H4: 生成实例级随机 salt, 防止同密码跨实例 token 复用
		saltBytes := make([]byte, 32)
		if _, err := rand.Read(saltBytes); err != nil {
			log.Fatalf("生成实例 salt 失败: %v", err)
		}
		instanceSalt := hex.EncodeToString(saltBytes)
		defaultToken := tokenFromPasswordWithSalt(defaultAdminPassword, instanceSalt)
		hash, err := bcrypt.GenerateFromPassword([]byte(defaultToken), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("bcrypt 加密失败: %v", err)
		}
		st = &store.AdminState{TokenHash: string(hash), PasswordChanged: false, InstanceSalt: instanceSalt}
		if err := s.SaveAdminState(st); err != nil {
			log.Fatalf("保存管理员状态失败: %v", err)
		}
		log.Println("[admin] 首次运行 — 已设置默认密码（请立即登录修改）")
	}
	if !st.PasswordChanged {
		if st.InstanceSalt != "" {
			svr.adminToken = tokenFromPasswordWithSalt(defaultAdminPassword, st.InstanceSalt)
		} else {
			svr.adminToken = tokenFromPassword(defaultAdminPassword)
		}
	}
	// v1.6.71 N1: acme.sh 路径 + home 接线。
	// ① acmeHasCerts 必须在未持 acmeMu 时求值（锁顺序规范：不得同时持 acmeMu 与 store.mu）；
	// ② 先接线 main.go 构造的默认 Manager（I29 覆盖该构造点）。
	svr.acmeHasCerts = svr.detectLocalACMECerts()
	svr.attachAcmeShPath(svr.acme)
	// init multi-account ACME managers
	svr.initACMEManagers()
	// v1.6.70 I15: 启动自检（凭据解析器接线 + meta.dns_key 数据前置条件），仅一次
	svr.startupAudit()
	// 加载时区配置，应用到流量统计、日志轮转、和所有时间展示
	tzCfg, _ := s.LoadTimezoneConfig()
	loc, err := time.LoadLocation(tzCfg.Timezone)
	if err != nil {
		loc = time.Local
	}
	// 统一设置：Server自身缓存 + accessCollector + logger
	svr.SetTimezone(loc)
	// 加载受信代理配置：优先 proxy_config.json，回退到 manager.yaml
	proxyCfg, _ := s.LoadProxyConfig()
	if proxyCfg != nil && proxyCfg.TrustedProxy != "" {
		svr.proxyConfig = proxyCfg
	} else if cfg.Server.TrustedProxy != "" {
		svr.proxyConfig = &store.ProxyConfig{TrustedProxy: cfg.Server.TrustedProxy}
		_ = s.SaveProxyConfig(svr.proxyConfig) // 迁入 JSON（只迁移非空值）
	}
	return svr
}

// startupAudit performs the one-shot wiring and data self-checks (I15).
//
// Two failure modes motivated it: (1) an ACME manager whose DNS key resolver was
// never attached silently falls back to acme.sh's global account.conf, so the
// fix would appear to work while doing nothing; (2) an ACME bundle without
// meta.dns_key cannot resolve its key precisely and degrades to the ambiguous
// unique-match fallback.
func (s *Server) startupAudit() {
	// v1.6.73 B-2：统一采集各 manager 的**非判定性**提示（仅告警通道；不参与任何判定）。
	// 采集点放在这里而非 attachAcmeShPath —— attach 保持"纯接线"，不改动既有审计时序（T49e 不变量）。
	for _, cm := range s.acmeMgrs {
		if cm != nil {
			s.reportAcmeCaveats(cm.AcmeHomeCaveats())
		}
	}
	unwired := 0
	for _, mgr := range s.acmeMgrList() {
		if mgr == nil || !mgr.KeyLookupConfigured() {
			unwired++
		}
	}
	if unwired > 0 {
		msg := fmt.Sprintf("%d 个 ACME 帐号缺少 DNS Key 解析器 — 续期将回退 acme.sh account.conf，自动续期可能失效", unwired)
		log.Printf("[acme] 启动自检: %s", msg)
		if s.logMgr != nil {
			s.logMgr.Log("acme", "凭据解析器未挂载", msg, "error")
		}
	}

	names, err := s.store.ListCertBundles()
	if err != nil {
		return
	}
	missing := 0
	for _, name := range names {
		meta, err := s.store.LoadCertMeta(name)
		if err != nil {
			continue
		}
		if is, _ := meta["acme"].(bool); !is {
			continue
		}
		if keyName, _ := meta["dns_key"].(string); keyName == "" {
			missing++
		}
	}
	if missing > 0 {
		msg := fmt.Sprintf("%d 个 ACME 证书缺少 meta.dns_key — 续期将回退唯一匹配/account.conf，建议执行迁移脚本", missing)
		log.Printf("[acme] 启动自检: %s", msg)
		if s.logMgr != nil {
			s.logMgr.Log("acme", "凭据未登记", msg, "warning")
		}
	}

	// ④ v1.6.71 N1（I29）: acme.sh 路径 + ACME home 接线自检。
	// 未接线 ⇒ 相关 acme.sh 调用一律拒绝执行（fail-fast），此处必须显式可见。
	pathUnset, homeUnset := 0, 0
	for _, mgr := range s.acmeMgrList() {
		if mgr == nil {
			continue
		}
		if mgr.AcmeShPath() == "" {
			pathUnset++
		}
		if !mgr.AcmeHomeConfigured() {
			homeUnset++
		}
	}
	if pathUnset > 0 || homeUnset > 0 {
		msg := fmt.Sprintf("%d 个 ACME 帐号未接线 acme.sh 路径、%d 个未固定 ACME home — 相关调用将拒绝执行", pathUnset, homeUnset)
		log.Printf("[acme] 启动自检: %s", msg)
		if s.logMgr != nil {
			s.logMgr.Log("acme", "acme.sh 接线未完成", msg, "error")
		}
	}
	s.flushAcmeWireIssues()

	// ③ 一致性只读预检（v1.6.70 B5）：只判定与审计，绝不重建。
	// 两个作用：a) 启动即暴露 PEM/PFX 不一致，不必等首个心跳；
	//          b) 预热去重签名，避免重启后首轮心跳为每个 bundle 各输出一条 info。
	flagged := 0
	for _, name := range names {
		meta, err := s.store.LoadCertMeta(name)
		if err != nil {
			continue
		}
		if is, _ := meta["acme"].(bool); !is {
			continue
		}
		b, err := s.store.LoadCertBundle(name)
		if err != nil {
			continue
		}
		verdict, reason, hard := s.checkBundlePFXConsistency(b, meta)
		s.auditBundleConsistency(name, b, meta, verdict, reason, hard)
		if verdict != pfxConsistent {
			flagged++
		}
	}
	if flagged > 0 {
		log.Printf("[acme] 启动自检: %d 个 ACME bundle 存在一致性问题（详见 cert 审计；心跳推送时按需重建）", flagged)
	}
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
			s.attachDNSKeyLookup(s.acme) // v1.6.70: 挂载点 2/4（回退分支）
			s.attachAcmeShPath(s.acme)   // v1.6.71 N1: 同一 acme.sh 路径/home（I29）
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
		// v1.6.70: 挂载点 3/4 —— 就在 acmeMu 锁内。attachDNSKeyLookup 只触
		// manager 自身 m.mu，不改动 acmeMu 语义；若改走 addACMEMgr 会因
		// RWMutex 非重入而在启动时自死锁（I10）。
		s.attachDNSKeyLookup(mgr)
		s.attachAcmeShPath(mgr) // v1.6.71 N1: 同一 acme.sh 路径/home（I29）
		inits = append(inits, mgrInit{
			mgr: mgr, idx: len(s.acmeMgrs) - 1,
			email: ac.Email, ac: ac,
		})
	}
	mgrCount := len(s.acmeMgrs)
	s.acmeMu.Unlock() // ← 释放 acmeMu，允许 handleACMESaveAccountIndex 并发执行

	// 阶段2: 后台注册账号 (不持任何锁，避免与 store.mu 形成反序)
	// v1.6.50 M5: 用 semaphore 限制并发注册 goroutine 数 (最多3个并发), 防止配置大量ACME
	// 账号时并发注册请求压垮ACME服务器或堆积goroutine
	sem := make(chan struct{}, 3)
	for _, init := range inits {
		mgr, idx, email, ac := init.mgr, init.idx, init.email, init.ac
		sem <- struct{}{} // 获取信号量
		go func() {
			defer func() { <-sem }() // 释放信号量
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

	// F5: 后台验证 acme.sh 实际可用性（不阻塞启动，仅第一个 Manager 检查即可）
	if mgrCount > 0 {
		first := s.acmeMgrs[0]
		go first.AcmeShAvailable()
	}
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
	r.HandleFunc("/api/admin/status", s.rateLimitMiddleware(s.handleAdminStatus, false, false)).Methods("GET")
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
	a.HandleFunc("/certs/{name}/push/{id}", s.handleForcePushCert).Methods("POST") // v1.6.0: 测试用强制推送
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
	// trusted proxy
	a.HandleFunc("/trusted-proxy", s.handleGetTrustedProxy).Methods("GET")
	a.HandleFunc("/trusted-proxy", s.handleSaveTrustedProxy).Methods("POST")
	// backup & restore
	a.HandleFunc("/backup", s.handleBackupDownload).Methods("GET")
	a.HandleFunc("/backup/restore", s.handleBackupRestore).Methods("POST")

	// static

	// /bin/ file server — explicit HandleFunc avoids PathPrefix("/") conflict
	r.HandleFunc("/bin/{filename:.*}", s.handleBinFile).Methods("GET", "HEAD")
	// /dl/ alternative download path — some proxies (NPM) block /bin/
	r.HandleFunc("/dl/{filename:.*}", s.handleBinFile).Methods("GET", "HEAD")

	// static SPA served by cmd/manager/main.go
	return r
}

// ── middleware ──
