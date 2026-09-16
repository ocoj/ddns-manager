// Package acme provides ACME certificate issuance with multi-CA, key algorithms, and DNS-01 support.
package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	mycrypto "github.com/ocoj/ddns-manager/internal/crypto"
	"golang.org/x/crypto/acme"
)

// KeyType represents a certificate key algorithm.
type KeyType string

const (
	EC256   KeyType = "EC256"
	EC384   KeyType = "EC384"
	RSA2048 KeyType = "RSA2048"
	RSA3072 KeyType = "RSA3072"
	RSA4096 KeyType = "RSA4096"
)

var KeyTypes = []KeyType{EC256, EC384, RSA2048, RSA3072, RSA4096}

var keyTypeAliases = map[string]KeyType{
	"ec256": EC256, "ec384": EC384, "rsa2048": RSA2048, "rsa3072": RSA3072, "rsa4096": RSA4096,
	"EC256": EC256, "EC384": EC384, "RSA2048": RSA2048, "RSA3072": RSA3072, "RSA4096": RSA4096,
}

func ParseKeyType(s string) KeyType {
	if kt, ok := keyTypeAliases[strings.ToLower(s)]; ok {
		return kt
	}
	if kt, ok := keyTypeAliases[s]; ok {
		return kt
	}
	return EC256
}

// CA represents an ACME certificate authority.
type CA struct {
	Name     string
	URL      string
	NeedsEAB bool
}

var (
	LetsEncrypt = CA{"Let's Encrypt", "https://acme-v02.api.letsencrypt.org/directory", false}
	ZeroSSL     = CA{"ZeroSSL", "https://acme.zerossl.com/v2/DV90", false}
	Buypass     = CA{"Buypass", "https://api.buypass.com/acme/directory", false}
	GoogleTrust = CA{"Google Trust Services", "https://dv.acme-v02.api.pkc.goog/directory", true}
)

var AllCAs = []CA{LetsEncrypt, ZeroSSL, Buypass, GoogleTrust}

type EAB struct{ KID, HMACKey string }

// AccountInfo holds ACME account metadata.
type AccountInfo struct {
	Email      string `json:"email"`
	CA         string `json:"ca"`
	KeyType    string `json:"key_type"`
	AccountURL string `json:"account_url"`
	Registered bool   `json:"registered"`
}

type Manager struct {
	mu          sync.Mutex
	challengeMu sync.RWMutex // separate lock for challenges map (HTTP-01 handler runs in separate goroutine)
	acmeClient  *acme.Client
	accountKey  crypto.Signer
	email       string
	ca          CA
	certsDir    string
	httpPort    string
	challenges  map[string]string
	renewBefore time.Duration
	reg         *acme.Account
	acmeShPath  string
	// v1.6.71 N1: acme.sh home 由代码显式固定（I26/I27/I28），不再依赖父环境 HOME。
	// 解析失败时 acmeHomeErr != nil —— 所有 acme.sh 调用一律拒绝执行（fail-fast）。
	acmeHome        string
	acmeHomeTrace   []string
	acmeHomeCaveats []string // B-2：非判定性提示（仅告警，不参与判定）
	acmeHomeErr     error
	keyType         KeyType
	eab             *EAB
	logBuf          strings.Builder // collects operation output for debug
	lastRenewErr    error

	// v1.6.70: DNS 凭据解析器（由 server 注入；解析期间不持 m.mu，见 I6）
	keyLookup DNSKeyLookup
	// v1.6.73 B-1 Slice 3b: PFX 口令解析器（由 server 注入）。Slice 3a 起落盘明文
	// 口令恒为空，口令唯一来源是 meta.json 的密文 `pfx_password_enc` ⇒ acme 层
	// 不得直读 meta 键，必须经此解析器（解析期间不持 m.mu，见 I6）。
	pfxPasswordLookup PFXPasswordResolver
	// v1.6.70: 同一证书的续期串行化（I13）；renewMu 仅保护 renewing 映射本身
	renewMu  sync.Mutex
	renewing map[string]*sync.Mutex
	// v1.6.70 B2: logBuf 的独立锁 —— AppendLog 在签发路径与续期路径都会被调用，
	// 而 GetLog 可能同时被 UI 读取；原实现 AppendLog 无锁、GetLog 持 m.mu，
	// 二者并不互斥（strings.Builder 并发写会损坏）。
	logMu sync.Mutex
}

// DNSKeyLookup returns a snapshot of the configured DNS keys, keyed by key name.
type DNSKeyLookup func() map[string]*DNSProvider

// PFXPasswordResolver resolves the PFX password that a bundle's PFX containers
// must be regenerated with, given that bundle's meta.json content.
//
// v1.6.73 B-1 Slice 3b: after Slice 3a the on-disk plaintext password is always
// empty, so the value can only be obtained by decrypting meta's `pfx_password_enc`.
// The decryption lives in internal/store (purpose-scoped derived key), so the
// resolver is injected by the server rather than implemented here. An error must
// NOT be treated as "use the default" — that would re-encrypt the containers with
// the wrong password and destroy the user's custom one.
type PFXPasswordResolver func(meta map[string]interface{}) (string, error)

// RenewKind classifies the outcome of a single certificate renewal.
type RenewKind int

const (
	// KindOK: acme.sh reported success AND the certificate content changed.
	KindOK RenewKind = iota
	// KindNotReplaced: acme.sh exited 0 but fullchain.pem did not change.
	KindNotReplaced
	// KindSkipped: not due for renewal, or another goroutine just renewed it.
	KindSkipped
	// KindFailed: acme.sh failed, or the certificate could not be prepared.
	KindFailed
)

// RenewOutcome is reported per certificate so that concurrent renewals cannot
// overwrite each other's result (previously a single shared lastRenewErr).
type RenewOutcome struct {
	Name    string
	Domains []string
	Kind    RenewKind
	Err     error
}

// SetDNSKeyLookup installs the DNS key resolver. It must be called for every
// Manager registered with the server, otherwise renewals silently fall back to
// acme.sh's global account.conf credentials (the sp incident root cause).
func (m *Manager) SetDNSKeyLookup(fn DNSKeyLookup) {
	m.mu.Lock()
	m.keyLookup = fn
	m.mu.Unlock()
}

// KeyLookupConfigured reports whether a resolver has been installed.
func (m *Manager) KeyLookupConfigured() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keyLookup != nil
}

// loadDNSKeys resolves a snapshot outside of m.mu (I6: never call the store
// while holding m.mu).
func (m *Manager) loadDNSKeys() map[string]*DNSProvider {
	m.mu.Lock()
	fn := m.keyLookup
	m.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn()
}

// SetPFXPasswordResolver installs the PFX password resolver (B-1 Slice 3b). It is
// called for every Manager through the same mount point as the DNS key resolver
// (Server.attachDNSKeyLookup), so the mount-point count is unchanged.
func (m *Manager) SetPFXPasswordResolver(fn PFXPasswordResolver) {
	m.mu.Lock()
	m.pfxPasswordLookup = fn
	m.mu.Unlock()
}

// PFXPasswordResolverConfigured reports whether a PFX password resolver has been
// installed. Used by tests to assert the wiring (injection ⑧: without the wiring
// the acme read point must fall back to the default and fail its assertion).
func (m *Manager) PFXPasswordResolverConfigured() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pfxPasswordLookup != nil
}

// resolvePFXPassword returns the password the PFX containers must be regenerated
// with, for the given bundle meta. Precedence (B-1 Slice 3b):
//
//	resolver(meta)  →  明文 pfx_password（v1 兼容读）  →  mycrypto.DefaultPFXPassword
//
// The resolver is invoked with m.mu released (I6): it reaches the store, and the
// store must never be entered while m.mu is held. A resolver error is returned to
// the caller, never converted into the default password — the default may not be
// the user's custom password, and using it would overwrite the stored one.
func (m *Manager) resolvePFXPassword(meta map[string]interface{}) (string, error) {
	m.mu.Lock()
	fn := m.pfxPasswordLookup
	m.mu.Unlock()
	if fn != nil {
		return fn(meta)
	}
	if pw, ok := meta["pfx_password"].(string); ok && pw != "" {
		return pw, nil // v1 兼容读（解析器未接线时的退路）
	}
	return mycrypto.DefaultPFXPassword, nil
}

// lockCert serialises renewals of a single certificate directory (I13).
// It must never be acquired while m.mu is held.
func (m *Manager) lockCert(certDir string) func() {
	m.renewMu.Lock()
	if m.renewing == nil {
		m.renewing = map[string]*sync.Mutex{}
	}
	mu, ok := m.renewing[certDir]
	if !ok {
		mu = &sync.Mutex{}
		m.renewing[certDir] = mu
	}
	m.renewMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

// acmeShEnvFor returns the environment for an acme.sh invocation (S14: never nil).
//
// v1.6.71 N1: 环境**始终显式构造**。原实现（dp==nil 时返回 nil，令子进程逐字节继承
// 父环境）隐含假设"父环境会提供 HOME"，而 systemd 默认不设置 HOME ⇒ acme.sh 的 home
// 落到 /.acme.sh（既读不到既有 conf，又会在非预期目录写入明文凭据）。见 I26/I27/I28。
//
// home 未能显式确定时返回错误：调用方必须拒绝执行 acme.sh（fail-fast），
// 而不是让它在一个会被创建、且会落明文凭据的路径上初始化 home。
func (m *Manager) acmeShEnvFor(dp *DNSProvider) ([]string, error) {
	m.mu.Lock()
	home, homeErr, path := m.acmeHome, m.acmeHomeErr, m.acmeShPath
	m.mu.Unlock()
	if path == "" {
		return nil, fmt.Errorf("acme.sh 不可用（未找到可执行文件）")
	}
	if homeErr != nil {
		return nil, homeErr
	}
	if home == "" {
		return nil, fmt.Errorf("无法确定 acme.sh home，已拒绝执行 acme.sh")
	}
	return acmeShEnv(dp, home), nil
}

// resolveDNSKey picks the DNS key to use for a certificate, given its meta.json
// fields and the current key snapshot.
//
// Rules (I4/I5): the selected key's provider must match meta.provider; a
// recorded dns_key must exist and be complete; if it is missing (renamed or
// deleted) a unique same-provider candidate is used as a fallback; zero
// candidates means fall back to account.conf (nil); two or more candidates are
// ambiguous and are refused rather than guessed.
//
// The returned reason is non-empty either as an advisory (success with a
// recommendation) or as the cause of refusal (nil provider).
func resolveDNSKey(meta map[string]interface{}, keys map[string]*DNSProvider) (*DNSProvider, string) {
	if len(keys) == 0 {
		return nil, "未配置 DNS Key 来源"
	}
	provider, _ := meta["provider"].(string)
	if provider == "" {
		return nil, "meta 缺少 provider"
	}
	needSecret := false
	if spec, ok := dnsAPILookup(provider); ok {
		needSecret = spec.secret != ""
	} else {
		return nil, "provider 不支持 acme.sh DNS API: " + provider
	}
	complete := func(dp *DNSProvider) bool {
		if dp == nil || dp.KeyID == "" {
			return false
		}
		return !needSecret || dp.KeySecret != ""
	}

	if name, _ := meta["dns_key"].(string); name != "" {
		if dp, ok := keys[name]; ok {
			if !strings.EqualFold(dp.Name, provider) {
				return nil, fmt.Sprintf("dns_key %q 的 provider(%s) 与 meta.provider(%s) 不一致，拒绝注入", name, dp.Name, provider)
			}
			if !complete(dp) {
				return nil, fmt.Sprintf("dns_key %q 凭据不完整，拒绝注入", name)
			}
			return dp, ""
		}
		// fall through: key was renamed or deleted
	}

	var matches []*DNSProvider
	for _, dp := range keys {
		if !strings.EqualFold(dp.Name, provider) || !complete(dp) {
			continue
		}
		matches = append(matches, dp)
	}
	switch len(matches) {
	case 1:
		return matches[0], fmt.Sprintf("dns_key 未登记或已改名，按 provider=%s 唯一匹配到 %q（建议重新签发以登记）", provider, matches[0].KeyName)
	case 0:
		return nil, "无同厂商可用凭据，回退 account.conf"
	default:
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m.KeyName)
		}
		sort.Strings(names)
		return nil, fmt.Sprintf("同厂商存在 %d 个候选 [%s]，无法确定，拒绝注入", len(matches), strings.Join(names, ","))
	}
}

func New(certsDir, email, httpPort string) (*Manager, error) {
	return NewWithKey(certsDir, email, httpPort, nil)
}

// NewWithKey creates a Manager with an optional existing account key (PEM-encoded).
// If keyPEM is empty, a new ECDSA P-256 key is generated.
func NewWithKey(certsDir, email, httpPort string, keyPEM []byte) (*Manager, error) {
	if httpPort == "" {
		httpPort = ":80"
	}
	m := &Manager{
		certsDir: certsDir, email: email, httpPort: httpPort,
		challenges: make(map[string]string), renewBefore: 30 * 24 * time.Hour,
		ca: LetsEncrypt, keyType: EC256,
	}
	var signer crypto.Signer
	var err error
	if len(keyPEM) > 0 {
		signer, err = loadKeyFromPEM(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("load account key: %w", err)
		}
	} else {
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("gen key: %w", err)
		}
	}
	m.accountKey = signer
	m.acmeClient = &acme.Client{Key: signer, DirectoryURL: m.ca.URL}
	if p, err := exec.LookPath("acme.sh"); err == nil {
		m.acmeShPath = p
	}
	return m, nil
}

// AccountKeyPEM returns the account's private key as PEM.
func (m *Manager) AccountKeyPEM() ([]byte, error) {
	switch k := m.accountKey.(type) {
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil
	case *rsa.PrivateKey:
		b := x509.MarshalPKCS1PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}), nil
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

func loadKeyFromPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unknown key type: %s", block.Type)
	}
}

func (m *Manager) SetCA(ca CA)           { m.ca = ca; m.acmeClient.DirectoryURL = ca.URL; m.reg = nil }
func (m *Manager) SetKeyType(kt KeyType) { m.keyType = kt }
func (m *Manager) SetEAB(eab *EAB)       { m.eab = eab }

// AppendLog writes to the operation log buffer (for UI debug display).
// Guarded by logMu: both the issuance path and the renewal path append to it,
// possibly while the UI reads it via GetLog (v1.6.70 B2).
func (m *Manager) AppendLog(s string) {
	m.logMu.Lock()
	m.logBuf.WriteString(s)
	m.logMu.Unlock()
}

// GetLog returns the accumulated operation log.

func (m *Manager) RegisterAccount(ctx context.Context) error {
	account := &acme.Account{Contact: []string{"mailto:" + m.email}}
	// Attach EAB for providers that require it (e.g. Google Trust Services)
	if m.ca.NeedsEAB && m.eab != nil {
		account.ExternalAccountBinding = &acme.ExternalAccountBinding{
			KID: m.eab.KID,
			Key: []byte(m.eab.HMACKey),
		}
	}
	var err error
	m.reg, err = m.acmeClient.Register(ctx, account, acme.AcceptTOS)
	if err == acme.ErrAccountAlreadyExists {
		m.reg, err = m.acmeClient.GetReg(ctx, "")
	}
	return err
}

// GetLog returns the accumulated operation log (thread-safe).
// Uses logMu (the same lock as AppendLog) instead of m.mu, so readers and
// writers of logBuf are actually mutually excluded (v1.6.70 B2).
func (m *Manager) GetLog() string {
	m.logMu.Lock()
	s := m.logBuf.String()
	m.logMu.Unlock()
	return s
}

// LastError returns the last error encountered during renewal (if any).
func (m *Manager) LastError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastRenewErr
}

// AcmeShAvailable returns true if acme.sh is configured and the binary is executable.
// It performs an actual execution test (--version), more reliable than LookPath alone
// which can succeed on dangling symlinks.
// F5: startup health check for acme.sh availability.
// SetAcmeShPath pins the acme.sh executable path (I29).
//
// v1.6.71 N1: 该值优先于 exec.LookPath。由 server 层从 cfg.Cert.Provider 解析
// （绝对路径 + 存在 + 可执行）后注入，从而
//
//	① 消除对 PATH 的运行时依赖；
//	② 使"acme.sh 路径 + home"对所有 Manager 构造点保持一致（I29），
//	   避免"签发写 home A、续期读 home B"。
func (m *Manager) SetAcmeShPath(p string) {
	if v := strings.TrimSpace(p); v != "" {
		m.mu.Lock()
		m.acmeShPath = v
		m.mu.Unlock()
	}
}

// ResolveAcmeHome 按候选判定表显式固定 ACME home（I26）。
//
// hasCerts 表示本地是否已管理 ACME 证书，用于"语义分层"：本地已有证书时，
// 未初始化的路径不被采用（宁可 fail-fast，也不要静默另起一个 home）。
// 解析失败会记录 acmeHomeErr：此后所有 acme.sh 调用都拒绝执行。
func (m *Manager) ResolveAcmeHome(hasCerts bool) error {
	m.mu.Lock()
	path := m.acmeShPath
	m.mu.Unlock()

	res := ResolveAcmeHome(DefaultHomeProbe(hasCerts), path, os.Getenv("LE_WORKING_DIR"), os.Getenv("HOME"))

	m.mu.Lock()
	m.acmeHomeTrace = append([]string(nil), res.Trace...)
	m.acmeHomeCaveats = append([]string(nil), res.Caveats...)
	if res.OK() {
		m.acmeHome, m.acmeHomeErr = res.Home, nil
	} else {
		m.acmeHome, m.acmeHomeErr = "", res.Err()
	}
	home, err := m.acmeHome, m.acmeHomeErr
	m.mu.Unlock()

	for _, t := range res.Trace {
		log.Printf("[acme] home 解析: %s", t)
	}
	if err != nil {
		log.Printf("[acme] ACME home 解析失败 —— 已拒绝执行 acme.sh: %v", err)
		return err
	}
	log.Printf("[acme] ACME home 已固定: %s", home)
	return nil
}

// AcmeShPath 返回当前生效的 acme.sh 可执行路径（空表示未接线）。
func (m *Manager) AcmeShPath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.acmeShPath
}

// AcmeHome 返回已固定的 home（空表示尚未解析或解析失败）。
func (m *Manager) AcmeHome() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.acmeHome
}

// AcmeHomeTrace 返回候选解析轨迹（供启动自检与审计输出）。
func (m *Manager) AcmeHomeTrace() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.acmeHomeTrace...)
}

// AcmeHomeCaveats 返回 home 解析过程中的**非判定性**提示（仅告警；不参与 adopt/skip 判定）。
// v1.6.73 B-2：供 Server 侧写入独立审计通道（warning 级），与「解析失败」通道物理隔离。
func (m *Manager) AcmeHomeCaveats() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.acmeHomeCaveats...)
}

// AcmeHomeConfigured 表示 acme.sh home 是否已成功固定（I26）。
func (m *Manager) AcmeHomeConfigured() bool { return m.AcmeHome() != "" }

func (m *Manager) AcmeShAvailable() bool {
	if m.acmeShPath == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// v1.6.71 N1: 探针使用与真实调用相同的环境 —— home 解析异常在此即暴露。
	env, envErr := m.acmeShEnvFor(nil)
	if envErr != nil {
		log.Printf("[acme] acme.sh 环境不可用 (%s): %v — 自动续期将失效", m.acmeShPath, envErr)
		return false
	}
	cmd := exec.CommandContext(ctx, m.acmeShPath, "--version")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[acme] acme.sh 不可用 (%s): %v — 自动续期将失效", m.acmeShPath, err)
		return false
	}
	log.Printf("[acme] acme.sh 就绪: %s", strings.TrimSpace(string(out)))
	return true
}

// AccountInfo returns the ACME account metadata.
func (m *Manager) AccountInfo() AccountInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	info := AccountInfo{
		Email:   m.email,
		CA:      m.ca.Name,
		KeyType: string(m.keyType),
	}
	if m.reg != nil {
		info.Registered = true
		info.AccountURL = m.reg.URI
	}
	return info
}

// generateKey creates a key pair based on the selected algorithm.
func (m *Manager) generateKey() (crypto.Signer, error) {
	switch m.keyType {
	case EC256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case EC384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
}

func (m *Manager) IssueHTTP01(ctx context.Context, domains []string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reg == nil {
		if err := m.RegisterAccount(ctx); err != nil {
			return "", fmt.Errorf("register: %w", err)
		}
	}
	listener, err := net.Listen("tcp", m.httpPort)
	if err != nil {
		return "", fmt.Errorf("listen %s: %w (need root for port 80)", m.httpPort, err)
	}
	defer listener.Close()
	srv := &http.Server{Handler: http.HandlerFunc(m.handleChallenge)}
	go func() { srv.Serve(listener) }()
	defer srv.Close()
	return m.issueCert(ctx, domains, "http-01")
}

func (m *Manager) IssueDNS01(ctx context.Context, domains []string, dp DNSProvider) (string, error) {
	// v1.6.72 P0-F1（生产 H2 复现）：此处**不得**在持 m.mu 的情况下进入 issueViaAcmeSh ——
	// 后者经 acmeShEnvFor 再次获取 m.mu，而 sync.Mutex 不可重入 ⇒ 自死锁：请求永久挂起、
	// acme.sh 从未启动、每次请求泄漏一个 goroutine（修复前为 Lock + defer Unlock 覆盖全函数体）。
	// 现在锁内只做"注册 + 状态快照"，执行段完全无锁。回归守卫：TestT50 / TestT51。
	m.mu.Lock()
	if m.reg == nil {
		if err := m.RegisterAccount(ctx); err != nil {
			m.mu.Unlock()
			return "", fmt.Errorf("register: %w", err)
		}
	}
	acmeShPath, ca, keyType := m.acmeShPath, m.ca, m.keyType
	m.mu.Unlock()

	if acmeShPath != "" {
		// v1.6.70 B6: 与续期路径统一使用 dnsAPILookup（大小写不敏感）——
		// 否则会出现"续期能解析凭据、签发却报不支持"的口径分裂。
		if _, ok := dnsAPILookup(dp.Name); ok {
			return m.issueViaAcmeSh(ctx, domains, dp, acmeShPath, ca, keyType)
		}
		log.Printf("[acme] provider %q not supported by acme.sh DNS API", dp.Name)
	}
	return "", fmt.Errorf("DNS-01 challenge requires acme.sh with a supported DNS provider (alidns/cloudflare/txcloud/huawei/duckdns/godaddy); provider %q not supported", dp.Name)
}

// v1.6.72 P0-F1: 本函数**不得**在持 m.mu 时被调用（它会经 acmeShEnvFor 再次取 m.mu）。
// 所需可变状态由调用方在锁内快照后作为参数传入（acmeShPath / ca / keyType）。
func (m *Manager) issueViaAcmeSh(ctx context.Context, domains []string, dp DNSProvider, acmeShPath string, ca CA, keyType KeyType) (string, error) {
	firstDomain := domains[0]
	certDir := filepath.Join(m.certsDir, firstDomain)
	os.MkdirAll(certDir, 0o700)

	// CA server flag
	caFlag := " --server " + ca.URL

	// Key length flag for acme.sh
	keyLength := "ec-256"
	switch keyType {
	case EC384:
		keyLength = "ec-384"
	case RSA2048:
		keyLength = "2048"
	case RSA3072:
		keyLength = "3072"
	case RSA4096:
		keyLength = "4096"
	}

	// DNS API mapping（v1.6.70 B6: 统一经 dnsAPILookup，与解析/注入口径一致）
	mapping, ok := dnsAPILookup(dp.Name)
	if !ok {
		return "", fmt.Errorf("DNS provider %s not supported via acme.sh", dp.Name)
	}

	args := []string{"--issue", "--dns", mapping.api, "--dnssleep", "30", "--keylength", keyLength}
	for _, d := range domains {
		args = append(args, "-d", d)
	}
	args = append(args,
		"--cert-file", filepath.Join(certDir, "cert.pem"),
		"--key-file", filepath.Join(certDir, "privkey.pem"),
		"--fullchain-file", filepath.Join(certDir, "fullchain.pem"),
	)
	if caFlag != "" {
		args = append(args, strings.Fields(caFlag)...)
	}

	// Write DNS credentials to a temp file (0600) instead of env vars
	// to avoid leaking secrets via /proc/<pid>/environ.
	// NOTE: file persists on kill -9 (defer won't run); mitigated by /tmp tmpfs (cleared on reboot).
	envFile, err := os.CreateTemp("", "acme-dns-creds-*.sh")
	if err != nil {
		return "", fmt.Errorf("create temp: %w", err)
	}
	envPath := envFile.Name()
	envFile.Close()
	os.Remove(envPath)

	// v1.6.56: 凭证注入改用 cmd.Env，消除 shell 注入风险
	// v1.6.70 S3: 与续期共用 acmeShEnvFor —— dp 无匹配映射时返回 nil，
	// 此时不设 cmd.Env，子进程逐字节继承父环境（I1）。
	// v1.6.70 S3 + v1.6.71 N1(S14): 始终显式构造环境（固定 home + 按需注入凭据）；
	// home 不可判定即拒绝执行 acme.sh（fail-fast, I26/I28）。
	env, envErr := m.acmeShEnvFor(&dp)
	if envErr != nil {
		return "", fmt.Errorf("acme.sh 环境不可用: %w", envErr)
	}
	cmd := exec.CommandContext(ctx, acmeShPath, args...)
	cmd.Dir = certDir
	cmd.Env = env

	log.Printf("[acme] %s %s", acmeShPath, strings.Join(args, " "))
	out, err := cmd.CombinedOutput()
	log.Printf("[acme] 输出:\n%s", string(out))
	m.AppendLog(fmt.Sprintf("acme.sh %s\n%s\n", strings.Join(args, " "), string(out)))
	if err != nil {
		return "", fmt.Errorf("acme.sh: %w\n%s", err, string(out))
	}

	// v1.6.70 S6: 改用 json.MarshalIndent，避免 Key 名/域名含引号或反斜杠时
	// 生成非法 JSON；同时把 DNS Key 名登记到 meta.dns_key，供续期精确取用。
	metaMap := map[string]interface{}{
		"domains":  domains,
		"issued":   time.Now().Format(time.RFC3339),
		"acme":     true,
		"ca":       ca.Name,
		"provider": dp.Name,
		"key_type": string(keyType),
		"email":    m.email,
	}
	if dp.KeyName != "" {
		metaMap["dns_key"] = dp.KeyName
	}
	if metaData, mErr := json.MarshalIndent(metaMap, "", "  "); mErr != nil {
		log.Printf("[acme] 序列化 meta.json 失败: %v", mErr)
	} else if err := os.WriteFile(filepath.Join(certDir, "meta.json"), metaData, 0o600); err != nil {
		log.Printf("[acme] 写入 meta.json 失败: %v (证书已签发但元数据丢失)", err)
	}
	log.Printf("[acme] 证书已签发: %s (CA=%s 密钥=%s)", strings.Join(domains, ","), ca.Name, keyType)
	return firstDomain, nil
}

func (m *Manager) issueCert(ctx context.Context, domains []string, ct string) (string, error) {
	var orderAuthz []acme.AuthzID
	for _, d := range domains {
		orderAuthz = append(orderAuthz, acme.AuthzID{Type: "dns", Value: d})
	}
	log.Printf("[acme] 正在申请证书: %s (方式=%s CA=%s)", strings.Join(domains, ","), ct, m.ca.Name)
	m.AppendLog(fmt.Sprintf("Ordering certificate for: %s\nCA: %s\nChallenge: %s\n", strings.Join(domains, ","), m.ca.Name, ct))
	order, err := m.acmeClient.AuthorizeOrder(ctx, orderAuthz)
	if err != nil {
		return "", fmt.Errorf("authorize: %w", err)
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := m.acmeClient.GetAuthorization(ctx, authzURL)
		if err != nil {
			return "", fmt.Errorf("authz: %w", err)
		}
		var challenge *acme.Challenge
		for i, c := range authz.Challenges {
			if ct == c.Type {
				challenge = authz.Challenges[i]
				break
			}
		}
		if challenge == nil {
			return "", fmt.Errorf("no %s challenge for %s", ct, authz.Identifier.Value)
		}
		if ct == "http-01" {
			keyAuth, _ := m.acmeClient.HTTP01ChallengeResponse(challenge.Token)
			m.challengeMu.Lock()
			m.challenges[challenge.Token] = keyAuth
			m.challengeMu.Unlock()
			m.AppendLog(fmt.Sprintf("Waiting for HTTP-01 validation: %s\n", authz.Identifier.Value))
		} else if ct == "dns-01" {
			return "", fmt.Errorf("dns-01 not supported in pure-Go path; use acme.sh with a supported DNS provider")
		}
		if _, err := m.acmeClient.Accept(ctx, challenge); err != nil {
			return "", fmt.Errorf("accept: %w", err)
		}
		if _, err := m.acmeClient.WaitAuthorization(ctx, authz.URI); err != nil {
			if ct == "http-01" {
				m.challengeMu.Lock()
				delete(m.challenges, challenge.Token)
				m.challengeMu.Unlock()
			}
			m.AppendLog(fmt.Sprintf("Validation failed: %v\n", err))
			return "", fmt.Errorf("wait: %w", err)
		}
		if ct == "http-01" {
			m.challengeMu.Lock()
			delete(m.challenges, challenge.Token) // v1.6.56 M6: 验证完成立即清理，防内存泄漏
			m.challengeMu.Unlock()
		}
		m.AppendLog(fmt.Sprintf("Validation OK: %s\n", authz.Identifier.Value))
	}
	certKey, err := m.generateKey()
	if err != nil {
		return "", fmt.Errorf("gen key: %w", err)
	}
	m.AppendLog(fmt.Sprintf("Generating %s key...\n", m.keyType))
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, certKey)
	if err != nil {
		return "", fmt.Errorf("csr: %w", err)
	}
	derChain, _, err := m.acmeClient.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return "", fmt.Errorf("cert: %w", err)
	}
	m.AppendLog(fmt.Sprintf("Certificate issued successfully\n"))
	firstDomain := domains[0]
	certDir := filepath.Join(m.certsDir, firstDomain)
	os.MkdirAll(certDir, 0o700)
	// v1.5.20 M5: 检查文件创建错误
	fullchain, err := os.Create(filepath.Join(certDir, "fullchain.pem"))
	if err != nil {
		return "", fmt.Errorf("create fullchain.pem: %w", err)
	}
	for _, der := range derChain {
		pem.Encode(fullchain, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	fullchain.Close()
	keyFile, err := os.Create(filepath.Join(certDir, "privkey.pem"))
	if err != nil {
		return "", fmt.Errorf("create privkey.pem: %w", err)
	}
	switch k := certKey.(type) {
	case *ecdsa.PrivateKey:
		b, _ := x509.MarshalECPrivateKey(k)
		pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	case *rsa.PrivateKey:
		b := x509.MarshalPKCS1PrivateKey(k)
		pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b})
	}
	keyFile.Close()
	meta := fmt.Sprintf(`{"domains":["%s"],"issued":"%s","acme":true,"ca":"%s","key_type":"%s","email":"%s"}`,
		strings.Join(domains, `","`), time.Now().Format(time.RFC3339), m.ca.Name, m.keyType, m.email,
	)
	if err := os.WriteFile(filepath.Join(certDir, "meta.json"), []byte(meta), 0o600); err != nil {
		log.Printf("[acme] 写入 meta.json 失败: %v (证书已签发但元数据丢失)", err)
	}
	log.Printf("[acme] 证书已签发: %s (CA=%s 密钥=%s)", strings.Join(domains, ","), m.ca.Name, m.keyType)
	return firstDomain, nil
}

// isACMECert checks whether meta.json data marks this cert as ACME-issued.
// Uses json.Unmarshal instead of strings.Contains to be immune to JSON whitespace
// differences (e.g. "acme":true vs "acme": true from json.MarshalIndent).
func isACMECert(data []byte) bool {
	var m map[string]interface{}
	if json.Unmarshal(data, &m) != nil {
		return false
	}
	v, ok := m["acme"]
	return ok && v == true
}

// isAcmeShSkip reports whether acme.sh declined to renew because its own next
// renewal time has not been reached yet.
//
// Measured against acme.sh v3.1.4 (RT1): `--renew` prints
//
//	"Skipping. Next renewal time is: <ts>" / "Add '--force' to force renewal."
//
// and exits with a NON-ZERO status (2), leaving the certificate untouched.
// Treating that as a failure would emit a misleading error every ticker, which
// is precisely the "misleading failure feedback" family this change removes.
func isAcmeShSkip(output []byte) bool {
	return bytes.Contains(output, []byte("Skipping. Next renewal time is")) ||
		bytes.Contains(output, []byte("to force renewal"))
}

// certContentChanged reports whether fullchain.pem changed relative to before.
// Used by the RT1 skip classification (B8): acme.sh's skip wording must never
// swallow a run that actually replaced the certificate, and a real failure that
// happens to print that wording must stay a failure.
func certContentChanged(certDir string, before []byte) bool {
	after, err := os.ReadFile(filepath.Join(certDir, "fullchain.pem"))
	if err != nil {
		return true // unreadable → treat as "may have changed" rather than swallowing it
	}
	return sha256.Sum256(after) != sha256.Sum256(before)
}

func (m *Manager) setLastRenewErr(err error) {
	m.mu.Lock()
	m.lastRenewErr = err
	m.mu.Unlock()
}

// renewOne renews (or force-renews) a single certificate directory.
//
// Credentials: the DNS key is resolved from meta.json via the injected
// DNSKeyLookup and injected through cmd.Env (the fix for the sp incident).
// When no key resolves, cmd.Env is left untouched so acme.sh falls back to its
// global account.conf byte-for-byte as before.
//
// Concurrency: per-certificate serialisation plus a post-lock expiry re-check,
// so a concurrent renewal cannot cause a duplicate issuance (I13).
func (m *Manager) renewOne(ctx context.Context, certName string, force bool, keys map[string]*DNSProvider) RenewOutcome {
	m.mu.Lock()
	certsDir := m.certsDir
	email := m.email
	acmeShPath := m.acmeShPath
	renewBefore := m.renewBefore
	m.mu.Unlock()

	out := RenewOutcome{Name: certName}
	certDir := filepath.Join(certsDir, certName)

	// v1.6.70 B1: 手工/强制续期是单证书入口，先清空历史错误，
	// 避免上次的无关错误被当成本次结果展示给用户。
	if force {
		m.setLastRenewErr(nil)
	}

	if acmeShPath == "" {
		if force {
			out.Kind = KindFailed
			out.Err = fmt.Errorf("acme.sh not available")
			m.setLastRenewErr(out.Err)
		} else {
			out.Kind = KindSkipped
		}
		return out
	}

	readLeaf := func() (*x509.Certificate, []byte, error) {
		fcData, err := os.ReadFile(filepath.Join(certDir, "fullchain.pem"))
		if err != nil {
			return nil, nil, err
		}
		block, _ := pem.Decode(fcData)
		if block == nil {
			return nil, nil, fmt.Errorf("invalid fullchain.pem")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		return cert, fcData, nil
	}

	metaData, err := os.ReadFile(filepath.Join(certDir, "meta.json"))
	if err != nil {
		if force {
			out.Kind = KindFailed
			out.Err = fmt.Errorf("meta read: %w", err)
			m.setLastRenewErr(out.Err)
		} else {
			out.Kind = KindSkipped
		}
		return out
	}
	if !isACMECert(metaData) {
		if force {
			out.Kind = KindFailed
			out.Err = fmt.Errorf("not an ACME cert")
			m.setLastRenewErr(out.Err)
		} else {
			out.Kind = KindSkipped
		}
		return out
	}
	// Only auto-renew certs belonging to this ACME account. Legacy meta without
	// an "email" field is claimed by the first Manager that scans it.
	if !force && strings.Contains(string(metaData), `"email"`) &&
		!strings.Contains(string(metaData), `"`+email+`"`) {
		out.Kind = KindSkipped
		return out
	}
	var meta map[string]interface{}
	_ = json.Unmarshal(metaData, &meta)

	cert, before, err := readLeaf()
	if err != nil {
		out.Kind = KindFailed
		out.Err = err
		m.setLastRenewErr(err)
		return out
	}
	domains := cert.DNSNames
	if len(domains) == 0 {
		domains = []string{cert.Subject.CommonName}
	}
	out.Domains = domains

	if !force && time.Until(cert.NotAfter) > renewBefore {
		out.Kind = KindSkipped
		return out
	}

	unlock := m.lockCert(certDir)
	defer unlock()
	// Re-check after the lock: a concurrent renewal may have completed already.
	if cert2, cur, err2 := readLeaf(); err2 == nil {
		if !force && time.Until(cert2.NotAfter) > renewBefore {
			out.Kind = KindSkipped
			return out
		}
		before = cur
	}

	dp, reason := resolveDNSKey(meta, keys)
	if reason != "" {
		log.Printf("[acme] 凭据解析: %s → %s", certName, reason)
	} else if dp != nil {
		log.Printf("[acme] 凭据解析: %s → dns_key=%q provider=%s", certName, dp.KeyName, dp.Name)
	}

	args := []string{"--renew"}
	for _, d := range domains {
		args = append(args, "-d", d)
	}
	if force {
		args = append(args, "--force")
	}
	log.Printf("[acme] %s 续期: %s (到期日 %s)", map[bool]string{true: "强制", false: "正在"}[force],
		strings.Join(domains, ","), cert.NotAfter.Format("2006-01-02"))

	// v1.6.71 N1(S14): 同签发路径 —— 环境始终显式构造。
	// home 不可判定 ⇒ KindFailed（Q5：不新增枚举），原因经 B1 的 setLastRenewErr 可达 UI。
	env, envErr := m.acmeShEnvFor(dp)
	if envErr != nil {
		out.Kind = KindFailed
		out.Err = envErr
		m.setLastRenewErr(out.Err)
		return out
	}
	cmd := exec.CommandContext(ctx, acmeShPath, args...)
	cmd.Dir = certDir
	cmd.Env = env
	combined, err := cmd.CombinedOutput()
	if err != nil {
		// v1.6.70 RT1: acme.sh 未到其自身续期时间时返回非零退出码（v3.1.4 实测 = 2）
		// 且不改动证书。本管理端的 30 天阈值可能略早于 acme.sh 的自身计划/ARI
		// 建议，因此这里必须按 KindSkipped 处理，而不是记一条误导性的 error。
		//
		// v1.6.70 B8（验收加固）：仅凭输出串判定不够 —— 若某次真实失败的输出恰好
		// 命中该文案，会把失败吞成 skip。因此追加"证书内容确实未变"作为第二条件：
		// 内容变了 ⇒ 一定是真实执行过，按失败处理（宁可多一条 error，不可漏报）。
		if !force && isAcmeShSkip(combined) && !certContentChanged(certDir, before) {
			out.Kind = KindSkipped
			log.Printf("[acme] acme.sh 判定尚未到续期时间，跳过: %s", strings.Join(domains, ","))
			return out
		}
		out.Kind = KindFailed
		out.Err = fmt.Errorf("renew: %w\n%s", err, combined)
		m.setLastRenewErr(out.Err)
		log.Printf("[acme] 续期失败 %s: %v\n%s", strings.Join(domains, ","), err, combined)
		return out
	}
	log.Printf("[acme] 续期输出:\n%s", string(combined))
	m.AppendLog(fmt.Sprintf("acme.sh %s\n%s\n", strings.Join(args, " "), string(combined)))

	// S4: exit 0 alone is not success — the certificate content must change.
	after, err := os.ReadFile(filepath.Join(certDir, "fullchain.pem"))
	if err != nil {
		out.Kind = KindFailed
		out.Err = fmt.Errorf("read fullchain after renew: %w", err)
		m.setLastRenewErr(out.Err)
		return out
	}
	if sha256.Sum256(after) == sha256.Sum256(before) {
		out.Kind = KindNotReplaced
		out.Err = fmt.Errorf("acme.sh 返回成功但 fullchain.pem 未变化")
		// v1.6.70 B1: 必须记录，否则 handleRenewCert 读不到原因 → 回落到
		// 误导性的 404「证书未找到或未到续期时间」。
		m.setLastRenewErr(out.Err)
		log.Printf("[acme] 续期未替换证书内容 %s (acme.sh 退出码 0)", strings.Join(domains, ","))
		return out
	}

	if err := m.UpdateCertMeta(certDir); err != nil {
		out.Kind = KindFailed
		out.Err = fmt.Errorf("update meta: %w", err)
		m.setLastRenewErr(out.Err)
		log.Printf("[acme] 更新证书元数据失败 %s: %v", certName, err)
		return out
	}
	out.Kind = KindOK
	m.setLastRenewErr(nil)
	log.Printf("[acme] renewed: %s", strings.Join(domains, ","))
	return out
}

// RenewWithOutcomes renews every due certificate and returns one outcome per
// certificate. Results are returned per call, so concurrent renewals no longer
// overwrite a single shared error field.
func (m *Manager) RenewWithOutcomes(ctx context.Context) []RenewOutcome {
	m.mu.Lock()
	certsDir := m.certsDir
	m.mu.Unlock()

	entries, err := os.ReadDir(certsDir)
	if err != nil {
		return nil
	}
	keys := m.loadDNSKeys() // resolved once for the whole pass
	var outcomes []RenewOutcome
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		outcomes = append(outcomes, m.renewOne(ctx, e.Name(), false, keys))
	}
	return outcomes
}

// Renew renews all due certificates and returns the names whose content actually
// changed. Compatibility entry point.
func (m *Manager) Renew(ctx context.Context) (renewed []string) {
	outcomes := m.RenewWithOutcomes(ctx)
	var failed, notReplaced int
	for _, o := range outcomes {
		switch o.Kind {
		case KindOK:
			renewed = append(renewed, o.Name)
		case KindNotReplaced:
			notReplaced++
		case KindFailed:
			failed++
		}
	}
	if len(renewed) > 0 {
		log.Printf("[acme] 续签完成: 已续签 %d 个证书", len(renewed))
	}
	if failed > 0 || notReplaced > 0 {
		log.Printf("[acme] 续签汇总: 成功 %d, 未替换 %d, 失败 %d", len(renewed), notReplaced, failed)
	}
	return renewed
}

// RenewByName forces renewal of a specific certificate, ignoring the expiry
// threshold.
func (m *Manager) RenewByName(ctx context.Context, certName string) bool {
	out := m.renewOne(ctx, certName, true, m.loadDNSKeys())
	return out.Kind == KindOK
}

// InstallCert re-points acme.sh's install paths at the certificate bundle
// directory (invariant I9). Without this, issueViaAcmeSh's initial install paths
// (certs/<domain>/) are deleted right after issuance, so later renewals would
// never land in the bundle.
//
// It deliberately does NOT set cmd.Env (I11): no credentials are needed, and the
// child must inherit HOME to locate ~/.acme.sh.
func (m *Manager) InstallCert(ctx context.Context, primaryDomain, dir string) error {
	m.mu.Lock()
	acmeShPath := m.acmeShPath
	m.mu.Unlock()
	if acmeShPath == "" {
		return fmt.Errorf("install-cert: acme.sh not available")
	}
	if primaryDomain == "" {
		return fmt.Errorf("install-cert: empty primary domain")
	}
	if dir == "" {
		return fmt.Errorf("install-cert: empty target dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("install-cert: mkdir: %w", err)
	}
	// -d carries the primary domain ONLY. Measured against acme.sh v3.1.4 (RT2a/RT2b):
	// acme.sh resolves the certificate from the FIRST -d, therefore
	//   · first -d is not a cert name      → exit 1, nothing installed;
	//   · first -d is another *valid* cert → exit 0 while SILENTLY installing THAT
	//     certificate (no error at all).
	// So extra -d values are not merely redundant: they can install the wrong
	// certificate without any signal. This single-argument shape is the only one
	// that cannot mis-install; TestInstallCert_PassesBundlePaths asserts it.
	args := []string{
		"--install-cert", "-d", primaryDomain,
		"--cert-file", filepath.Join(dir, "cert.pem"),
		"--key-file", filepath.Join(dir, "privkey.pem"),
		"--fullchain-file", filepath.Join(dir, "fullchain.pem"),
	}
	// v1.6.71 N1(S15): 显式设置环境（不含凭据）—— 必须保证 acme.sh 能定位 home，
	// 否则 --install-cert 会把证书写到非预期目录；home 不可判定即拒绝执行。
	env, envErr := m.acmeShEnvFor(nil)
	if envErr != nil {
		return fmt.Errorf("install-cert: %w", envErr)
	}
	cmd := exec.CommandContext(ctx, acmeShPath, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install-cert: %w\n%s", err, out)
	}
	log.Printf("[acme] --install-cert 完成: %s → %s", primaryDomain, dir)
	return nil
}

func (m *Manager) handleChallenge(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	m.challengeMu.RLock()
	keyAuth, ok := m.challenges[token]
	m.challengeMu.RUnlock()
	if ok {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(keyAuth))
		return
	}
	http.NotFound(w, r)
}

// UpdateCertMeta re-reads all cert files from the directory, recomputes the
// deterministic SHA256 hash, updates meta.json, and regenerates cert.pfx.
// Must be called after acme.sh --renew to ensure the bundle hash reflects
// the renewed certificate contents, so the next heartbeat can detect the
// change and push the updated cert to agents.
func (m *Manager) UpdateCertMeta(certDir string) error {
	entries, err := os.ReadDir(certDir)
	if err != nil {
		return fmt.Errorf("readdir: %w", err)
	}

	// Read existing meta.json to preserve non-hash fields (acme, email, ca, etc.)
	metaPath := filepath.Join(certDir, "meta.json")
	var metaMap map[string]interface{}
	if data, err := os.ReadFile(metaPath); err == nil {
		json.Unmarshal(data, &metaMap)
	}
	if metaMap == nil {
		metaMap = make(map[string]interface{})
	}

	// Collect files — sorted for deterministic hashing
	var fileNames []string
	fileContents := make(map[string][]byte)
	var keyPEM []byte
	for _, e := range entries {
		if e.IsDir() || e.Name() == "meta.json" {
			continue
		}
		content, err := os.ReadFile(filepath.Join(certDir, e.Name()))
		if err != nil {
			continue
		}
		fileNames = append(fileNames, e.Name())
		fileContents[e.Name()] = content
		// Detect the private key PEM for PFX regeneration (C2)
		if isKeyPEM(e.Name(), content) && keyPEM == nil {
			keyPEM = content
		}
	}

	// v1.6.70 I24: 证书源由唯一 helper 决定（确定性偏好 fullchain，带完整链），
	// 不再依赖目录/map 遍历顺序 —— 旧实现在此恒取 cert.pem（leaf-only），
	// 且 handleACMEIssue 遍历 map 导致链长随机（U4）。
	certPEM := mycrypto.PickCertPEM(fileContents)

	// C2: 先生成双 PFX 文件（Modern + Legacy），后续算 hash 时包含它们
	// v1.6.73 B-1 Slice 3b: 读取已存储的 PFX 口令（经**解析器**，见下方注释）——
	// 防止自动续签覆盖用户自定义口令。
	if certPEM != nil && keyPEM != nil {
		// v1.6.73 B-1 Slice 3b：口令必须经**解析器**取值（resolver ⇒ 明文兼容 ⇒
		// 默认），不再直读 meta 键。理由：Slice 3a 起落盘明文 `pfx_password` 恒为
		// 空，口令的唯一磁盘来源是 Manager bundle meta.json 的密文
		// `pfx_password_enc`，只有 store 的 purpose 派生密钥能解开。
		//  ① 本函数读到的 certDir/meta.json 由 acme 侧写入（domains/issued/acme/
		//     ca/…），**从不含口令键** ⇒ 这一步通常只得到默认值；
		//  ② 口令的权威来源是 Manager bundle 目录（`acme-<certName>`）的 meta.json；
		//  ③ 解析失败（密文损坏 / `.storage_key` 不符）⇒ **绝不用默认口令顶替**：
		//     那会用错误口令重建 PFX 并下发，正好破坏本块「防止自动续签覆盖用户
		//     自定义口令」的意图。此时跳过 PFX 重建、保留磁盘既有 PFX，并把失败
		//     写进 acme 操作日志（可见、不静默）。
		pfxPassword, pfxResolveErr := m.resolvePFXPassword(metaMap)
		if pfxResolveErr == nil && pfxPassword == mycrypto.DefaultPFXPassword {
			bundleDir := filepath.Join(filepath.Dir(certDir), "acme-"+filepath.Base(certDir))
			if bundleData, err := os.ReadFile(filepath.Join(bundleDir, "meta.json")); err == nil {
				var bundleMeta map[string]interface{}
				if json.Unmarshal(bundleData, &bundleMeta) == nil {
					if pw, err := m.resolvePFXPassword(bundleMeta); err != nil {
						pfxResolveErr = err
					} else {
						pfxPassword = pw
					}
				}
			}
		}
		if pfxResolveErr != nil {
			log.Printf("[acme] PFX 口令解析失败 %s — 跳过 PFX 重建（保留既有口令，不用默认值顶替）: %v",
				filepath.Base(certDir), pfxResolveErr)
			m.AppendLog(fmt.Sprintf("PFX 口令解析失败 %s: %v（已跳过 PFX 重建，保留既有 PFX）\n",
				filepath.Base(certDir), pfxResolveErr))
		} else {
			pfxData, pfxErr := mycrypto.GeneratePFX(certPEM, keyPEM, pfxPassword)
			if pfxErr != nil {
				log.Printf("[acme] PFX 重新生成失败 %s: %v", filepath.Base(certDir), pfxErr)
			} else {
				os.WriteFile(filepath.Join(certDir, "cert.pfx"), pfxData, 0o600)
				fileContents["cert.pfx"] = pfxData
				log.Printf("[acme] PFX(Legacy) 已重新生成: %s", filepath.Base(certDir))
			}
			if modernData, modernErr := mycrypto.GeneratePFXModern(certPEM, keyPEM, pfxPassword); modernErr == nil {
				os.WriteFile(filepath.Join(certDir, "cert-modern.pfx"), modernData, 0o600)
				fileContents["cert-modern.pfx"] = modernData
				log.Printf("[acme] PFX(Modern) 已重新生成: %s", filepath.Base(certDir))
			}
		}
	}

	// 重建文件名列表（可能新增了 PFX 文件）
	fileNames = nil
	for name := range fileContents {
		fileNames = append(fileNames, name)
	}
	sort.Strings(fileNames)

	// 计算包含 PFX 文件的确定性 hash
	h := sha256.New()
	for _, name := range fileNames {
		h.Write(fileContents[name])
	}
	hash := fmt.Sprintf("sha256:%x", h.Sum(nil))

	// Update meta.json: preserve all ACME metadata, only update hash + issued time
	metaMap["hash"] = hash
	metaMap["issued"] = time.Now().Format(time.RFC3339)

	metaData, err := json.MarshalIndent(metaMap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}
	if err := os.WriteFile(metaPath, metaData, 0o600); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}

	return nil
}

// isKeyPEM checks if a file is a private key file (by extension or content).
func isKeyPEM(name string, content []byte) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".key") || strings.Contains(string(content), "PRIVATE KEY")
}

// dnsAPIMapping maps provider name → acme.sh DNS API credentials env vars.
// dnsAPISpec describes how a provider's credentials map onto acme.sh env vars.
type dnsAPISpec struct{ env, secret, api, extraEnv string }

var dnsAPIMapping = map[string]dnsAPISpec{
	"alidns":       {"Ali_Key", "Ali_Secret", "dns_ali", ""},
	"cloudflare":   {"CF_Token", "", "dns_cf", ""},
	"txcloud":      {"Tencent_SecretId", "Tencent_SecretKey", "dns_tencent", ""},
	"tencentcloud": {"Tencent_SecretId", "Tencent_SecretKey", "dns_tencent", ""},
	"huawei":       {"HUAWEICLOUD_Username", "HUAWEICLOUD_Password", "dns_huaweicloud", "HUAWEICLOUD_DomainID"},
	"huaweicloud":  {"HUAWEICLOUD_Username", "HUAWEICLOUD_Password", "dns_huaweicloud", "HUAWEICLOUD_DomainID"},
	"duckdns":      {"DuckDNS_Token", "", "dns_duckdns", ""},
	"godaddy":      {"GD_Key", "GD_Secret", "dns_gd", ""},
	"dnspod":       {"Tencent_SecretId", "Tencent_SecretKey", "dns_tencent", ""},
	"porkbun":      {"Porkbun_API_Key", "Porkbun_Secret_API_Key", "dns_porkbun", ""},
	"namecheap":    {"NAMECHEAP_USERNAME", "NAMECHEAP_API_KEY", "dns_namecheap", ""},
	"namesilo":     {"Namesilo_Key", "", "dns_namesilo", ""},
	"dynv6":        {"dynv6_token", "", "dns_dynv6", ""},
}

// dnsAPILookup resolves a provider's acme.sh mapping, tolerating case
// differences. Both credential injection (acmeShEnvFor) and key resolution
// (resolveDNSKey) must use this single entry point: if they disagreed, a key
// could be accepted for renewal and then silently never be injected — the exact
// failure family this change exists to eliminate (v1.6.70 B6).
func dnsAPILookup(provider string) (dnsAPISpec, bool) {
	if spec, ok := dnsAPIMapping[provider]; ok {
		return spec, true
	}
	for name, spec := range dnsAPIMapping {
		if strings.EqualFold(name, provider) {
			return spec, true
		}
	}
	return dnsAPISpec{}, false
}

// DNSProvider holds credentials for DNS-01 challenge.
type DNSProvider struct {
	Name      string
	KeyID     string
	KeySecret string
	// KeyName is the entry name in dns_keys.json. It is persisted to
	// meta.json as "dns_key" so renewals can resolve the exact key instead of
	// guessing among same-provider candidates (S5).
	KeyName string
}
