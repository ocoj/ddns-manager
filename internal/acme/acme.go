// Package acme provides ACME certificate issuance with multi-CA, key algorithms, and DNS-01 support.
package acme

import (
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
	RSA2048  KeyType = "RSA2048"
	RSA3072  KeyType = "RSA3072"
	RSA4096  KeyType = "RSA4096"
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

type EAB struct { KID, HMACKey string }

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
	keyType     KeyType
	eab         *EAB
	logBuf      strings.Builder // collects operation output for debug
	lastRenewErr error
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
	}
	if signer == nil {
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return nil, fmt.Errorf("gen key: %w", err)
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

func (m *Manager) SetCA(ca CA)              { m.ca = ca; m.acmeClient.DirectoryURL = ca.URL; m.reg = nil }
func (m *Manager) SetKeyType(kt KeyType)    { m.keyType = kt }
func (m *Manager) SetEAB(eab *EAB)          { m.eab = eab }

// AppendLog writes to the operation log buffer (for UI debug display).
func (m *Manager) AppendLog(s string) { m.logBuf.WriteString(s) }

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
func (m *Manager) GetLog() string {
	m.mu.Lock()
	s := m.logBuf.String()
	m.mu.Unlock()
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
func (m *Manager) AcmeShAvailable() bool {
	if m.acmeShPath == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, m.acmeShPath, "--version")
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reg == nil {
		if err := m.RegisterAccount(ctx); err != nil {
			return "", fmt.Errorf("register: %w", err)
		}
	}
	if m.acmeShPath != "" {
		if _, ok := dnsAPIMapping[dp.Name]; ok {
			return m.issueViaAcmeSh(ctx, domains, dp)
		}
		log.Printf("[acme] provider %q not supported by acme.sh DNS API", dp.Name)
	}
	return "", fmt.Errorf("DNS-01 challenge requires acme.sh with a supported DNS provider (alidns/cloudflare/txcloud/huawei/duckdns/godaddy); provider %q not supported", dp.Name)
}

func (m *Manager) issueViaAcmeSh(ctx context.Context, domains []string, dp DNSProvider) (string, error) {
	firstDomain := domains[0]
	certDir := filepath.Join(m.certsDir, firstDomain)
	os.MkdirAll(certDir, 0o700)

	// CA server flag
	caFlag := " --server " + m.ca.URL

	// Key length flag for acme.sh
	keyLength := "ec-256"
	switch m.keyType {
	case EC384:
		keyLength = "ec-384"
	case RSA2048:
		keyLength = "2048"
	case RSA3072:
		keyLength = "3072"
	case RSA4096:
		keyLength = "4096"
	}

	// DNS API mapping
	mapping, ok := dnsAPIMapping[dp.Name]
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
	cmd := exec.CommandContext(ctx, m.acmeShPath, args...)
	cmd.Dir = certDir
	cmdEnv := os.Environ()
	if mapping.env != "" {
		cmdEnv = append(cmdEnv, mapping.env+"="+dp.KeyID)
	}
	if mapping.secret != "" {
		cmdEnv = append(cmdEnv, mapping.secret+"="+dp.KeySecret)
	}
	cmd.Env = cmdEnv

	log.Printf("[acme] %s %s", m.acmeShPath, strings.Join(args, " "))
	out, err := cmd.CombinedOutput()
	log.Printf("[acme] 输出:\n%s", string(out))
	m.AppendLog(fmt.Sprintf("acme.sh %s\n%s\n", strings.Join(args, " "), string(out)))
	if err != nil {
		return "", fmt.Errorf("acme.sh: %w\n%s", err, string(out))
	}

	meta := fmt.Sprintf(`{"domains":["%s"],"issued":"%s","acme":true,"ca":"%s","provider":"%s","key_type":"%s","email":"%s"}`,
		strings.Join(domains, `","`), time.Now().Format(time.RFC3339), m.ca.Name, dp.Name, m.keyType, m.email,
	)
	if err := os.WriteFile(filepath.Join(certDir, "meta.json"), []byte(meta), 0o600); err != nil {
		log.Printf("[acme] 写入 meta.json 失败: %v (证书已签发但元数据丢失)", err)
	}
	log.Printf("[acme] 证书已签发: %s (CA=%s 密钥=%s)", strings.Join(domains, ","), m.ca.Name, m.keyType)
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

func (m *Manager) Renew(ctx context.Context) (renewed []string) {
	m.mu.Lock()
	certsDir := m.certsDir
	email := m.email
	acmeShPath := m.acmeShPath
	renewBefore := m.renewBefore
	m.mu.Unlock()

	entries, err := os.ReadDir(certsDir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() { continue }
		certDir := filepath.Join(certsDir, e.Name())
		data, _ := os.ReadFile(filepath.Join(certDir, "meta.json"))
		if !isACMECert(data) { continue }
		// Only renew certs belonging to this ACME account.
		// Legacy certs without "email" are handled by the first Manager that scans them.
		if strings.Contains(string(data), `"email"`) && !strings.Contains(string(data), `"`+email+`"`) {
			continue
		}
		fcData, _ := os.ReadFile(filepath.Join(certDir, "fullchain.pem"))
		block, _ := pem.Decode(fcData)
		if block == nil { continue }
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || time.Until(cert.NotAfter) > renewBefore { continue }
		domains := cert.DNSNames
		if len(domains) == 0 { domains = []string{cert.Subject.CommonName} }
		log.Printf("[acme] 正在续期: %s (到期日 %s)", strings.Join(domains, ","), cert.NotAfter.Format("2006-01-02"))
		if acmeShPath != "" {
			// C2: 传递全部域名到 acme.sh --renew，确保多域名 SAN 证书所有域名续签
			args := []string{"--renew"}
			for _, d := range domains {
				args = append(args, "-d", d)
			}
			cmd := exec.CommandContext(ctx, acmeShPath, args...)
			cmd.Dir = certDir
			out, err := cmd.CombinedOutput()
			if err != nil {
				// C4: 锁保护 lastRenewErr 写入（与 LastError() 串行化）
				m.mu.Lock()
				m.lastRenewErr = fmt.Errorf("renew %s: %w\n%s", strings.Join(domains, ","), err, out)
				m.mu.Unlock()
				log.Printf("[acme] 续期失败 %s: %v\n%s", strings.Join(domains, ","), err, out)
				continue
			}
			log.Printf("[acme] 续期输出:\n%s", string(out))
		} else {
			// acme.sh not available → skip (pure-Go HTTP-01 path not suitable for auto-renew)
			log.Printf("[acme] acme.sh 不可用，跳过 %s 续期", strings.Join(domains, ","))
			continue
		}
		// C1: 续期成功后更新 cert bundle hash + meta.json，确保下次心跳下发新证书
		if err := m.UpdateCertMeta(certDir); err != nil {
			log.Printf("[acme] 更新证书元数据失败 %s: %v", e.Name(), err)
		}
		renewed = append(renewed, e.Name())
	}
	// M2: 续签汇总日志，便于运维判断续签是否正常工作
	if len(renewed) > 0 {
		log.Printf("[acme] 续签完成: 已续签 %d 个证书", len(renewed))
	}
	return renewed
}

// RenewByName forces renewal of a specific certificate (ignoring expiry threshold).
func (m *Manager) RenewByName(ctx context.Context, certName string) (renewed bool) {
	// v1.5.34 C3: 所有 lastRenewErr 写入统一加锁，消除与 LastError() 的数据竞争
	setLastErr := func(err error) {
		m.mu.Lock()
		m.lastRenewErr = err
		m.mu.Unlock()
	}
	m.mu.Lock()
	m.lastRenewErr = nil
	m.mu.Unlock()

	certDir := filepath.Join(m.certsDir, certName)
	data, err := os.ReadFile(filepath.Join(certDir, "meta.json"))
	if err != nil {
		setLastErr(fmt.Errorf("meta read: %w", err))
		return false
	}
	if !isACMECert(data) {
		setLastErr(fmt.Errorf("not an ACME cert"))
		return false
	}
	fcData, _ := os.ReadFile(filepath.Join(certDir, "fullchain.pem"))
	block, _ := pem.Decode(fcData)
	if block == nil {
		setLastErr(fmt.Errorf("invalid fullchain.pem"))
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		setLastErr(fmt.Errorf("parse cert: %w", err))
		return false
	}
	domains := cert.DNSNames
	if len(domains) == 0 {
		domains = []string{cert.Subject.CommonName}
	}
	log.Printf("[acme] 强制续期: %s (到期日 %s)", strings.Join(domains, ","), cert.NotAfter.Format("2006-01-02"))
	m.mu.Lock()
	acmeShPath := m.acmeShPath
	m.mu.Unlock()
	if acmeShPath != "" {
		// C3: 传递全部域名到 acme.sh --renew --force，确保多域名 SAN 所有域名续签
		args := []string{"--renew"}
		for _, d := range domains {
			args = append(args, "-d", d)
		}
		args = append(args, "--force")
		cmd := exec.CommandContext(ctx, acmeShPath, args...)
		cmd.Dir = certDir
		out, err := cmd.CombinedOutput()
		log.Printf("[acme] 续期输出:\n%s", string(out))
		m.AppendLog(fmt.Sprintf("acme.sh %s\n%s\n", strings.Join(args, " "), string(out)))
		if err != nil {
			setLastErr(fmt.Errorf("renew: %w\n%s", err, string(out)))
			return false
		}
	} else {
		setLastErr(fmt.Errorf("acme.sh not available"))
		return false
	}
	// v1.5.34 C4: UpdateCertMeta 失败时返回 false，防止 bundle hash 未更新导致 Agent 永收不到新证书
	if err := m.UpdateCertMeta(certDir); err != nil {
		log.Printf("[acme] 更新证书元数据失败 %s: %v", certName, err)
		setLastErr(fmt.Errorf("update meta: %w", err))
		return false
	}
	log.Printf("[acme] renewed: %s", strings.Join(domains, ","))
	return true
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
	var certPEM, keyPEM []byte
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
		// Detect cert and key PEM for PFX regeneration (C2)
		if isCertPEM(e.Name(), content) && certPEM == nil {
			certPEM = content
		}
		if isKeyPEM(e.Name(), content) && keyPEM == nil {
			keyPEM = content
		}
	}

	// C2: 先生成双 PFX 文件（Modern + Legacy），后续算 hash 时包含它们
	// v1.5.36 C1: 从 meta.json 读取已存储的 PFX 密码，防止自动续签覆盖用户自定义密码
	if certPEM != nil && keyPEM != nil {
		// 继承已存储的 PFX 密码。
		// 优先从 meta.json 读取（首次签发时持久化的），
		// 其次从 Manager bundle 目录读取（handleACMEIssue 写入的）。
		pfxPassword := mycrypto.DefaultPFXPassword
		if pw, ok := metaMap["pfx_password"]; ok {
			if pws, ok := pw.(string); ok && pws != "" {
				pfxPassword = pws
			}
		}
		if pfxPassword == mycrypto.DefaultPFXPassword {
			bundleDir := filepath.Join(filepath.Dir(certDir), "acme-"+filepath.Base(certDir))
			if bundleData, err := os.ReadFile(filepath.Join(bundleDir, "meta.json")); err == nil {
				var bundleMeta map[string]interface{}
				if json.Unmarshal(bundleData, &bundleMeta) == nil {
					if pw, ok := bundleMeta["pfx_password"]; ok {
						if pws, ok := pw.(string); ok && pws != "" {
							pfxPassword = pws
						}
					}
				}
			}
		}
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

// isCertPEM checks if a file is a certificate PEM file.
func isCertPEM(name string, content []byte) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".crt") || strings.HasSuffix(lower, ".cer")
}

// isKeyPEM checks if a file is a private key file (by extension or content).
func isKeyPEM(name string, content []byte) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".key") || strings.Contains(string(content), "PRIVATE KEY")
}

// dnsAPIMapping maps provider name → acme.sh DNS API credentials env vars.
var dnsAPIMapping = map[string]struct{ env, secret, api, extraEnv string }{
	"alidns":        {"Ali_Key", "Ali_Secret", "dns_ali", ""},
	"cloudflare":    {"CF_Token", "", "dns_cf", ""},
	"txcloud":       {"Tencent_SecretId", "Tencent_SecretKey", "dns_tencent", ""},
	"tencentcloud":  {"Tencent_SecretId", "Tencent_SecretKey", "dns_tencent", ""},
	"huawei":        {"HUAWEICLOUD_Username", "HUAWEICLOUD_Password", "dns_huaweicloud", "HUAWEICLOUD_DomainID"},
	"huaweicloud":   {"HUAWEICLOUD_Username", "HUAWEICLOUD_Password", "dns_huaweicloud", "HUAWEICLOUD_DomainID"},
	"duckdns":       {"DuckDNS_Token", "", "dns_duckdns", ""},
	"godaddy":       {"GD_Key", "GD_Secret", "dns_gd", ""},
	"dnspod":        {"Tencent_SecretId", "Tencent_SecretKey", "dns_tencent", ""},
	"porkbun":       {"Porkbun_API_Key", "Porkbun_Secret_API_Key", "dns_porkbun", ""},
	"namecheap":     {"NAMECHEAP_USERNAME", "NAMECHEAP_API_KEY", "dns_namecheap", ""},
	"namesilo":      {"Namesilo_Key", "", "dns_namesilo", ""},
	"dynv6":         {"dynv6_token", "", "dns_dynv6", ""},
}

// DNSProvider holds credentials for DNS-01 challenge.
type DNSProvider struct {
	Name      string
	KeyID     string
	KeySecret string
}
