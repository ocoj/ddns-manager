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

	mycrypto "github.com/kk/ddns-manager/internal/crypto"
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
func (m *Manager) LastError() error { return m.lastRenewErr }

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
	defer os.Remove(envPath)
	if mapping.env != "" {
		fmt.Fprintf(envFile, "export %s='%s'\n", mapping.env, strings.ReplaceAll(dp.KeyID, "'", "'\\''"))
	}
	if mapping.secret != "" {
		fmt.Fprintf(envFile, "export %s='%s'\n", mapping.secret, strings.ReplaceAll(dp.KeySecret, "'", "'\\''"))
	}
	// L1: 华为云等需要额外环境变量(如 HUAWEICLOUD_DomainID)
	if mapping.extraEnv != "" {
		// extraEnv 是环境变量名，值从 DNS Key 的 notes 字段中提取（如果用户配置了）
		// 对于华为云: HUAWEICLOUD_DomainID 需要在 DNS Key 备注中配置 domain_id=xxx
		fmt.Fprintf(envFile, "export %s='${%s:-}'\n", mapping.extraEnv, mapping.extraEnv)
	}
	envFile.Close()
	os.Chmod(envPath, 0o600)

	// Source the env file then run acme.sh
	cmd := exec.CommandContext(ctx, "sh", "-c",
		fmt.Sprintf(". '%s' && exec '%s' %s", envPath, m.acmeShPath, strings.Join(args, " ")))
	cmd.Dir = certDir
	cmd.Env = os.Environ()

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
	os.WriteFile(filepath.Join(certDir, "meta.json"), []byte(meta), 0o600)
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
			m.AppendLog(fmt.Sprintf("Validation failed: %v\n", err))
			return "", fmt.Errorf("wait: %w", err)
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
	fullchain, _ := os.Create(filepath.Join(certDir, "fullchain.pem"))
	for _, der := range derChain {
		pem.Encode(fullchain, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	fullchain.Close()
	keyFile, _ := os.Create(filepath.Join(certDir, "privkey.pem"))
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
	os.WriteFile(filepath.Join(certDir, "meta.json"), []byte(meta), 0o600)
	log.Printf("[acme] 证书已签发: %s (CA=%s 密钥=%s)", strings.Join(domains, ","), m.ca.Name, m.keyType)
	return firstDomain, nil
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
		if !strings.Contains(string(data), `"acme":true`) { continue }
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
			cmd := exec.CommandContext(ctx, acmeShPath, "--renew", "-d", domains[0])
			cmd.Dir = certDir
			out, err := cmd.CombinedOutput()
			if err != nil {
				m.lastRenewErr = fmt.Errorf("renew %s: %w\n%s", domains[0], err, out)
				log.Printf("[acme] 续期失败 %s: %v\n%s", domains[0], err, out)
				continue
			}
			log.Printf("[acme] 续期输出:\n%s", string(out))
		} else {
			// acme.sh not available → skip (pure-Go HTTP-01 path not suitable for auto-renew)
			log.Printf("[acme] acme.sh 不可用，跳过 %s 续期", domains[0])
			continue
		}
		// C1: 续期成功后更新 cert bundle hash + meta.json，确保下次心跳下发新证书
		if err := m.UpdateCertMeta(certDir); err != nil {
			log.Printf("[acme] 更新证书元数据失败 %s: %v", e.Name(), err)
		}
		renewed = append(renewed, e.Name())
	}
	return renewed
}

// RenewByName forces renewal of a specific certificate (ignoring expiry threshold).
func (m *Manager) RenewByName(ctx context.Context, certName string) (renewed bool) {
	m.lastRenewErr = nil
	certDir := filepath.Join(m.certsDir, certName)
	data, err := os.ReadFile(filepath.Join(certDir, "meta.json"))
	if err != nil {
		m.lastRenewErr = fmt.Errorf("meta read: %w", err)
		return false
	}
	if !strings.Contains(string(data), `"acme":true`) {
		m.lastRenewErr = fmt.Errorf("not an ACME cert")
		return false
	}
	fcData, _ := os.ReadFile(filepath.Join(certDir, "fullchain.pem"))
	block, _ := pem.Decode(fcData)
	if block == nil {
		m.lastRenewErr = fmt.Errorf("invalid fullchain.pem")
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		m.lastRenewErr = fmt.Errorf("parse cert: %w", err)
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
		cmd := exec.CommandContext(ctx, acmeShPath, "--renew", "-d", domains[0], "--force")
		cmd.Dir = certDir
		out, err := cmd.CombinedOutput()
		log.Printf("[acme] 续期输出:\n%s", string(out))
		m.AppendLog(fmt.Sprintf("acme.sh --renew -d %s --force\n%s\n", domains[0], string(out)))
		if err != nil {
			m.lastRenewErr = fmt.Errorf("renew: %w\n%s", err, string(out))
			return false
		}
	} else {
		m.lastRenewErr = fmt.Errorf("acme.sh not available")
		return false
	}
	// C1/H3: 续期成功后更新 cert bundle hash + meta.json，确保下次心跳下发新证书
	if err := m.UpdateCertMeta(certDir); err != nil {
		log.Printf("[acme] 更新证书元数据失败 %s: %v", certName, err)
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

	// Collect files and compute deterministic hash (sorted by filename)
	var fileNames []string
	fileContents := make(map[string][]byte)
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
	}
	sort.Strings(fileNames)

	h := sha256.New()
	var certPEM, keyPEM []byte
	for _, name := range fileNames {
		content := fileContents[name]
		h.Write(content)
		// Detect cert and key PEM for PFX regeneration (C2)
		if isCertPEM(name, content) && certPEM == nil {
			certPEM = content
		}
		if isKeyPEM(name, content) && keyPEM == nil {
			keyPEM = content
		}
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

	// C2: 续期后重新生成 PFX，Windows Agent 需要最新 PFX 文件
	if certPEM != nil && keyPEM != nil {
		pfxData, pfxErr := mycrypto.GeneratePFX(certPEM, keyPEM, "ddns")
		if pfxErr != nil {
			log.Printf("[acme] PFX 重新生成失败 %s: %v", filepath.Base(certDir), pfxErr)
		} else {
			os.WriteFile(filepath.Join(certDir, "cert.pfx"), pfxData, 0o600)
			log.Printf("[acme] PFX 已重新生成: %s", filepath.Base(certDir))
		}
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
