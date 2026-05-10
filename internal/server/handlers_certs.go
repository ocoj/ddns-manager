package server

import (
	"archive/zip"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/kk/ddns-manager/internal/acme"
	"github.com/kk/ddns-manager/internal/store"
)

func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	names, _ := s.store.ListCertBundles()
	type ci struct {
		Name    string   `json:"name"`
		Files   []string `json:"files"`
		Hash    string   `json:"hash"`
		Acme    bool     `json:"acme"`
		Domains []string `json:"domains,omitempty"`
		Expiry  string   `json:"expiry,omitempty"`
	}
	var result []ci
	for _, name := range names {
		b, err := s.store.LoadCertBundle(name)
		if err != nil {
			continue
		}
		var fileNames []string
		for f := range b.Files {
			fileNames = append(fileNames, f)
		}
		sort.Strings(fileNames)
		hashShort := strings.TrimPrefix(b.Hash, "sha256:")
		if len(hashShort) > 12 {
			hashShort = hashShort[:12]
		}
		item := ci{Name: name, Files: fileNames, Hash: hashShort, Acme: strings.HasPrefix(name, "acme-")}
		// try to parse expiry from any pem file (fullchain.pem / cert.pem / fullchain11.pem / etc.)
		for fn, content := range b.Files {
			if strings.HasSuffix(strings.ToLower(fn), ".pem") || strings.HasSuffix(strings.ToLower(fn), ".crt") {
				if exp, dom := parseCertExpiry(content); exp != "" {
					item.Expiry = exp
					item.Domains = dom
					break
				}
			}
		}
		result = append(result, item)
	}
	jsonOK(w, result)
}

func parseCertExpiry(pemData []byte) (string, []string) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", nil
	}
	domains := cert.DNSNames
	if len(domains) == 0 {
		domains = []string{cert.Subject.CommonName}
	}
	return cert.NotAfter.Format("2006-01-02"), domains
}

func (s *Server) handleGetCert(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	b, err := s.store.LoadCertBundle(name)
	if err != nil {
		jsonErr(w, http.StatusNotFound, "证书集未找到")
		return
	}
	var files []string
	for f := range b.Files {
		files = append(files, f)
	}
	sort.Strings(files)
	// parse cert details
	detail := map[string]interface{}{"name": name, "files": files, "hash": b.Hash}
	var certPEM []byte
	for fn, content := range b.Files {
		if strings.HasSuffix(strings.ToLower(fn), ".pem") || strings.HasSuffix(strings.ToLower(fn), ".crt") {
			certPEM = content; break
		}
	}
	if certPEM != nil {
		block, _ := pem.Decode(certPEM)
		if block != nil {
			c, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				detail["subject"] = c.Subject.CommonName
				// Issuer: Organization优先 (如"Let's Encrypt")，备选CommonName (如"E7")
					issuer := c.Issuer.CommonName
					if len(c.Issuer.Organization) > 0 {
						issuer = strings.Join(c.Issuer.Organization, ", ")
						if c.Issuer.CommonName != "" && c.Issuer.CommonName != issuer {
							issuer += " (" + c.Issuer.CommonName + ")"
						}
					}
					detail["issuer"] = issuer
				detail["not_before"] = c.NotBefore.Format("2006-01-02")
				detail["not_after"] = c.NotAfter.Format("2006-01-02")
				detail["dns_names"] = c.DNSNames
			}
		}
	}
	// read meta.json for acme/dns info
	metaPath := filepath.Join(s.cfg.DataDir, "certs", name, "meta.json")
	if meta, err := os.ReadFile(metaPath); err == nil {
		var mi map[string]interface{}
		if json.Unmarshal(meta, &mi) == nil {
			if mi["acme"] == true { detail["acme"] = true }
			if v, ok := mi["ca"]; ok { detail["ca"] = v }
			if v, ok := mi["email"]; ok { detail["email"] = v }
			if v, ok := mi["provider"]; ok { detail["dns_provider"] = v }
		}
	}
	jsonOK(w, detail)
}

func (s *Server) handleUploadCert(w http.ResponseWriter, r *http.Request) {
	// Consistent limit: MaxBytesReader and ParseMultipartForm both use maxUploadSize (50MB)
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		jsonErr(w, http.StatusBadRequest, "file too large")
		return
	}
	name := r.FormValue("name")
	if name == "" {
		jsonErr(w, http.StatusBadRequest, "name required")
		return
	}
	files := map[string][]byte{}
	for _, fh := range r.MultipartForm.File {
		for _, h := range fh {
			f, err := h.Open()
			if err != nil {
				continue
			}
			data, _ := io.ReadAll(f)
			f.Close()
			files[h.Filename] = data
		}
	}
	if len(files) == 0 {
		jsonErr(w, http.StatusBadRequest, "no files uploaded")
		return
	}
	bundle := &store.CertBundle{Name: name, Files: files, Hash: computeBundleHash(files)}
	if err := s.store.SaveCertBundle(bundle); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logMgr.Log("cert", "已上传", name, "success")
	jsonOK(w, map[string]string{"status": "uploaded", "name": name})
}

func (s *Server) handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if strings.HasPrefix(name, "acme-") {
		jsonErr(w, http.StatusBadRequest, "不能删除 ACME 管理的证书")
		return
	}
	if err := s.store.DeleteCertBundle(name); err != nil {
		jsonErr(w, http.StatusNotFound, "证书集未找到")
		return
	}
	s.logMgr.Log("cert", "已删除", name, "info")
	jsonOK(w, map[string]string{"deleted": name})
}

func (s *Server) handleDownloadCert(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	b, err := s.store.LoadCertBundle(name)
	if err != nil {
		jsonErr(w, http.StatusNotFound, "未找到")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.zip", name))
	zw := zip.NewWriter(w)
	defer zw.Close()
	for fname, data := range b.Files {
		fw, _ := zw.Create(fname)
		fw.Write(data)
	}
}

func (s *Server) handleRenewCert(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if !strings.HasPrefix(name, "acme-") {
		jsonErr(w, http.StatusBadRequest, "仅 ACME 证书支持续期")
		return
	}
	certName := name // keep acme- prefix, directory matches
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	mgrs := s.acmeMgrList()
	var lastErr error
	for _, mgr := range mgrs {
		renewed := mgr.RenewByName(ctx, certName)
		if renewed {
			s.logMgr.Log("acme", "已续期", certName, "success")
			jsonOK(w, map[string]string{"status": "renewed", "name": name})
			return
		}
		if err := mgr.LastError(); err != nil {
			lastErr = err
		}
	}
	if lastErr != nil {
		jsonErr(w, http.StatusInternalServerError, "续期失败: "+lastErr.Error())
		return
	}
	jsonErr(w, http.StatusNotFound, "证书未找到或未到续期时间")
}


func (s *Server) getACMEMgr(index int) *acme.Manager {
	s.acmeMu.RLock()
	defer s.acmeMu.RUnlock()
	if index >= 0 && index < len(s.acmeMgrs) {
		return s.acmeMgrs[index]
	}
	if len(s.acmeMgrs) > 0 {
		return s.acmeMgrs[0]
	}
	return s.acme
}

func (s *Server) handleACMEList(w http.ResponseWriter, r *http.Request) {
	type acct struct {
		Email      string `json:"email"`
		CA         string `json:"ca"`
		KeyType    string `json:"key_type"`
		Registered bool   `json:"registered"`
		AccountURL string `json:"account_url"`
		Active     bool   `json:"active"`
	}
	var accounts []acct
	for i, mgr := range s.acmeMgrList() {
		info := mgr.AccountInfo()
		accounts = append(accounts, acct{
			Email: info.Email, CA: info.CA, KeyType: info.KeyType,
			Registered: info.Registered, AccountURL: info.AccountURL,
			Active: i == 0,
		})
	}
	if len(accounts) == 0 && s.acme != nil {
		info := s.acme.AccountInfo()
		accounts = append(accounts, acct{
			Email: info.Email, CA: info.CA, KeyType: info.KeyType,
			Registered: info.Registered, AccountURL: info.AccountURL, Active: true,
		})
	}
	jsonOK(w, map[string]interface{}{"accounts": accounts})
}

func (s *Server) handleACMESaveAccountIndex(w http.ResponseWriter, r *http.Request) {
	idxStr := mux.Vars(r)["index"]
	// 安全解析: 检查错误，非数字字符当作新增 (-1)，防止 strconv.Atoi("abc") → 0 静默覆盖
	idx, err := strconv.Atoi(idxStr)
	isAppend := idxStr == "-1" || idxStr == "" || err != nil
	if isAppend {
		idx = -1
	} else if idx < 0 {
		jsonErr(w, http.StatusBadRequest, "invalid index")
		return
	}
	certsDir := filepath.Join(s.cfg.DataDir, "certs")

	var req struct {
		Email   string `json:"email"`
		CA      string `json:"ca"`
		KeyType string `json:"key_type"`
		EABKID  string `json:"eab_kid,omitempty"`
		EABKey  string `json:"eab_key,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	if req.Email == "" {
		jsonErr(w, http.StatusBadRequest, "邮箱为必填项")
		return
	}

	// create or reuse ACME manager with stored key
	accounts, _ := s.store.LoadACMEAccounts()
	var storedKey string
	if idx >= 0 && idx < len(accounts) {
		storedKey = accounts[idx].AccountKey
	}
	mgr, err := acme.NewWithKey(certsDir, req.Email, ":80", []byte(storedKey))
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, ca := range acme.AllCAs {
		if strings.EqualFold(ca.Name, req.CA) {
			mgr.SetCA(ca)
			break
		}
	}
	if req.KeyType != "" {
		mgr.SetKeyType(acme.ParseKeyType(req.KeyType))
	}
	if req.EABKID != "" && req.EABKey != "" {
		mgr.SetEAB(&acme.EAB{KID: req.EABKID, HMACKey: req.EABKey})
	}

	// try register
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	regErr := mgr.RegisterAccount(ctx)

	// persist to store atomically (read-modify-write under lock to prevent concurrent corruption)
	keyPEM, _ := mgr.AccountKeyPEM()
	acct := store.ACMEAccountConfig{
		Email: req.Email, CA: req.CA, KeyType: req.KeyType, AccountKey: string(keyPEM),
		EABKID: req.EABKID, EABKey: req.EABKey,
		Updated: time.Now().UTC().Format(time.RFC3339),
	}

	if err := s.store.PutACMEAccount(idx, acct); err != nil {
		jsonErr(w, http.StatusInternalServerError, "保存帐号: "+err.Error())
		return
	}

	if isAppend {
		s.addACMEMgr(mgr)
	} else if idx >= 0 {
		s.setACMEMgr(idx, mgr)
	}

	msg := "saved"
	if regErr != nil {
		msg = "saved but register failed: " + regErr.Error()
	}
	s.logMgr.Log("acme", "帐号已保存", req.Email+" ("+req.CA+")", "success")
	jsonOK(w, map[string]interface{}{"status": msg, "registered": mgr.AccountInfo().Registered})
}

func (s *Server) handleACMEDeleteAccount(w http.ResponseWriter, r *http.Request) {
	idxStr := mux.Vars(r)["index"]
	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx < 0 {
		jsonErr(w, http.StatusBadRequest, "invalid index")
		return
	}
	// Load accounts under lock to get email for logging before deletion
	accounts, _ := s.store.LoadACMEAccounts()
	if idx >= len(accounts) {
		jsonErr(w, http.StatusNotFound, "帐号未找到")
		return
	}
	deleted := accounts[idx].Email
	// Atomic delete under write lock — prevents concurrent write corruption
	if err := s.store.DeleteACMEAccount(idx); err != nil {
		jsonErr(w, http.StatusInternalServerError, "删除帐号: "+err.Error())
		return
	}
	s.removeACMEMgr(idx)
	s.logMgr.Log("acme", "帐号已删除", deleted, "info")
	jsonOK(w, map[string]string{"deleted": deleted})
}

func (s *Server) handleACMEIssue(w http.ResponseWriter, r *http.Request) {
	refMgr := s.getACMEMgr(0)
	if refMgr == nil {
		jsonErr(w, http.StatusBadRequest, "ACME 未配置")
		return
	}
	var req struct {
		Domains      []string `json:"domains"`
		CA           string   `json:"ca"`
		KeyType      string   `json:"key_type"`
		DNSProvider  string   `json:"dns_provider"`
		AccountIndex string   `json:"account_index"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	if len(req.Domains) == 0 {
		jsonErr(w, http.StatusBadRequest, "至少需要一个域名")
		return
	}
	// select account
	email := refMgr.AccountInfo().Email
	if req.AccountIndex != "" {
		if idx, err := strconv.Atoi(req.AccountIndex); err == nil {
			if am := s.getACMEMgr(idx); am != nil {
				email = am.AccountInfo().Email
				refMgr = am
			}
		}
	}
	// determine CA and key type (from request or account defaults)
	caName := refMgr.AccountInfo().CA
	keyType := refMgr.AccountInfo().KeyType
	if req.CA != "" {
		caName = req.CA
	}
	if req.KeyType != "" {
		keyType = req.KeyType
	}

	// create a per-request Manager to avoid mutating shared state
	certsDir := filepath.Join(s.cfg.DataDir, "certs")
	mgr, err := acme.New(certsDir, email, ":80")
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, ca := range acme.AllCAs {
		if strings.EqualFold(ca.Name, caName) {
			mgr.SetCA(ca)
			break
		}
	}
	mgr.SetKeyType(acme.ParseKeyType(keyType))

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	var certName string
	if req.DNSProvider != "" {
		keys, _ := s.store.LoadDNSKeys()
		dk, ok := keys[req.DNSProvider]
		if !ok {
			// fallback: try lowercase
			dk, ok = keys[strings.ToLower(req.DNSProvider)]
		}
		if !ok {
			jsonErr(w, http.StatusBadRequest, "DNS 密钥未找到: "+req.DNSProvider+" — ensure a Key with this name exists")
			return
		}
		certName, err = mgr.IssueDNS01(ctx, req.Domains, acme.DNSProvider{
			Name: dk.Provider, KeyID: dk.AccessKeyID, KeySecret: dk.AccessKeySecret,
		})
	} else {
		certName, err = mgr.IssueHTTP01(ctx, req.Domains)
	}
	if err != nil {
		s.logMgr.Log("acme", "签发失败", strings.Join(req.Domains, ","), err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "ACME 错误: " + err.Error(), "log": mgr.GetLog()})
		return
	}

	certDir := filepath.Join(s.cfg.DataDir, "certs", certName)
	bundle := &store.CertBundle{Name: "acme-" + certName, Files: map[string][]byte{}}
	for _, fn := range []string{"fullchain.pem", "privkey.pem", "cert.pem"} {
		if data, err := os.ReadFile(filepath.Join(certDir, fn)); err == nil {
			bundle.Files[fn] = data
		}
	}
	bundle.Hash = computeBundleHash(bundle.Files)
	s.store.SaveCertBundle(bundle)
	// clean up the original cert dir (issueViaAcmeSh creates certs/domain/, we save to certs/acme-domain/)
	if !strings.HasPrefix(certName, "acme-") {
		os.RemoveAll(certDir)
	}
	s.logMgr.Log("acme", "已签发", certName, fmt.Sprintf("ca=%s domains=%s", mgr.AccountInfo().CA, strings.Join(req.Domains, ",")))
	jsonOK(w, map[string]interface{}{"status": "issued", "name": "acme-" + certName, "domains": req.Domains, "log": mgr.GetLog()})
}

// ── admin: logs ──
