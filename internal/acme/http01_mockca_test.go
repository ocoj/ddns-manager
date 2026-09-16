package acme

// A-6（v1.6.72 补丁 v2）：HTTP-01 路径的**离线端到端**测试（自建最小 mock CA）。
//
// 背景（依第三方裁决 Q4-1/Q4-2）：
//   · DNS-01 走 acme.sh ⇒ 已由 fakeHarness 离线覆盖；
//   · HTTP-01 走 Go 原生 ACME 客户端（m.acmeClient）⇒ 此前**只能真连 LE**，离线不可测。
// 本文件用 `httptest` 起一个最小 ACME 目录（newNonce/newAccount/newOrder/authz/challenge/finalize/cert）
// 并用自签 CA 签发证书，从而**离线**驱动 IssueHTTP01 全链路。
//
// 两条硬要求（Q4）：
//  ① **必须覆盖「经 HTTP 端口真实读取挑战文件」这一跳** —— mock 在校验挑战时会对被测 Manager
//     的真实监听地址发起 `http.Client.Get`，并把读到的状态码/内容**回传断言**；
//     ⇒ 若实现未真正经 HTTP 供应挑战，本测试**必失败**（见负控 TestT58b）。
//  ② 超时 + 端口释放：全部网络操作带超时；`httptest.Server` 由 `t.Cleanup(Close)` 释放。
//
// 顺序约束（实测 `SetCA` 内含 `m.reg = nil`）：**先 SetCA(mockURL) → 再 RegisterAccount → 此后不得再调 SetCA**。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── 最小 mock CA ────────────────────────────────────────────────────────────

type mockCA struct {
	mu    sync.Mutex
	srv   *httptest.Server
	ca    *x509.Certificate
	caDER []byte
	key   *ecdsa.PrivateKey

	// 校验地址基址：mock 会真实 GET http://<base>/.well-known/acme-challenge/<token>
	validateBase string

	token       string
	nonce       int
	authzStatus string // pending → valid/invalid（Accept 后由真实 HTTP 读取决定）
	orderStatus string // pending → ready → valid
	leafDER     []byte

	// 观测（供断言）：真实 HTTP 读取的结果
	fetchedStatus int
	fetchedBody   string
	fetchedErr    string
	getCount      int
}

func newMockCA(t *testing.T, validateBase string) *mockCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "T58 Mock CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	c2 := &mockCA{ca: c, caDER: der, key: key, validateBase: validateBase,
		token:       "t58token" + fmt.Sprint(time.Now().UnixNano()),
		authzStatus: "pending", orderStatus: "pending"}
	mux := http.NewServeMux()
	mux.HandleFunc("/directory", c2.handleDirectory)
	mux.HandleFunc("/new-nonce", c2.handleNonce)
	mux.HandleFunc("/new-account", c2.handleNewAccount)
	mux.HandleFunc("/new-order", c2.handleNewOrder)
	mux.HandleFunc("/authz/1", c2.handleAuthz)
	mux.HandleFunc("/chal/1", c2.handleChallenge)
	mux.HandleFunc("/finalize/1", c2.handleFinalize)
	mux.HandleFunc("/cert/1", c2.handleCert)
	c2.srv = httptest.NewServer(mux)
	t.Cleanup(c2.srv.Close) // ② 端口释放
	return c2
}

func (c *mockCA) directoryURL() string { return c.srv.URL + "/directory" }

func (c *mockCA) nextNonce() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nonce++
	return fmt.Sprintf("nonce-%d", c.nonce)
}

func (c *mockCA) writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Replay-Nonce", c.nextNonce())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (c *mockCA) handleDirectory(w http.ResponseWriter, r *http.Request) {
	c.writeJSON(w, 200, map[string]string{
		"newNonce":   c.srv.URL + "/new-nonce",
		"newAccount": c.srv.URL + "/new-account",
		"newOrder":   c.srv.URL + "/new-order",
	})
}

func (c *mockCA) handleNonce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", c.nextNonce())
	w.WriteHeader(http.StatusOK)
}

func (c *mockCA) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", c.srv.URL+"/acct/1")
	c.writeJSON(w, 201, map[string]interface{}{"status": "valid", "contact": []string{"mailto:t58@example.com"}})
}

func (c *mockCA) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", c.srv.URL+"/order/1")
	c.mu.Lock()
	c.orderStatus = "pending"
	c.mu.Unlock()
	c.writeJSON(w, 201, c.orderJSON())
}

func (c *mockCA) orderJSON() map[string]interface{} {
	c.mu.Lock()
	st := c.orderStatus
	c.mu.Unlock()
	o := map[string]interface{}{
		"status":         st,
		"authorizations": []string{c.srv.URL + "/authz/1"},
		"finalize":       c.srv.URL + "/finalize/1",
	}
	if st == "valid" {
		o["certificate"] = c.srv.URL + "/cert/1"
	}
	return o
}

func (c *mockCA) authzJSON() map[string]interface{} {
	c.mu.Lock()
	st := c.authzStatus
	c.mu.Unlock()
	return map[string]interface{}{
		"status":     st,
		"identifier": map[string]string{"type": "dns", "value": "t58.example.com"},
		"challenges": []map[string]interface{}{{
			"type":   "http-01",
			"status": st,
			"url":    c.srv.URL + "/chal/1",
			"token":  c.token,
		}},
	}
}

func (c *mockCA) handleAuthz(w http.ResponseWriter, r *http.Request) {
	c.writeJSON(w, 200, c.authzJSON())
}

// handleChallenge：收到 Accept（POST，payload 非空）时执行**真实 HTTP 读取**校验。
func (c *mockCA) handleChallenge(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	c.mu.Lock()
	st := c.authzStatus
	c.mu.Unlock()
	if len(jwsPayload(body)) > 0 && st == "pending" { // Accept
		c.validateViaRealHTTP()
	}
	c.writeJSON(w, 200, map[string]interface{}{
		"type": "http-01", "status": c.currentAuthz(), "url": c.srv.URL + "/chal/1", "token": c.token,
	})
}

func (c *mockCA) currentAuthz() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authzStatus
}

// validateViaRealHTTP 是**本测试的核心**：对被测 Manager 的真实 HTTP 端口发起 GET，
// 读取 `/.well-known/acme-challenge/<token>`，并记录状态码/内容/错误。
func (c *mockCA) validateViaRealHTTP() {
	url := "http://" + c.validateBase + "/.well-known/acme-challenge/" + c.token
	cli := &http.Client{Timeout: 5 * time.Second} // ② 超时
	resp, err := cli.Get(url)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getCount++
	if err != nil {
		c.fetchedErr = err.Error()
		c.authzStatus = "invalid"
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	c.fetchedStatus = resp.StatusCode
	c.fetchedBody = string(b)
	if resp.StatusCode == http.StatusOK && len(b) > 0 {
		c.authzStatus = "valid"
	} else {
		c.authzStatus = "invalid"
	}
}

// jwsPayload 取出 JWS 的 payload（POST-as-GET 时为空）。
func jwsPayload(body []byte) []byte {
	var m struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(body, &m); err != nil || m.Payload == "" {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(m.Payload)
	if err != nil {
		return nil
	}
	return b
}

// handleFinalize：从 JWS payload 解析 CSR，用自签 CA 签发叶证书。
func (c *mockCA) handleFinalize(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(jwsPayload(body), &req); err != nil || req.CSR == "" {
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		http.Error(w, "bad csr b64", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		http.Error(w, "bad csr parse", http.StatusBadRequest)
		return
	}
	_ = csr.CheckSignature()
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: strings.Join(csr.DNSNames, ",")},
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, c.ca, csr.PublicKey, c.key)
	if err != nil {
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	c.mu.Lock()
	c.leafDER = leafDER
	c.orderStatus = "valid"
	c.mu.Unlock()
	w.Header().Set("Location", c.srv.URL+"/order/1")
	c.writeJSON(w, 200, c.orderJSON())
}

func (c *mockCA) handleCert(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	leaf := c.leafDER
	c.mu.Unlock()
	if leaf == nil {
		http.Error(w, "no cert", http.StatusNotFound)
		return
	}
	w.Header().Set("Replay-Nonce", c.nextNonce())
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(200)
	_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: leaf})
	_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: c.caDER})
}

// freeAddr 取得一个空闲的本地监听地址（供被测 Manager 使用）。
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// ── 测试 ────────────────────────────────────────────────────────────────────

// TestT58_IssueHTTP01_OfflineWithMockCA 正向：mock CA 经**真实 HTTP** 读取挑战 ⇒ 全链路成功。
func TestT58_IssueHTTP01_OfflineWithMockCA(t *testing.T) {
	mgrAddr := freeAddr(t)
	ca := newMockCA(t, mgrAddr) // mock 将去 mgrAddr 读取挑战（真实 HTTP）

	dir := t.TempDir()
	m, err := New(dir, "t58@example.com", mgrAddr)
	if err != nil {
		t.Fatal(err)
	}
	// 顺序约束：先 SetCA（内含 m.reg = nil）→ 再注册 → 此后不得再 SetCA
	m.SetCA(CA{Name: "T58 Mock CA", URL: ca.directoryURL()})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // ② 超时
	defer cancel()
	// 显式注册，锁定顺序（IssueHTTP01 内部也会在 reg==nil 时注册）
	if err := func() error { return m.RegisterAccount(ctx) }(); err != nil {
		t.Fatalf("RegisterAccount(mock CA): %v", err)
	}

	domains := []string{"t58.example.com"}
	got, err := m.IssueHTTP01(ctx, domains)
	if err != nil {
		t.Fatalf("IssueHTTP01 应成功（mock CA 离线签发）: %v", err)
	}
	if got != domains[0] {
		t.Errorf("IssueHTTP01 返回值应为主域名 %q，实际 %q", domains[0], got)
	}

	// ★ 核心断言：挑战**确实经 HTTP 端口被读取**（而非进程内断言）
	ca.mu.Lock()
	status, body, ferr, n := ca.fetchedStatus, ca.fetchedBody, ca.fetchedErr, ca.getCount
	ca.mu.Unlock()
	if status != http.StatusOK || body == "" {
		t.Fatalf("mock 未能经 HTTP 读到挑战文件：status=%d body=%q err=%q（getCount=%d）", status, body, ferr, n)
	}
	// 内容闭环：读到的内容必须等于客户端本应给出的 key authorization
	want, kerr := m.acmeClient.HTTP01ChallengeResponse(ca.token)
	if kerr != nil {
		t.Fatalf("HTTP01ChallengeResponse: %v", kerr)
	}
	if body != want {
		t.Errorf("挑战内容不符：mock 读到 %q，期望 keyAuth %q", body, want)
	}

	// 落盘断言（issueCert 实际契约：fullchain.pem / privkey.pem / meta.json；
	//   cert.pem 由后续 UpdateCertMeta / acme.sh 安装路径产生，HTTP-01 原生路径不写）
	for _, f := range []string{"fullchain.pem", "privkey.pem", "meta.json"} {
		if _, err := os.Stat(filepath.Join(dir, domains[0], f)); err != nil {
			t.Errorf("签发后应存在 %s: %v", f, err)
		}
	}
	// 叶证书 SAN 应为申请的域名
	b, err := os.ReadFile(filepath.Join(dir, domains[0], "fullchain.pem"))
	if err == nil {
		blk, _ := pem.Decode(b)
		if blk != nil {
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				found := false
				for _, d := range c.DNSNames {
					if d == domains[0] {
						found = true
					}
				}
				if !found {
					t.Errorf("叶证书 SAN 应含 %q，实际 %v", domains[0], c.DNSNames)
				}
			}
		}
	}
}

// TestT58b_MockCA_RequiresRealHTTPRead 负控（判别力证明）：
// mock 去**无人监听**的地址读取挑战 ⇒ IssueHTTP01 **必须失败**。
// 若实现并未真正经 HTTP 供应挑战，本测试会误判为"成功" ⇒ 从而反证 mock 具备判别力。
func TestT58b_MockCA_RequiresRealHTTPRead(t *testing.T) {
	mgrAddr := freeAddr(t)
	deadAddr := freeAddr(t) // 只取地址、不监听：模拟"挑战不可达"

	ca := newMockCA(t, deadAddr)

	dir := t.TempDir()
	m, err := New(dir, "t58b@example.com", mgrAddr)
	if err != nil {
		t.Fatal(err)
	}
	m.SetCA(CA{Name: "T58b Mock CA", URL: ca.directoryURL()})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := m.RegisterAccount(ctx); err != nil {
		t.Fatalf("RegisterAccount: %v", err)
	}

	_, err = m.IssueHTTP01(ctx, []string{"t58b.example.com"})
	if err == nil {
		ca.mu.Lock()
		st, ferr := ca.fetchedStatus, ca.fetchedErr
		ca.mu.Unlock()
		t.Fatalf("负控失败：挑战不可达（fetchedStatus=%d err=%q）但 IssueHTTP01 仍返回成功 ⇒ 未真正经 HTTP 供应挑战", st, ferr)
	}
	ca.mu.Lock()
	ferr := ca.fetchedErr
	ca.mu.Unlock()
	if ferr == "" {
		t.Logf("注意：mock 未记录到读取错误（错误来自其它环节），IssueHTTP01 错误=%v", err)
	}
	t.Logf("负控符合预期：挑战不可达 ⇒ IssueHTTP01 失败（%v）", err)
}
