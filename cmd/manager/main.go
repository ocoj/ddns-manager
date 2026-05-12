// ddns-manager — central management server for ddns-go nodes
package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kk/ddns-manager/internal/acme"
	"github.com/kk/ddns-manager/internal/config"
	"github.com/kk/ddns-manager/internal/logger"
	"github.com/kk/ddns-manager/internal/server"
	"github.com/kk/ddns-manager/internal/store"
)

//go:embed static/*
var staticFiles embed.FS

// version is set at build time via -ldflags "-X main.version=x.y.z"
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "show version and exit")
	configPath := flag.String("c", "manager.yaml", "config file path")
	listen := flag.String("l", "", "override listen address")
	dataDir := flag.String("data-dir", "", "data directory")
	tlsCert := flag.String("tls-cert", "", "TLS certificate path")
	tlsKey := flag.String("tls-key", "", "TLS key path")
	noTLS := flag.Bool("no-tls", false, "disable TLS (dev only)")
	acmeEmail := flag.String("acme-email", "", "ACME account email (enables Let's Encrypt)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ddns-manager v%s\nPublisher: Lanxun CO.,Ltd.\n", version)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}

	if *listen != "" {
		cfg.Server.Listen = *listen
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if *tlsCert != "" {
		cfg.Server.TLSCert = *tlsCert
	}
	if *tlsKey != "" {
		cfg.Server.TLSKey = *tlsKey
	}

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
	}

	st, err := store.NewStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("初始化存储失败: %v", err)
	}

	// 日志管理器
	logMgr, err := logger.New(filepath.Join(cfg.DataDir, "events.log"), 10000)
	if err != nil {
		log.Fatalf("初始化日志系统失败: %v", err)
	}
	defer logMgr.Close()

	// 启动时重建 agent manifest — 确保与 /bin/ 目录实际内容一致
	// (兜底: 手动删文件、迁移数据等边缘情况)
	st.RebuildManifest()
	log.Printf("[manifest] 已重建 agent_manifest (从 /bin/ 扫描)")

	// ACME manager — load from stored accounts, fallback to -acme-email flag
	var acmeMgr *acme.Manager
	var hasAcmeMgrs bool
	acmeAccounts, _ := st.LoadACMEAccounts()
	if len(acmeAccounts) == 0 && *acmeEmail != "" {
		// bootstrap: migrate -acme-email flag to store
		st.SaveACMEAccounts([]store.ACMEAccountConfig{{
			Email: *acmeEmail, CA: "Let's Encrypt", KeyType: "EC256",
			Updated: time.Now().UTC().Format(time.RFC3339),
		}})
		log.Printf("[acme] 已将命令行参数邮箱 %s 迁移到存储", *acmeEmail)
		acmeAccounts, _ = st.LoadACMEAccounts()
	}
	if len(acmeAccounts) > 0 {
		hasAcmeMgrs = true
		email := acmeAccounts[0].Email
		acmeMgr, err = acme.NewWithKey(filepath.Join(cfg.DataDir, "certs"), email, ":80", []byte(acmeAccounts[0].AccountKey))
		if err != nil {
			log.Printf("[acme] 初始化失败: %v", err)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := acmeMgr.RegisterAccount(ctx); err != nil {
				log.Printf("[acme] 注册帐号失败: %v", err)
			} else {
				// persist generated key
				keyPEM, _ := acmeMgr.AccountKeyPEM()
				if keyPEM != nil && acmeAccounts[0].AccountKey == "" {
					acmeAccounts[0].AccountKey = string(keyPEM)
					acmeAccounts[0].Updated = time.Now().UTC().Format(time.RFC3339)
					st.SaveACMEAccounts(acmeAccounts)
				}
				log.Printf("[acme] 帐号就绪: %s", email)
			}
			cancel()
		}
	}

	mgr := server.New(cfg, st, acmeMgr, logMgr, version)

	// auto-renew goroutine for all ACME accounts
	shutdownACME := make(chan struct{})
	if hasAcmeMgrs {
		mgr.StartAutoRenew(shutdownACME)
	}
	defer close(shutdownACME)

	// start background system info collector (non-blocking, 30s interval)
	shutdownSysInfo := make(chan struct{})
	mgr.StartSysInfoCollector(shutdownSysInfo)
	defer close(shutdownSysInfo)

	r := mgr.Router()

	// static SPA (must be LAST — catches all other paths)
	staticFS, _ := fs.Sub(staticFiles, "static")
	r.PathPrefix("/").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		http.FileServer(http.FS(staticFS)).ServeHTTP(w, r)
	}))

	log.Printf("[admin] 默认管理员密码: Admin12345 (请在首次登录后修改)")
	if acmeMgr != nil {
		log.Println("[acme] Let's Encrypt 已启用 (http-01 验证端口 :80)")
	}

	httpSrv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("[http] 收到信号 %v，正在优雅关闭...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		httpSrv.Shutdown(ctx)
	}()

	if *noTLS || (cfg.Server.TLSCert == "" && cfg.Server.TLSKey == "") {
		log.Printf("[http] ddns-manager v%s 监听 %s", version, cfg.Server.Listen)
		if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
		log.Println("[http] HTTP 服务已停止")
		return
	}

	log.Printf("[https] HTTPS 监听 %s", cfg.Server.Listen)
	if err := httpSrv.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey); err != http.ErrServerClosed {
		log.Fatal(err)
	}
	log.Println("[https] HTTPS 服务已停止")
}
