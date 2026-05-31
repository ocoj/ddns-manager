package server

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ocoj/ddns-manager/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// ctxKeyTrustedProxy 上下文键：标记请求来自受信反向代理
type ctxKey int

const ctxKeyTrustedProxy ctxKey = iota

type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	interval time.Duration
	capacity int
	stop     chan struct{} // 关闭以停止 cleanupLoop goroutine
}

type tokenBucket struct {
	tokens   float64
	lastTime time.Time
}

func newRateLimiter(reqPerMin int) *rateLimiter {
	rl := &rateLimiter{
		buckets:  make(map[string]*tokenBucket),
		interval: time.Minute,
		capacity: reqPerMin,
		stop:     make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

func (rl *rateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.cleanupStale()
		case <-rl.stop:
			return
		}
	}
}

func (rl *rateLimiter) cleanupStale() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-10 * time.Minute)
	for k, v := range rl.buckets {
		if v.lastTime.Before(cutoff) {
			delete(rl.buckets, k)
		}
	}
}

func (rl *rateLimiter) allow(clientIP string) bool {
	if rl.capacity <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b, ok := rl.buckets[clientIP]
	if !ok {
		b = &tokenBucket{tokens: float64(rl.capacity) - 1, lastTime: now}
		rl.buckets[clientIP] = b
		return true
	}
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * float64(rl.capacity) / rl.interval.Seconds()
	if b.tokens > float64(rl.capacity) {
		b.tokens = float64(rl.capacity)
	}
	b.lastTime = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// applyTrustedProxy sets the trusted proxy context flag on the request
// if the connection originates from one of the configured trusted proxy IPs or CIDR ranges.
func (s *Server) applyTrustedProxy(r *http.Request) *http.Request {
	tp := s.GetTrustedProxy()
	if tp == "" {
		return r
	}
	host := remoteHost(r)
	if host != "" && isTrustedProxyHost(host, tp) {
		ctx := context.WithValue(r.Context(), ctxKeyTrustedProxy, true)
		return r.WithContext(ctx)
	}
	return r
}

func remoteHost(r *http.Request) string {
	if r == nil || r.RemoteAddr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func isTrustedProxyHost(host, cfg string) bool {
	if host == "" || cfg == "" {
		return false
	}
	for _, entry := range strings.Split(cfg, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			if host == ip.String() {
				return true
			}
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			if parsedHost := net.ParseIP(host); parsedHost != nil && network.Contains(parsedHost) {
				return true
			}
			continue
		}
		if host == entry {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request) string {
	// v1.6.56: 仅当受信代理中间件设置了上下文标记时才信任 X-Real-IP / X-Forwarded-For
	if _, ok := r.Context().Value(ctxKeyTrustedProxy).(bool); ok {
		if ip := r.Header.Get("X-Real-IP"); ip != "" {
			return ip
		}
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			if i := strings.IndexByte(fwd, ','); i >= 0 {
				return strings.TrimSpace(fwd[:i])
			}
			return fwd
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func (s *Server) adminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = s.applyTrustedProxy(r)
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			jsonErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if token == "" {
			jsonErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.getAdminToken())) == 1 {
			s.accessCollector.record(clientIP(r))
			next.ServeHTTP(w, r)
			return
		}
		// H3: bcrypt 回退前轻量限流 (5 req/min per IP)，防止 CPU DoS
		if s.bcryptLimiter != nil && !s.bcryptLimiter.allow(clientIP(r)) {
			jsonErr(w, 429, "rate limit exceeded")
			return
		}
		st, _ := s.store.LoadAdminState()
		if st != nil && bcrypt.CompareHashAndPassword([]byte(st.TokenHash), []byte(token)) == nil {
			s.setAdminToken(token)
			s.accessCollector.record(clientIP(r))
			next.ServeHTTP(w, r)
			return
		}
		jsonErr(w, http.StatusUnauthorized, "unauthorized")
	})
}

// ── public ──

func (s *Server) reloadRateLimit(cfg *store.RateLimitConfig) {
	if cfg == nil {
		return
	}
	s.rateLock.Lock()
	defer s.rateLock.Unlock()

	// v1.6.42 H8: 停止前先清理所有 IP bucket, 释放内存 (旧 limiter 不再使用)
	// 防止长期运行后 buckets map 无限增长
	for _, old := range []*rateLimiter{s.globalLimiter, s.heartbeatLimiter, s.loginLimiter} {
		if old != nil {
			old.cleanupStale()
			close(old.stop)
		}
	}

	if cfg.Enabled {
		s.globalLimiter = newRateLimiter(cfg.RequestsPerMin)
		s.heartbeatLimiter = newRateLimiter(cfg.HeartbeatPerMin)
		s.loginLimiter = newRateLimiter(cfg.LoginPerMin)
	} else {
		s.globalLimiter = nil
		s.heartbeatLimiter = nil
		s.loginLimiter = nil
	}
}

// rateLimitMiddleware applies rate limiting based on config.
func (s *Server) rateLimitMiddleware(h http.HandlerFunc, isHeartbeat, isLogin bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = s.applyTrustedProxy(r)
		s.accessCollector.record(clientIP(r))
		s.rateLock.RLock()
		hbLim := s.heartbeatLimiter
		loginLim := s.loginLimiter
		globalLim := s.globalLimiter
		s.rateLock.RUnlock()

		ip := clientIP(r)
		if isHeartbeat && hbLim != nil && !hbLim.allow(ip) {
			jsonErr(w, 429, "rate limit exceeded")
			return
		}
		if isLogin && loginLim != nil && !loginLim.allow(ip) {
			jsonErr(w, 429, "rate limit exceeded")
			return
		}
		if !isHeartbeat && !isLogin && globalLim != nil && !globalLim.allow(ip) {
			jsonErr(w, 429, "rate limit exceeded")
			return
		}
		h(w, r)
	}
}

// pingRateLimitMiddleware applies a lightweight rate limit to /api/ping.
// Fixed at 1000 req/min per IP — high enough for legitimate use (installer checks),
// low enough to prevent HTTP flood abuse.
func (s *Server) pingRateLimitMiddleware(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if s.pingLimiter != nil && !s.pingLimiter.allow(ip) {
			jsonErr(w, 429, "rate limit exceeded")
			return
		}
		h(w, r)
	}
}

// ── admin: smtp ──
