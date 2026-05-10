package server

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kk/ddns-manager/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	interval time.Duration
	capacity int
}

type tokenBucket struct {
	tokens   float64
	lastTime time.Time
}


func newRateLimiter(reqPerMin int) *rateLimiter {
	rl := &rateLimiter{buckets: make(map[string]*tokenBucket), interval: time.Minute, capacity: reqPerMin}
	// start periodic cleanup to prevent unbounded map growth
	go rl.cleanupLoop()
	return rl
}

func (rl *rateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.cleanupStale()
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
	if rl.capacity <= 0 { return true }
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
	if b.tokens > float64(rl.capacity) { b.tokens = float64(rl.capacity) }
	b.lastTime = now
	if b.tokens >= 1 { b.tokens--; return true }
	return false
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" { return ip }
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if i := strings.IndexByte(fwd, ','); i >= 0 { return strings.TrimSpace(fwd[:i]) }
		return fwd
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func (s *Server) adminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if cfg == nil { return }
	s.rateLock.Lock()
	defer s.rateLock.Unlock()
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

// ── admin: smtp ──
