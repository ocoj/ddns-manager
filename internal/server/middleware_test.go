package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIPUsesTrustedProxyHeadersForDockerBridgeRange(t *testing.T) {
	s := &Server{}
	s.SetTrustedProxy("172.18.0.0/16")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.18.0.5:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")

	req = s.applyTrustedProxy(req)
	if got := clientIP(req); got != "203.0.113.10" {
		t.Fatalf("expected forwarded client IP, got %q", got)
	}
}

func TestClientIPSupportsCommaSeparatedTrustedProxyList(t *testing.T) {
	s := &Server{}
	s.SetTrustedProxy("127.0.0.1, 172.18.0.0/16")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.18.0.9:54321"
	req.Header.Set("X-Real-IP", "198.51.100.42")

	req = s.applyTrustedProxy(req)
	if got := clientIP(req); got != "198.51.100.42" {
		t.Fatalf("expected real IP from trusted proxy, got %q", got)
	}
}
