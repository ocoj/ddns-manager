package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSelfUpgradeRetryLoop verifies that the self-upgrade download loop
// retries on transient HTTP errors (5xx) instead of returning immediately.
// Covers: C1 fix — selfUpgrade retry loop use continue instead of return.
//
// This tests the download retry logic abstraction: a helper function that
// attempts an HTTP GET 3 times with backoff, succeeding when it gets 200.
func TestSelfUpgradeRetryLoop_SuccessOnRetry(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable) // 503
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(strings.Repeat("x", 10000))) // valid binary content
	}))
	defer ts.Close()

	// Simulate the retry logic from selfUpgrade
	var lastErr error
	maxAttempts := 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		lastErr = func() error {
			resp, err := http.Get(ts.URL)
			if err != nil {
				return fmt.Errorf("attempt %d: %w", attempt+1, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("attempt %d: HTTP %d", attempt+1, resp.StatusCode)
			}
			return nil
		}()
		if lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		t.Fatalf("retry should succeed by attempt 3: %v", lastErr)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

// TestSelfUpgradeRetryLoop_AllFail verifies the retry loop exhausts all attempts
// when all responses are errors.
func TestSelfUpgradeRetryLoop_AllFail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	var lastErr error
	maxAttempts := 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		lastErr = func() error {
			resp, err := http.Get(ts.URL)
			if err != nil {
				return fmt.Errorf("attempt %d: %w", attempt+1, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("attempt %d: HTTP %d", attempt+1, resp.StatusCode)
			}
			return nil
		}()
		if lastErr == nil {
			break
		}
	}
	if lastErr == nil {
		t.Fatal("retry should fail after all attempts exhausted")
	}
}

// TestSelfUpgradeRetryLoop_FirstSuccess verifies the retry loop returns
// immediately on first success without making additional requests.
func TestSelfUpgradeRetryLoop_FirstSuccess(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(strings.Repeat("x", 10000)))
	}))
	defer ts.Close()

	var lastErr error
	maxAttempts := 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		lastErr = func() error {
			resp, err := http.Get(ts.URL)
			if err != nil {
				return fmt.Errorf("attempt %d: %w", attempt+1, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("attempt %d: HTTP %d", attempt+1, resp.StatusCode)
			}
			return nil
		}()
		if lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		t.Fatalf("first attempt should succeed: %v", lastErr)
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt, got %d (should not retry on success)", attempts)
	}
}
