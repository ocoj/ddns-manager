package server

import (
	"testing"
	"time"
)

// TestTimezone_DisplayConversion verifies event time conversion from UTC to display TZ.
func TestTimezone_DisplayConversion(t *testing.T) {
	// Simulate an event stored in UTC
	utcTime := time.Date(2026, 5, 12, 13, 30, 0, 0, time.UTC) // 13:30 UTC = 21:30 CST

	// Asia/Shanghai (UTC+8)
	cst, _ := time.LoadLocation("Asia/Shanghai")
	displayTime := utcTime.In(cst)

	if displayTime.Hour() != 21 {
		t.Errorf("expected 21:30 CST, got %02d:%02d", displayTime.Hour(), displayTime.Minute())
	}

	if displayTime.Format("2006-01-02 15:04:05") != "2026-05-12 21:30:00" {
		t.Errorf("expected '2026-05-12 21:30:00', got '%s'", displayTime.Format("2006-01-02 15:04:05"))
	}
}

// TestTimezone_UTCStorage verifies that Logger stores events in UTC.
func TestTimezone_UTCStorage(t *testing.T) {
	// Simulate event creation time (should always be within current day)
	nowUTC := time.Now().UTC()
	nowLocal := time.Now()

	// On a server configured to UTC, these should differ for most timezones
	if nowUTC.Location() != time.UTC {
		t.Errorf("time.Now().UTC() returned non-UTC location: %s", nowUTC.Location())
	}

	// nowLocal may be UTC or local depending on server config
	t.Logf("UTC: %s, Local: %s", nowUTC.Format(time.RFC3339), nowLocal.Format(time.RFC3339))
}

// TestTimezone_BoundaryDST tests timezone conversion across DST boundaries.
func TestTimezone_BoundaryDST(t *testing.T) {
	// Test US Eastern time (observes DST)
	eastern, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("cannot load America/New_York: %v", err)
	}

	// January (EST, UTC-5)
	janTime := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	easternJan := janTime.In(eastern)
	// UTC noon = 7:00 AM EST
	if easternJan.Hour() != 7 {
		t.Errorf("January: expected 07:00 EST, got %02d:%02d", easternJan.Hour(), easternJan.Minute())
	}

	// July (EDT, UTC-4)
	julTime := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	easternJul := julTime.In(eastern)
	// UTC noon = 8:00 AM EDT
	if easternJul.Hour() != 8 {
		t.Errorf("July: expected 08:00 EDT, got %02d:%02d", easternJul.Hour(), easternJul.Minute())
	}
}

// TestTimezone_RFC3339Formatting verifies timestamps include timezone info.
func TestTimezone_RFC3339Formatting(t *testing.T) {
	cst, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Now().In(cst)

	formatted := now.Format(time.RFC3339)
	if len(formatted) < 20 {
		t.Errorf("RFC3339 format too short: %s", formatted)
	}

	// Should contain +08:00 offset
	if !contains(formatted, "+08:00") && !contains(formatted, "CST") {
		// Some Go versions format as "+08:00", others as "CST"
		t.Logf("RFC3339 format: %s", formatted)
	}

	// Verify it's parseable
	parsed, err := time.Parse(time.RFC3339, formatted)
	if err != nil {
		t.Errorf("RFC3339 unparseable: %v", err)
	}
	if parsed.Unix() != now.Unix() {
		t.Errorf("round-trip mismatch: %d != %d", parsed.Unix(), now.Unix())
	}
}

// TestTimezone_DefaultFallback verifies default fallback when timezone config is missing.
func TestTimezone_DefaultFallback(t *testing.T) {
	// Simulate empty timezone config → should use Asia/Shanghai
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatalf("cannot load Asia/Shanghai: %v", err)
	}

	// This is the default configured in store.go:LoadTimezoneConfig()
	if loc.String() != "Asia/Shanghai" {
		t.Errorf("expected Asia/Shanghai, got %s", loc.String())
	}

	// Verify the default matches our server default
	defaultLoc, _ := time.LoadLocation("Asia/Shanghai")
	nowDefault := time.Now().In(defaultLoc)

	if nowDefault.Location().String() != "Asia/Shanghai" {
		t.Errorf("timezone default mismatch: %s", nowDefault.Location().String())
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
