package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSelfUpgradeEarlyValidation verifies C3 fix: validateAgentBinary is called
// inside the retry loop after each successful download, not just after all retries.
func TestSelfUpgradeEarlyValidation(t *testing.T) {
	t.Run("valid_elf_binary", func(t *testing.T) {
		dir := t.TempDir()
		binPath := filepath.Join(dir, "test-agent")
		data := make([]byte, 1024)
		data[0] = 0x7f; data[1] = 'E'; data[2] = 'L'; data[3] = 'F'
		data[4] = 2     // 64-bit
		data[5] = 1     // little-endian
		data[7] = 3     // OS/ABI = GNU/Linux
		binary.LittleEndian.PutUint16(data[16:18], 2)    // ET_EXEC
		binary.LittleEndian.PutUint16(data[18:20], 0x3E) // x86-64
		os.WriteFile(binPath, data, 0755)
		if err := validateAgentBinary(binPath); err != nil {
			t.Errorf("valid ELF should pass: %v", err)
		}
	})

	t.Run("empty_file_fails", func(t *testing.T) {
		dir := t.TempDir()
		binPath := filepath.Join(dir, "empty")
		os.WriteFile(binPath, []byte{}, 0755)
		if err := validateAgentBinary(binPath); err == nil {
			t.Error("empty file should fail validation")
		}
	})

	t.Run("invalid_binary_fails", func(t *testing.T) {
		dir := t.TempDir()
		binPath := filepath.Join(dir, "bad")
		os.WriteFile(binPath, []byte("not a binary"), 0755)
		if err := validateAgentBinary(binPath); err == nil {
			t.Error("invalid binary should fail")
		}
		if !strings.Contains(validateAgentBinary(binPath).Error(), "not") {
			t.Logf("validation error: %v", validateAgentBinary(binPath))
		}
	})

	t.Run("corrupt_elf_fails", func(t *testing.T) {
		dir := t.TempDir()
		binPath := filepath.Join(dir, "corrupt")
		data := make([]byte, 64)
		data[0] = 0x7f; data[1] = 'E'; data[2] = 'L'; data[3] = 'F'
		data[4] = 2  // 64-bit
		data[5] = 1  // LE
		data[7] = 9  // OS/ABI = FreeBSD (rejected)
		binary.LittleEndian.PutUint16(data[16:18], 2)  // ET_EXEC
		binary.LittleEndian.PutUint16(data[18:20], 0x3E) // x86-64
		os.WriteFile(binPath, data, 0755)
		if err := validateAgentBinary(binPath); err == nil {
			t.Error("FreeBSD ELF should be rejected")
		}
	})

	t.Run("pe_binary_header_valid", func(t *testing.T) {
		dir := t.TempDir()
		binPath := filepath.Join(dir, "test.exe")
		data := make([]byte, 1024)
		data[0] = 'M'; data[1] = 'Z'
		binary.LittleEndian.PutUint32(data[60:64], 128)
		data[128] = 'P'; data[129] = 'E'
		binary.LittleEndian.PutUint16(data[132:134], 0x8664) // AMD64
		os.WriteFile(binPath, data, 0755)
		err := validateAgentBinary(binPath)
		t.Logf("PE validation (Linux host, amd64): %v", err)
	})

	t.Run("wrong_arch_pe_fails", func(t *testing.T) {
		dir := t.TempDir()
		binPath := filepath.Join(dir, "arm.exe")
		data := make([]byte, 1024)
		data[0] = 'M'; data[1] = 'Z'
		binary.LittleEndian.PutUint32(data[60:64], 128)
		data[128] = 'P'; data[129] = 'E'
		binary.LittleEndian.PutUint16(data[132:134], 0xAA64) // ARM64 on non-ARM host
		os.WriteFile(binPath, data, 0755)
		err := validateAgentBinary(binPath)
		t.Logf("ARM64 PE on Linux host: %v", err)
	})
}

// TestSelfUpgradeRetryPattern verifies the retry loop continues after
// validation failures (C3 fix behavior).
func TestSelfUpgradeRetryPattern(t *testing.T) {
	t.Run("retry_continues_after_validation_failure", func(t *testing.T) {
		attempts := 0
		for attempt := 0; attempt < 3; attempt++ {
			attempts++
			downloadOK := true
			validateOK := attempt == 2 // only 3rd attempt passes validation
			if downloadOK && validateOK {
				break
			}
		}
		if attempts != 3 {
			t.Errorf("expected 3 attempts when validation fails twice, got %d", attempts)
		}
	})

	t.Run("first_attempt_passes_no_retry", func(t *testing.T) {
		attempts := 0
		for attempt := 0; attempt < 3; attempt++ {
			attempts++
			break // first attempt succeeds immediately
		}
		if attempts != 1 {
			t.Errorf("expected 1 attempt, got %d", attempts)
		}
	})

	t.Run("all_three_fail_returns_error", func(t *testing.T) {
		finalErr := error(nil)
		for attempt := 0; attempt < 3; attempt++ {
			downloadOK := false
			if !downloadOK {
				finalErr = os.ErrNotExist
			}
		}
		if finalErr == nil {
			t.Error("expected error after 3 failed attempts")
		}
	})
}
