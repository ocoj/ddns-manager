package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hello")},
		{"json", []byte(`{"key":"value","num":42}`)},
		{"binary", bytes.Repeat([]byte{0x00, 0xFF, 0xAB}, 256)},
		{"cert_pem", []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----")},
		{"utf8", []byte("你好世界 — ddns-manager 证书")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := Encrypt(tt.plaintext, key)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if enc == "" {
				t.Fatal("Encrypt returned empty string")
			}

			dec, err := Decrypt(enc, key)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(dec, tt.plaintext) {
				t.Fatalf("roundtrip mismatch: got %q, want %q", dec, tt.plaintext)
			}
		})
	}
}

func TestDecryptInvalidInput(t *testing.T) {
	key := make([]byte, 32)

	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"not_base64", "!!!not-base64!!!"},
		{"too_short", "AA=="}, // decodes to 1 byte, shorter than nonce (12 bytes)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decrypt(tt.input, key)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	plain := []byte("secret data")
	enc, err := Encrypt(plain, key1)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt(enc, key2)
	if err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

func TestEncryptDifferentNonce(t *testing.T) {
	key := make([]byte, 32)
	plain := []byte("same plaintext")

	enc1, _ := Encrypt(plain, key)
	enc2, _ := Encrypt(plain, key)

	if enc1 == enc2 {
		t.Error("two encryptions of same plaintext produced identical ciphertext — nonce reuse?")
	}
}

func TestDeriveKey(t *testing.T) {
	// deterministic: same input → same key
	k1 := DeriveKey("password123", "sha256:abc", "cert-transport")
	k2 := DeriveKey("password123", "sha256:abc", "cert-transport")
	if !bytes.Equal(k1, k2) {
		t.Error("DeriveKey not deterministic")
	}

	// different inputs → different keys
	k3 := DeriveKey("password124", "sha256:abc", "cert-transport")
	if bytes.Equal(k1, k3) {
		t.Error("different passwords produced same key")
	}

	k4 := DeriveKey("password123", "sha256:abd", "cert-transport")
	if bytes.Equal(k1, k4) {
		t.Error("different fingerprints produced same key")
	}

	// domain separation: different purposes → different keys
	k5 := DeriveKey("password123", "sha256:abc", "config-cache")
	if bytes.Equal(k1, k5) {
		t.Error("different purposes produced same key — domain separation broken")
	}

	// output length
	if len(k1) != 32 {
		t.Errorf("DeriveKey length = %d, want 32", len(k1))
	}
}

func TestDeriveKeyCompatibility(t *testing.T) {
	// Ensure key derivation doesn't change — existing encrypted certs depend on this.
	// password="test", fingerprint="sha256:deadbeef", purpose="cert-transport"
	key := DeriveKey("test", "sha256:deadbeef", "cert-transport")
	// Golden value for HKDF-SHA256 (RFC 5869) key derivation.
	// Changing this breaks all existing encrypted cert deployments.
	expected := []byte{
		0x38, 0x03, 0x64, 0x74, 0x36, 0x25, 0xe6, 0x98,
		0xa0, 0xab, 0x85, 0xd0, 0x15, 0x67, 0xc5, 0xf5,
		0xe2, 0x95, 0x27, 0x6a, 0x07, 0xe5, 0xfd, 0xc3,
		0x22, 0x9b, 0x5f, 0x8a, 0x77, 0xd8, 0x32, 0xdb,
	}
	if !bytes.Equal(key, expected[:]) {
		t.Errorf("DeriveKey changed! got %x, this breaks existing cert deployments", key)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, 32)
	plain := bytes.Repeat([]byte("x"), 4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(plain, key)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := make([]byte, 32)
	plain := bytes.Repeat([]byte("x"), 4096)
	enc, _ := Encrypt(plain, key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(enc, key)
	}
}
