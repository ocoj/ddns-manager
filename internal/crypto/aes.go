// Package crypto provides AES-256-GCM encryption for config and cert transport.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKey creates a 32-byte AES key from password, fingerprint, and purpose.
//
// Uses HKDF-SHA256 (RFC 5869) for standard key derivation:
//   - IKM:  password + \x00 + fingerprint (\x00 prevents boundary collisions)
//   - salt: nil (IKM has sufficient entropy — 32-char hex random password)
//   - info: purpose string for domain separation
//
// Domain separation ensures keys for different purposes are independent:
//   - "cert-transport"   → encrypting certs before push to agents
//   - "config-cache"     → encrypting DNS config cached on agent disk
//
// Both inputs are hex-encoded (0-9a-f only), so \x00 cannot appear in either.
//
// ⚠️ BREAKING CHANGE: adding HKDF + purpose changes all derived keys.
// All existing encrypted cert deployments must be re-issued after this change.
func DeriveKey(password, fingerprint, purpose string) []byte {
	ikm := []byte(password + "\x00" + fingerprint)
	reader := hkdf.New(sha256.New, ikm, nil, []byte(purpose))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		panic("hkdf: " + err.Error()) // cannot happen: SHA256 hash size (32) = key size (32)
	}
	return key
}

// Encrypt encrypts plaintext with AES-256-GCM using the given key.
// Returns base64(nonce + ciphertext + tag).
func Encrypt(plaintext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded AES-256-GCM ciphertext using the given key.
func Decrypt(b64 string, key []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
