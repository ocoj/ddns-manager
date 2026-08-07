// Package crypto — PKCS#12 (PFX) generation for Windows certificate deployment.
// Uses pure Go go-pkcs12 library — zero external binary dependencies.
package crypto

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// DefaultPFXPassword is the legacy fallback used when no explicit PFX password
// is configured. Kept for backward compatibility with existing certificates
// and as a last-resort fallback in agent certutil retry.
const DefaultPFXPassword = "ddns"

// GenerateRandomPFXPassword returns a 32-character random password
// (24 bytes base64-encoded). Returns "" on system entropy failure;
// callers should fallback to DefaultPFXPassword.
func GenerateRandomPFXPassword() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ParseCertAndKey decodes PEM-encoded certificate chain and private key,
// returning the leaf certificate, CA chain, and parsed private key.
// Used by GeneratePFX and GeneratePFXModern to avoid code duplication.
func ParseCertAndKey(certPEM, keyPEM []byte) (leaf *x509.Certificate, caCerts []*x509.Certificate, privKey any, err error) {
	var certs []*x509.Certificate
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			continue
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, nil, nil, fmt.Errorf("pkcs12: no valid certificates found in PEM")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, nil, fmt.Errorf("pkcs12: cannot decode private key PEM")
	}
	key, e := parsePrivateKey(keyBlock.Bytes)
	if e != nil {
		return nil, nil, nil, fmt.Errorf("pkcs12: parse private key: %w", e)
	}

	return certs[0], certs[1:], key, nil
}

// GeneratePFX creates a LegacyDES PKCS#12 container (3DES+SHA1).
// Compatible with Windows 7 through Windows 11. Equivalent to OpenSSL -descert.
// Use this for maximum compatibility; use GeneratePFXModern for stronger encryption.
func GeneratePFX(certPEM, keyPEM []byte, password string) ([]byte, error) {
	leaf, caCerts, privKey, err := ParseCertAndKey(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	pfxData, err := pkcs12.LegacyDES.Encode(privKey, leaf, caCerts, password)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: encode: %w", err)
	}
	return pfxData, nil
}

// GeneratePFXModern creates a Modern PKCS#12 container (PBES2 + AES-256 + HMAC-SHA-256).
// Only compatible with Windows 10 1809+ / Windows 11 / Windows Server 2019+.
// Provides stronger encryption at rest (AES-256 vs 3DES).
func GeneratePFXModern(certPEM, keyPEM []byte, password string) ([]byte, error) {
	leaf, caCerts, privKey, err := ParseCertAndKey(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	pfxData, err := pkcs12.Modern.Encode(privKey, leaf, caCerts, password)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: modern encode: %w", err)
	}
	return pfxData, nil
}

// ParsePFXLeafChain decodes a PKCS#12 container and returns its leaf certificate
// and CA chain. Used by the bundle consistency check (v9 §4.1).
//
// IMPORTANT: must use DecodeChain — pkcs12.Decode only returns (key, cert, err)
// and silently drops any additional certificates shipped in the container.
func ParsePFXLeafChain(pfxData []byte, password string) (leaf *x509.Certificate, caCerts []*x509.Certificate, err error) {
	_, leaf, caCerts, err = pkcs12.DecodeChain(pfxData, password)
	return leaf, caCerts, err
}

// ClassifyPFXError maps a PKCS#12 decode error to a short human description used
// in audit messages. Distinguishing "wrong password" from "corrupt container"
// matters operationally: the former may be fixed by correcting meta.pfx_password,
// the latter needs the container replaced.
func ClassifyPFXError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, pkcs12.ErrIncorrectPassword) {
		return "密码不符（候选密码均已尝试）"
	}
	if errors.Is(err, pkcs12.ErrDecryption) {
		return "容器损坏/解密失败"
	}
	return "容器损坏/格式异常: " + err.Error()
}

// IsKeyPEM reports whether name/content look like a private key.
func IsKeyPEM(name string, content []byte) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".key") || strings.Contains(string(content), "PRIVATE KEY")
}

// IsCertPEM reports whether name looks like a certificate PEM file.
func IsCertPEM(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".crt") || strings.HasSuffix(lower, ".cer")
}

// PickCertPEM deterministically selects the certificate PEM used as the PFX
// certificate source (invariant I24). Rules, in order:
//
//  1. a file whose name contains "fullchain" (carries the complete chain)
//  2. otherwise the lexicographically smallest .pem/.crt/.cer name that is not a
//     private key
//  3. otherwise nil
//
// It must never depend on Go map iteration order: the previous per-caller
// implementations ranged over map[string][]byte, which made the chain length of
// the generated PFX non-deterministic (U4).
func PickCertPEM(files map[string][]byte) []byte {
	if len(files) == 0 {
		return nil
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if strings.Contains(strings.ToLower(name), "fullchain") && !IsKeyPEM(name, files[name]) {
			return files[name]
		}
	}
	for _, name := range names {
		if IsCertPEM(name) && !IsKeyPEM(name, files[name]) {
			return files[name]
		}
	}
	return nil
}

// ParseCertChainPEM parses every CERTIFICATE block of a PEM buffer in file
// order (leaf first for a fullchain). Used by the bundle consistency check.
func ParseCertChainPEM(pemData []byte) []*x509.Certificate {
	var out []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		out = append(out, cert)
	}
	return out
}

// parsePrivateKey decodes a DER-encoded private key (PKCS#1, PKCS#8, or EC).
func parsePrivateKey(der []byte) (any, error) {
	// Try PKCS#8 first (most common)
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	// Try PKCS#1 RSA
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	// Try EC
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key format")
}

// Ensure rand is imported (pkcs12.Modern.Encode uses it internally).
var _ = rand.Reader
