// Package crypto — PKCS#12 (PFX) generation for Windows certificate deployment.
// Uses pure Go go-pkcs12 library — zero external binary dependencies.
package crypto

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
)

// GeneratePFX creates a PKCS#12 (.pfx/.p12) container from PEM certificate and private key.
//
// On Windows, PFX is the native certificate import format (used by certlm.msc / PowerShell
// Import-PfxCertificate / netsh). By generating PFX once on the Manager side, Windows agents
// can use the fast importPFXToIIS path without depending on openssl.
//
// Parameters:
//   - certPEM: PEM-encoded certificate (fullchain or leaf cert)
//   - keyPEM:  PEM-encoded private key (RSA or ECDSA)
//   - password: PFX encryption password (use "" for no encryption; the PFX is
//     transmitted inside AES-256-GCM encrypted heartbeat, so PFX-level
//     encryption is defense-in-depth)
//
// Returns the DER-encoded PKCS#12 container bytes.
func GeneratePFX(certPEM, keyPEM []byte, password string) ([]byte, error) {
	// Decode certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("pkcs12: cannot decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: parse certificate: %w", err)
	}

	// Decode private key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("pkcs12: cannot decode private key PEM")
	}
	privKey, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: parse private key: %w", err)
	}

	// Build PKCS#12 container with modern algorithms (PBES2 + HMAC-SHA-256)
	// go-pkcs12 defaults to legacy RC2/3DES which is flagged by modern scanners;
	// we explicitly request modern ciphers.
	pfxData, err := pkcs12.Modern.Encode(privKey, cert, nil, password)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: encode: %w", err)
	}
	return pfxData, nil
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
