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
//   - certPEM: PEM-encoded certificate chain (fullchain or leaf cert with intermediates)
//   - keyPEM:  PEM-encoded private key (RSA or ECDSA)
//   - password: PFX encryption password
//
// Returns the DER-encoded PKCS#12 container bytes (leaf cert + full CA chain + private key).
func GeneratePFX(certPEM, keyPEM []byte, password string) ([]byte, error) {
	// Decode all certificates from PEM (fullchain may contain leaf + intermediates)
	var certs []*x509.Certificate
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue // skip non-certificate PEM blocks
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("pkcs12: no valid certificates found in PEM")
	}

	leaf := certs[0]              // first cert is the leaf/server cert
	caCerts := certs[1:]           // rest are intermediate/root CA certs

	// Decode private key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("pkcs12: cannot decode private key PEM")
	}
	privKey, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: parse private key: %w", err)
	}

	// Build PKCS#12 container — 包含完整证书链，Windows 才能正确显示颁发者和信任链
	// go-pkcs12 Modern: PBES2 + HMAC-SHA-256 (非旧版 RC2/3DES)
	pfxData, err := pkcs12.Modern.Encode(privKey, leaf, caCerts, password)
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
