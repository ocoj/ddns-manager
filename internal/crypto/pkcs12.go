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
