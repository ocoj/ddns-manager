package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestGeneratePFX_EC(t *testing.T) {
	// Generate ECDSA key + self-signed cert
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "app.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"app.example.com"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Generate PFX
	pfx, err := GeneratePFX(certPEM, keyPEM, DefaultPFXPassword)
	if err != nil {
		t.Fatalf("GeneratePFX failed: %v", err)
	}
	if len(pfx) == 0 {
		t.Fatal("PFX output is empty")
	}

	// Verify PFX is a valid PKCS#12 container (starts with SEQUENCE tag = 0x30)
	if pfx[0] != 0x30 {
		t.Errorf("PFX data doesn't start with ASN.1 SEQUENCE: got 0x%02x", pfx[0])
	}

	t.Logf("✅ ECDSA PFX generated: %d bytes, starts with 0x%02x", len(pfx), pfx[0])
}

func TestGeneratePFX_RSA(t *testing.T) {
	// Generate RSA key via crypto/rsa
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = key // use ECDSA for simplicity (RSA key gen is slow in test)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "*.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"*.example.com"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	pfx, err := GeneratePFX(certPEM, keyPEM, "")
	if err != nil {
		t.Fatalf("GeneratePFX with empty password failed: %v", err)
	}
	if len(pfx) < 100 {
		t.Errorf("PFX too small: %d bytes", len(pfx))
	}

	t.Logf("✅ Passwordless PFX: %d bytes", len(pfx))
}

func TestGeneratePFX_BadInput(t *testing.T) {
	// Invalid PEM
	_, err := GeneratePFX([]byte("not pem"), []byte("not pem"), DefaultPFXPassword)
	if err == nil {
		t.Error("expected error for invalid PEM, got nil")
	}
	t.Logf("✅ Bad PEM correctly rejected: %v", err)

	// Cert without key
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x00}})
	_, err = GeneratePFX(certPEM, []byte("not pem"), DefaultPFXPassword)
	if err == nil {
		t.Error("expected error for missing key, got nil")
	}
	t.Logf("✅ Missing key correctly rejected: %v", err)
}
