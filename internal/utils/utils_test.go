package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func selfSignedCert(t *testing.T, serial *big.Int, commonName string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func TestDeterministicGUIDIsStableAcrossCalls(t *testing.T) {
	first := DeterministicGUID("vault", "example.com")
	second := DeterministicGUID("vault", "example.com")
	if first != second {
		t.Fatalf("same input produced different GUIDs: %q and %q", first, second)
	}
}

func TestDeterministicGUIDSeparatesDifferentInputs(t *testing.T) {
	if DeterministicGUID("a", "b") == DeterministicGUID("b", "a") {
		t.Fatal("argument order must change the GUID")
	}
}

func TestGenerateRandomUUIDProducesDistinctValues(t *testing.T) {
	first := GenerateRandomUUID()
	second := GenerateRandomUUID()
	if first == second {
		t.Fatal("two calls returned the same UUID")
	}
}

func TestExtractSerialNumberFormatsAsLowerHexOctets(t *testing.T) {
	der := selfSignedCert(t, big.NewInt(0x0102ab), "example.com")

	got, err := ExtractSerialNumber(der)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "01:02:ab" {
		t.Fatalf("got %q, want %q", got, "01:02:ab")
	}
}

func TestExtractSerialNumberRejectsMalformedInput(t *testing.T) {
	if _, err := ExtractSerialNumber([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for malformed input, got nil")
	}
}

func TestExtractCommonNameReadsSubject(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "csr.example.com"}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}

	got, err := ExtractCommonName(csr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "csr.example.com" {
		t.Fatalf("got %q, want %q", got, "csr.example.com")
	}
}

func TestExtractCommonNameRejectsMalformedInput(t *testing.T) {
	if _, err := ExtractCommonName([]byte("not a CSR")); err == nil {
		t.Fatal("expected an error for malformed input, got nil")
	}
}

func TestGetCertificatesFromDerSplitsPEMChain(t *testing.T) {
	var chain []byte
	for _, cn := range []string{"first.example.com", "second.example.com"} {
		der := selfSignedCert(t, big.NewInt(1), cn)
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	certs, err := GetCertificatesFromDer(chain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certificates, want 2", len(certs))
	}
}

func TestGetCertificatesFromDerRejectsNonCertificateBlock(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})

	if _, err := GetCertificatesFromDer(block); err == nil {
		t.Fatal("expected an error for a non-certificate PEM block, got nil")
	}
}
