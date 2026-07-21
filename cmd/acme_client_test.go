package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestCACert(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-ca",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create test CA certificate: %v", err)
	}

	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	if certificatePEM == nil {
		t.Fatal("failed to encode test CA certificate")
	}

	certificatePath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		t.Fatalf("failed to write test CA certificate: %v", err)
	}

	return certificatePath
}

func TestInitHttpClientEnforcesTLS13(t *testing.T) {
	oldCACert := opts.CACert
	oldClient := client
	t.Cleanup(func() {
		opts.CACert = oldCACert
		client = oldClient
	})

	opts.CACert = writeTestCACert(t)

	if err := initHttpClient(); err != nil {
		t.Fatalf("initHttpClient returned error: %v", err)
	}

	if client == nil {
		t.Fatal("initHttpClient did not initialize the HTTP client")
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client transport has unexpected type %T", client.Transport)
	}

	if transport.TLSClientConfig == nil {
		t.Fatal("client transport is missing TLS configuration")
	}

	if got := transport.TLSClientConfig.MinVersion; got != tls.VersionTLS13 {
		t.Fatalf("unexpected TLS minimum version: got %d want %d", got, tls.VersionTLS13)
	}

	if transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("client TLS root CA pool is missing")
	}

	if got := len(transport.TLSClientConfig.RootCAs.Subjects()); got == 0 {
		t.Fatal("client TLS root CA pool was not populated")
	}
}
