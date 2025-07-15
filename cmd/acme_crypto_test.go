package main

import (
    "crypto"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "testing"
)

func TestBase64url(t *testing.T) {
    input := []byte("hello world")
    expected := base64.RawURLEncoding.EncodeToString(input)
    got := base64url(input)
    if got != expected {
        t.Fatalf("base64url encoding mismatch: expected %s, got %s", expected, got)
    }
}

// helper to verify JWS signature produced by acmeJwsSign
func verifyJwsSignature(jwsBytes []byte) error {
    var jws JWS
    if err := json.Unmarshal(jwsBytes, &jws); err != nil {
        return fmt.Errorf("failed to unmarshal JWS: %w", err)
    }

    signingInput := fmt.Sprintf("%s.%s", jws.Protected, jws.Payload)
    hashed := sha256.Sum256([]byte(signingInput))

    sigBytes, err := base64.RawURLEncoding.DecodeString(jws.Signature)
    if err != nil {
        return fmt.Errorf("failed to decode signature: %w", err)
    }

    // accountPublic is populated by acmeJoseInit
    if accountPublic == nil {
        return fmt.Errorf("accountPublic is nil – acmeJoseInit was not called")
    }

    if err := rsa.VerifyPKCS1v15(accountPublic, crypto.SHA256, hashed[:], sigBytes); err != nil {
        return fmt.Errorf("signature verification failed: %w", err)
    }
    return nil
}

func TestAcmeJwsSignAndVerify(t *testing.T) {
    acmeJoseInit()

    payload := []byte(`{"foo":"bar"}`)
    url := "https://example.com/acme"
    nonce := "NONCE123"

    jwsBytes, err := acmeJwsSign(payload, url, nonce)
    if err != nil {
        t.Fatalf("acmeJwsSign returned error: %v", err)
    }

    // verify signature
    if err := verifyJwsSignature(jwsBytes); err != nil {
        t.Fatalf("JWS verification failed: %v", err)
    }

    // sanity-check protected header fields
    var jws JWS
    if err := json.Unmarshal(jwsBytes, &jws); err != nil {
        t.Fatalf("failed to unmarshal JWS: %v", err)
    }

    protectedBytes, err := base64.RawURLEncoding.DecodeString(jws.Protected)
    if err != nil {
        t.Fatalf("failed to decode protected header: %v", err)
    }

    var protected JWSProtected
    if err := json.Unmarshal(protectedBytes, &protected); err != nil {
        t.Fatalf("failed to unmarshal protected header: %v", err)
    }

    if protected.Alg != Alg {
        t.Errorf("unexpected alg, want %s got %s", Alg, protected.Alg)
    }
    if protected.Url != url {
        t.Errorf("unexpected url, want %s got %s", url, protected.Url)
    }
    if protected.Nonce != nonce {
        t.Errorf("unexpected nonce, want %s got %s", nonce, protected.Nonce)
    }
}

func TestGenerateCsr(t *testing.T) {
    domains := []string{"example.com", "www.example.com"}
    csrDER, keyPEM, err := generateCsr(domains)
    if err != nil {
        t.Fatalf("generateCsr returned error: %v", err)
    }

    if len(csrDER) == 0 {
        t.Fatalf("CSR DER is empty")
    }
    if len(keyPEM) == 0 {
        t.Fatalf("key PEM is empty")
    }

    // Parse CSR to verify fields
    csr, err := x509.ParseCertificateRequest(csrDER)
    if err != nil {
        t.Fatalf("failed to parse CSR: %v", err)
    }

    if err := csr.CheckSignature(); err != nil {
        t.Fatalf("CSR signature invalid: %v", err)
    }

    if len(csr.DNSNames) != len(domains) {
        t.Fatalf("CSR DNSNames length mismatch, got %d want %d", len(csr.DNSNames), len(domains))
    }

    for i, d := range domains {
        if csr.DNSNames[i] != d {
            t.Errorf("CSR DNSNames[%d] = %s, want %s", i, csr.DNSNames[i], d)
        }
    }
} 