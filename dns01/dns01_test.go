package dns01

import (
    "crypto/sha256"
    "encoding/base64"
    "testing"
)

func TestInstallResource(t *testing.T) {
    domain := "example.com"
    keyAuthz := "testkeyauthz"

    challResources = make(map[string]string)

    InstallResource(domain, keyAuthz)

    hashed := sha256.Sum256([]byte(keyAuthz))
    expected := base64.RawURLEncoding.EncodeToString(hashed[:])

    got, ok := challResources[domain]
    if !ok {
        t.Fatalf("domain not present in challResources map after InstallResource")
    }
    if got != expected {
        t.Fatalf("resource mismatch: got %s, want %s", got, expected)
    }
} 