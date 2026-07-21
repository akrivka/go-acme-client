package myserver

import (
	"crypto/tls"
	"testing"
)

func TestNewServerEnforcesTLS13(t *testing.T) {
	server := newServer("127.0.0.1:5001", tls.Certificate{})
	if server.TLSConfig == nil {
		t.Fatal("expected TLSConfig to be configured")
	}
	if server.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("expected minimum TLS version %v, got %v", tls.VersionTLS13, server.TLSConfig.MinVersion)
	}
	if len(server.TLSConfig.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(server.TLSConfig.Certificates))
	}
}
