package myserver

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "Hello world! TLS achieved?")
}

var Server *http.Server

func RunServer(record string, certPEM []byte, keyPEM []byte) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		slog.Error("Failed to parse certificates", "err", err)
	}
	Server = &http.Server{
		Addr:    record + ":5001",
		Handler: http.HandlerFunc(handler),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}
	slog.Info("Listening at ", "addr", record+":5001")
	if err := Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Could not start my-server", "err", err)
	}
}
