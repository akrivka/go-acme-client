package myserver

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	slog.Info("(myserver) Received an HTTPS request!", "method", r.Method, "url", r.URL.Path, "from", r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "Hello world! TLS achieved?")
}

var Server *http.Server

func RunServer(record string, certPEM []byte, keyPEM []byte) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		slog.Error("(myserver) Failed to parse certificates", "err", err)
	}

	addr := record + ":5001"
	Server = &http.Server{
		Addr:    addr,
		Handler: http.HandlerFunc(handler),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	slog.Info("(myserver) Listening at ", "addr", addr)
	if err := Server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		slog.Error("(myserver) Could not start my-server", "err", err)
	}
}
