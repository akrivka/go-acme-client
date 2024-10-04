package http01

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
)

const prefix = "/.well-known/acme-challenge/"

var challResources map[string]string

var validReceived chan bool

func handler(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, prefix) {
		var token = r.URL.Path[len(prefix):]
		if keyAuthz := challResources[token]; keyAuthz != "" {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, keyAuthz)
			validReceived <- true
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func InstallResource(token string, keyAuthz string) {
	challResources[token] = keyAuthz
}

var Server *http.Server

func HTTP01(_validReceived chan bool) {
	challResources = make(map[string]string)
	validReceived = _validReceived

	Server = &http.Server{
		Addr:    "localhost:5002",
		Handler: http.HandlerFunc(handler),
	}
	if err := Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Could not start http01 server", "err", err)
	}
}
