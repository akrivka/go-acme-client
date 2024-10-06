package http01

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
)

const Prefix = "/.well-known/acme-challenge/"

var challResources map[string]string

var validReceived chan bool

func handler(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, Prefix) {
		var token = r.URL.Path[len(Prefix):]
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

func HTTP01(addr string, _validReceived chan bool) {
	validReceived = _validReceived
	challResources = make(map[string]string)

	Server = &http.Server{
		Addr:    addr + ":5002",
		Handler: http.HandlerFunc(handler),
	}
	if err := Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("(http01) Could not start http01 server", "err", err)
	}
}
