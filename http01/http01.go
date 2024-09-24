package http01

import (
	"io"
	"log/slog"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusAccepted)
	io.WriteString(w, "Hello World!")
}

var Server *http.Server

func HTTP01() {
	Server = &http.Server{
		Addr:    "0.0.0.0:5002",
		Handler: http.HandlerFunc(handler),
	}
	if err := Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Could not start http01 server", "err", err)
	}
}
