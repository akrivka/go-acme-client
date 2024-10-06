package dns01

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	"github.com/miekg/dns"
)

const Prefix = "_acme-challenge."

var challResources map[string]string

var addr string

var validReceived chan bool

func handler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg).SetReply(r)

	for _, q := range m.Question {
		var rr dns.RR
		var err error
		if strings.HasPrefix(q.Name, Prefix) {
			// ACME challenge
			var domain = q.Name[len(Prefix) : len(q.Name)-1]
			if resource := challResources[domain]; resource != "" {
				slog.Info("(dns01) Replied to ACME challenge for", "domain", domain)
				rr, err = dns.NewRR(fmt.Sprintf("%s 300 IN TXT \"%s\"", q.Name, resource))
				validReceived <- true
			} else {
				slog.Error("(dns01) Received unknown ACME challenge")
				continue
			}
		} else {
			// Regular DNS query
			rr, err = dns.NewRR(fmt.Sprintf("%s A %s", q.Name, addr))
		}
		if err != nil {
			slog.Error("(dns01) Could not create Resource Record", "err", err)
			continue
		}
		m.Answer = append(m.Answer, rr)
	}

	w.WriteMsg(m)
}

func InstallResource(domain string, keyAtuhz string) {
	hashed := sha256.Sum256([]byte(keyAtuhz))
	resource := base64.RawURLEncoding.EncodeToString(hashed[:])
	challResources[domain] = resource
}

var Server *dns.Server

func DNS01(_addr string, _validReceived chan bool) {
	// Set global record that we should respond with to all DNS queries
	addr = _addr
	validReceived = _validReceived
	challResources = make(map[string]string)

	Server = &dns.Server{
		Addr:    addr + ":10053",
		Net:     "udp",
		Handler: dns.HandlerFunc(handler),
	}

	if err := Server.ListenAndServe(); err != nil {
		slog.Error("(dns01) Could not start dns01 server", "err", err)
	}
}
