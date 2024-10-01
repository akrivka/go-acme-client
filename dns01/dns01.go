package dns01

import (
	"fmt"
	"log/slog"

	"github.com/miekg/dns"
)

func handler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg).SetReply(r)

	for _, q := range m.Question {
		rr, err := dns.NewRR(fmt.Sprintf("%s A 1.2.3.4", q.Name))
		if err != nil {
			slog.Error("Could not create Resource Record", "err", err)
			continue
		}
		m.Answer = append(m.Answer, rr)
	}

	w.WriteMsg(m)
}

var Server *dns.Server

func DNS01() {
	Server = &dns.Server{
		Addr:    "0.0.0.0:10053",
		Net:     "udp",
		Handler: dns.HandlerFunc(handler),
	}

	if err := Server.ListenAndServe(); err != nil {
		slog.Error("Could not start dns01 server", "err", err)
	}
}
