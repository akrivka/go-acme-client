package dns01

import (
	"fmt"
	"log/slog"

	"github.com/miekg/dns"
)

var record string

func handler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg).SetReply(r)

	for _, q := range m.Question {
		rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, record))
		if err != nil {
			slog.Error("Could not create Resource Record", "err", err)
			continue
		}
		m.Answer = append(m.Answer, rr)
	}

	w.WriteMsg(m)
}

var Server *dns.Server

func DNS01(_record string) {
	// Set global record that we should respond with to all DNS queries
	record = _record

	Server = &dns.Server{
		Addr:    record + ":10053",
		Net:     "udp",
		Handler: dns.HandlerFunc(handler),
	}

	if err := Server.ListenAndServe(); err != nil {
		slog.Error("Could not start dns01 server", "err", err)
	}
}
