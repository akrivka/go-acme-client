package main

import (
	"context"
	"log/slog"
	"time"

	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/dns01"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/http01"
)

func main() {
	// Hint: You may want to start by parsing command line arguments and
	// perform some sanity checks first. The built-in `argparse` library will suffice.

	go http01.HTTP01()
	go dns01.DNS01()
	// Hint: You will need more HTTP servers

	// Your code should go here

	// Prevent shutdown from being executed beofre the dns/http servers actually start
	time.Sleep(1 * time.Second)

	if err := http01.Server.Shutdown(context.Background()); err != nil {
		slog.Error("Error while stopping the http01 server", "err", err)
	}
	if err := dns01.Server.Shutdown(); err != nil {
		slog.Error("Error while stopping the dns01 server", "err", err)
	}
}
