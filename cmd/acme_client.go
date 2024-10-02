package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/jessevdk/go-flags"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/akrivka-acme-project/dns01"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/akrivka-acme-project/http01"
)

// List of urls describing the ACME server
type ACMEServer struct {
	newNonce   string
	newAccount string
	newOrder   string
	newAuthz   string
	revokeCert string
	keyChange  string
}

// Types of challenges
const (
	ChallengeHTTP01 = "http01"
	ChallengeDNS01  = "dns01"
)

// Type of challenge we'll be using to prove ownership of domain
var challengeType string

// Our ACME Server (currently we do not support trying multiple servers)
var server ACMEServer

// Command-line arguments configuration for go-flags
var opts struct {
	Directory   string   `long:"dir" description:"Directory URL of the ACME Server"`
	IPV4Address string   `long:"record" description:"IPv4 address to be returned by the DNS server"`
	Domains     []string `long:"domain" description:"Domain for which to request certificate. Can have multiple --domain flags for multiple domains."`
	Revoke      bool     `long:"revoke" description:"Should we revoke certificate after obtaining it"`
}

func main() {
	slog.Info("Starting the ACME client")

	// Check validity of the challenge type
	challengeType = os.Args[1]
	if !(challengeType == ChallengeHTTP01 || challengeType == ChallengeDNS01) {
		slog.Error("Invalid challenge type (http01 | dns01)")
	}

	// Parse the remaining arguments
	flags.ParseArgs(&opts, os.Args[2:])

	// Start both challenge servers (doesn't really matter that we only use one)
	go http01.HTTP01()
	go dns01.DNS01()

	// Prevent shutdown from being executed beofre the dns/http servers actually start
	time.Sleep(1 * time.Second)

	// Stop all servers
	if err := http01.Server.Shutdown(context.Background()); err != nil {
		slog.Error("Error while stopping the http01 server", "err", err)
	}
	if err := dns01.Server.Shutdown(); err != nil {
		slog.Error("Error while stopping the dns01 server", "err", err)
	}
}
