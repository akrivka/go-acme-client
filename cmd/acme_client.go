package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jessevdk/go-flags"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/akrivka-acme-project/dns01"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/akrivka-acme-project/http01"
)

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}

// ACME server's directory URLs
type ACMEDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	NewAuthz   string `json:"newAuthz"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

// ACME server representation
type ACMEServer struct {
	Directory ACMEDirectory
	NextNonce string
}

// Our ACME server (currently we do not support trying multiple servers)
var server ACMEServer

// Our main HTTP client
var client *http.Client

// Types of challenges
const (
	ChallengeHTTP01 = "http01"
	ChallengeDNS01  = "dns01"
)

// Command-line arguments configuration for go-flags
var opts struct {
	ChallengeType string
	Directory     string   `long:"dir" description:"Directory URL of the ACME Server" required:"true"`
	IPV4Address   string   `long:"record" description:"IPv4 address to be returned by the DNS server" required:"true"`
	Domains       []string `long:"domain" description:"Domain for which to request certificate. Can have multiple --domain flags for multiple domains." required:"true"`
	Revoke        bool     `long:"revoke" description:"Should we revoke certificate after obtaining it"`
	CACert        string   `long:"cert" description:"Path to the CA certificate of the ACME server (added for local debugging with Pebble)" default:"project/pebble.minica.pem"`
}

// Parse command line arguments and store them in `opts` and `challengeType`
func parseCmdArgs() error {
	if len(os.Args) < 2 {
		return errors.New("missing challenge type argument")
	}

	// parse challenge type
	opts.ChallengeType = os.Args[1]
	if !(opts.ChallengeType == ChallengeHTTP01 || opts.ChallengeType == ChallengeDNS01) {
		return errors.New("invalid challenge type (http01 | dns01)")
	}

	// parse remaining arguments
	if _, err := flags.ParseArgs(&opts, os.Args[2:]); err != nil {
		return err
	}
	return nil
}

// Initialize the HTTP client and install ACME server's public certificate
func initHttpClient() error {
	caCert, err := os.ReadFile(opts.CACert)
	if err != nil {
		return err
	}
	serverCACertPool := x509.NewCertPool()
	serverCACertPool.AppendCertsFromPEM(caCert)
	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: serverCACertPool,
			},
		},
	}
	return nil
}

// Initialize global variable `server` with the server's directory URLs
// and fetch the first replay nonce
func initACMEServer() error {
	// Fetch the directory endpoint and save the urls
	res, err := client.Get(opts.Directory)
	if err != nil {
		return fmt.Errorf("directory HTTP call failed (%s)", err.Error())
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("directory HTTP call unexpected status code (%d)", res.StatusCode)
	}

	resBody, err := io.ReadAll(res.Body)
	panicIfError(err)

	err = json.Unmarshal(resBody, &server.Directory)
	if err != nil {
		return fmt.Errorf("failed to parse directory response body (%s)", err)
	}

	// Request our first nonce and save it
	res, err = client.Head(server.Directory.NewNonce)
	if err != nil {
		return fmt.Errorf("failed to get first nonce (%s)", err.Error())
	}
	server.NextNonce = res.Header["Replay-Nonce"][0]

	return nil
}

// Make a POST request to the ACME server
// This procedure is repeated many times during the process of obtaining
// CA certificate so that it's abstracted into a function here
// The function does all the error handling and returns (if desired status)
// the response body and the location header value (sometimes there's
// important stuff there)
func doAcmePost(url string, payload any, desiredStatus int) ([]byte, string, error) {
	// Prepare message
	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	messageJws, err := acmeJwsSignJwk(payloadJson, url, server.NextNonce)
	if err != nil {
		return nil, "", err
	}

	// POST!!
	res, err := client.Post(url, "application/jose+json", bytes.NewBuffer(messageJws))
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	panicIfError(err)

	if res.StatusCode != desiredStatus {
		var acmeProblem ACMEProblem
		err := json.Unmarshal(resBody, &acmeProblem)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read problem document (%s)", err.Error())
		} else {
			slog.Error("ACME problem", "type", acmeProblem.Type, "detail", acmeProblem.Detail)
			return nil, "", errors.New("logged ACME problem")
		}
	}
	server.NextNonce = res.Header["Replay-Nonce"][0] // Save replace nonce!

	return resBody, res.Header["Location"][0], nil
}

// Obtain CA certificate for specified domains
func obtainCertificate() error {
	// Initialize JOSE (generate key pair)
	acmeJoseInit()

	// Create new account
	_, account, err := doAcmePost(
		server.Directory.NewAccount,
		ACMEMsg_NewAccount{true, []string{"mailto:akrivka@student.ethz.ch"}},
		http.StatusCreated)
	if err != nil {
		return fmt.Errorf("failed to create new account (%s)", err.Error())
	}
	slog.Info("Created account", "url", account)

	// Create new order
	// TODO

	return nil
}

func main() {
	slog.Info("Starting the ACME client")

	if err := parseCmdArgs(); err != nil {
		slog.Error("Failed to parse cmd arguments", "error", err.Error())
		os.Exit(1)
	}

	if err := initHttpClient(); err != nil {
		slog.Error("Failed to read server CA certs", "error", err.Error())
		os.Exit(1)
	}

	if err := initACMEServer(); err != nil {
		slog.Error("Failed to read/initialize ACME server", "error", err.Error())
		os.Exit(1)
	}

	slog.Info("ACME Server connection initialized")

	// Start both challenge servers (doesn't really matter that we only use one)
	slog.Info("Starting HTTP-01 and DNS-01 challenge servers")
	go http01.HTTP01()
	go dns01.DNS01()

	// Wait a little bit for the servers to start...
	time.Sleep(1 * time.Second)

	slog.Info("Trying to obtain a certificate")
	if err := obtainCertificate(); err != nil {
		slog.Error("Failed to obtain certificate", "error", err.Error())
		os.Exit(1)
	}

	// Stop all servers
	if err := http01.Server.Shutdown(context.Background()); err != nil {
		slog.Error("Error while stopping the http01 server", "err", err)
	}
	if err := dns01.Server.Shutdown(); err != nil {
		slog.Error("Error while stopping the dns01 server", "err", err)
	}
}
