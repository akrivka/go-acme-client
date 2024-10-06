/// This file defines the various message types used in the ACME protocol

package main

// REQUESTS

type ACMEMsg_NewAccount struct {
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	Contact              []string `json:"contact"`
}

type ACMEIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type ACMEMsg_NewOrder struct {
	Identifiers []ACMEIdentifier `json:"identifiers"`
	NotBefore   string           `json:"notBefore,omitempty"`
	NotAfter    string           `json:"notAfter,omitempty"`
}

type ACMEMsg_Finalize struct {
	CSR string `json:"csr"`
}

// RESPONSES
type ACMEProblem struct {
	Type        string `json:"type"`
	Detail      string `json:"detail"`
	Subproblems string `json:"subproblems"`
}

type ACMEOrder struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
}

type ACMEChallenge struct {
	Type  string `json:"type"`
	Url   string `json:"url"`
	Token string `json:"token"`
}

type ACMEAuthorization struct {
	Status     string          `json:"status"`
	Identifier ACMEIdentifier  `json:"identifier"`
	Challenges []ACMEChallenge `json:"challenges"`
}
