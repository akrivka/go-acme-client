/// This file defines the various message types used in the ACME protocol

package main

type ACMEProblem struct {
	Type        string `json:"type"`
	Detail      string `json:"detail"`
	Subproblems string `json:"subproblems"`
}

type ACMEMsg_NewAccount struct {
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	Contact              []string `json:"contact"`
}
