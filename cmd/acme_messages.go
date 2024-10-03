package main

type ACMEProblem struct {
	Type        string `json:"type"`
	Detail      string `json:"detail"`
	Subproblems string `json:"subproblems"`
}
