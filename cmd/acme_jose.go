/// This file implements necessary JOSE functionality for ACME
/// It does not aim to be a general JOSE implementaion because
/// that would be outside the scope of this assignment
///
/// The use of RS256 is hard-coded and some not-so-great
/// global variable practices are used...

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// Helper function to make base64url encoding more concise
// and similar to the RFC spec
func base64url(s []byte) string {
	return base64.RawURLEncoding.EncodeToString(s)
}

// We choose to use RS256...
const Alg = "RS256"

// RSA public key encoding in the JWK format
type RSAPublicKey struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// RS256 private-public key pair
var jwkPrivate *rsa.PrivateKey
var jwkPublic RSAPublicKey
var jwkThumbprint string

// Account id
var acmeKid string

// JWS Object
type JWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// JWS Protected Header
type JWSProtected struct {
	Alg   string        `json:"alg"`
	Jwk   *RSAPublicKey `json:"jwk,omitempty"`
	Kid   string        `json:"kid,omitempty"`
	Nonce string        `json:"nonce"`
	Url   string        `json:"url"`
}

// Generate a key pair
func acmeJoseInit() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	panicIfError(err)
	jwkPrivate = privateKey

	//privateKey.PublicKey.E = 65537
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(privateKey.PublicKey.E))
	jwkPublic = RSAPublicKey{"RSA", base64url(privateKey.PublicKey.N.Bytes()), base64url(bytes.Trim(bs, "\x00"))}
	var jwkPublicLexi struct {
		E   string `json:"e"`
		Kty string `json:"kty"`
		N   string `json:"n"`
	}
	jwkPublicLexi.E = jwkPublic.E
	jwkPublicLexi.Kty = jwkPublic.Kty
	jwkPublicLexi.N = jwkPublic.N
	jwkPublicJson, err := json.Marshal(jwkPublicLexi)
	panicIfError(err)
	hashed := sha256.Sum256(jwkPublicJson)
	jwkThumbprint = base64url(hashed[:])
}

// Set account key id
// (this is technically unnecessary, since we're in the same package
// so we could just directly set acmeKid without using a setter
// but that... _feels_ unsafe, so this wrapper was introduced)
func acmeJoseSetKid(newKid string) {
	acmeKid = newKid
}

// Helper for acmeJwsSignJwk and acmeJwsSignKid
func acmeJwsSign(payload []byte, url string, nonce string) ([]byte, error) {
	var payload64 string
	if string(payload) != "" {
		payload64 = base64url(payload)
	}
	// Construct protected header
	var protected JWSProtected
	if acmeKid == "" {
		protected = JWSProtected{
			Alg:   Alg,
			Jwk:   &jwkPublic,
			Nonce: nonce,
			Url:   url,
		}
	} else {
		protected = JWSProtected{
			Alg:   Alg,
			Kid:   acmeKid,
			Nonce: nonce,
			Url:   url,
		}
	}
	protectedJson, err := json.Marshal(protected)
	if err != nil {
		return nil, err
	}

	// Compute signature
	signingInput := fmt.Sprintf("%s.%s", base64url(protectedJson), payload64)
	hashed := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(nil, jwkPrivate, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}

	// Construct JWS object
	acmeJws := JWS{base64url(protectedJson), payload64, base64url(signature)}
	// Encode it as JSON and return
	jwsJson, err := json.Marshal(acmeJws)
	if err != nil {
		return nil, err
	}
	return jwsJson, nil
}

func acmeKeyAuthz(token string) string {
	return fmt.Sprintf("%s.%s", token, jwkThumbprint)
}
