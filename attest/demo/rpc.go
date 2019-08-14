package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"crypto/x509"
	"github.com/google/go-attestation/attest"
)

// requestData describes the format which clients marshal request data to.
// This struct is marshalled to JSON and HTTP-POST'ed to server endpoints.
// Only fields relevant to the request will be populated.
type requestData struct {
	TPMVersion attest.TPMVersion
	AIK        attest.AttestationParameters

	EKPem               []byte
	DecryptedCredential []byte

	Quote attest.Quote
	PCRs  map[uint32][]byte
}

func (rd requestData) EKPublic() (*rsa.PublicKey, error) {
	b, _ := pem.Decode(rd.EKPem)
	return x509.ParsePKCS1PublicKey(b.Bytes)
}

func unmarshalRequestBody(r *http.Request) (*requestData, error) {
	var rd requestData
	return &rd, json.NewDecoder(r.Body).Decode(&rd)
}

// responseData describes the format the server will marshal RPC responses in.
// This struct is marshalled to JSON and sent as the HTTP response content.
// Only fields relevant to the request will be populated.
type responseData struct {
	ActivationChallenge attest.EncryptedCredential

	Nonce []byte
}

// sendRequest is invoked by the client to send an RPC to the server.
func sendRequest(endpoint string, request requestData) (*responseData, error) {
	var (
		buf bytes.Buffer
		out responseData
	)

	if err := json.NewEncoder(&buf).Encode(request); err != nil {
		return nil, err
	}
	resp, err := http.Post("http://"+*addr+endpoint, "application/json", &buf)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%v failed: %v", endpoint, resp.Status)
	}

	return &out, json.NewDecoder(resp.Body).Decode(&out)
}
