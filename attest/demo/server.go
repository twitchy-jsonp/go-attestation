package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-attestation/verifier"

	tpb "github.com/google/go-attestation/proto"
	vpb "github.com/google/go-attestation/verifier/proto"
)

// clientInfo keeps track of state relevant to a remote attestation client.
// A single clientInfo should correspond to one AIK, of which there are
// one or many AIKs per device.
type clientInfo struct {
	AIK attest.AttestationParameters
	EK  *rsa.PublicKey

	ActivationSecret []byte
	Activated        bool

	Nonce []byte

	AttestResults *vpb.QuoteVerificationResults
}

type server struct {
	// state stores information about the clients the server has seen. In a
	// real server, state would probably be stored in a database.
	state []clientInfo
	lock  sync.Mutex

	s http.Server
}

// Close shuts down the server.
func (s *server) Close() error {
	return s.s.Close()
}

// clientInfo returns a structure to store state about the client in.
// This method is not thread-safe.
func (s *server) clientInfo(pub []byte) *clientInfo {
	for i := range s.state {
		if bytes.Equal(s.state[i].AIK.Public, pub) {
			return &s.state[i]
		}
	}

	s.state = append(s.state, clientInfo{AIK: attest.AttestationParameters{Public: pub}})
	return &s.state[len(s.state)-1]
}

// activationGetChallenge handles RPCs to /get/activation-challenge.
func (s *server) activationGetChallenge(w http.ResponseWriter, r *http.Request) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Decode the request.
	rd, err := unmarshalRequestBody(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[activationGetChallenge] Failed to unmarshal request: %v\n", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	ek, err := rd.EKPublic()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[activationGetChallenge] Failed to unmarshal ek: %v\n", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate the activation challenge.
	ap := attest.ActivationParameters{
		TPMVersion: rd.TPMVersion,
		EK:         ek,
		AIK:        rd.AIK,
	}
	secret, ec, err := ap.Generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[activationGetChallenge] Failed to generate activation challenge: %v\n", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Store the secret & update the state in the server.
	c := s.clientInfo(rd.AIK.Public)
	c.AIK = rd.AIK
	c.ActivationSecret = secret
	c.EK = ek
	c.Activated = false

	fmt.Printf("Generated activation challenge for %x\n", sha256.Sum256(rd.AIK.Public))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responseData{ActivationChallenge: *ec})
}

// activate handles RPCs to /do/activation.
func (s *server) activate(w http.ResponseWriter, r *http.Request) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Decode the request.
	rd, err := unmarshalRequestBody(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[activate] Failed to unmarshal request: %v\n", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	c := s.clientInfo(rd.AIK.Public)

	// Return an error if no challenge was requested, or an incorrect
	// credential was provided.
	if len(c.ActivationSecret) == 0 || !bytes.Equal(c.ActivationSecret, rd.DecryptedCredential) {
		http.Error(w, "Activation failed", http.StatusBadRequest)
		fmt.Printf("Activation failed for %x\n", sha256.Sum256(rd.AIK.Public))
		return
	}

	// If we got here, credential activation succeeded.
	c.Activated = true
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responseData{})
	fmt.Printf("Activation succeeded for %x\n", sha256.Sum256(rd.AIK.Public))
}

// getNonce handles RPCs to /get/attest-nonce.
func (s *server) getNonce(w http.ResponseWriter, r *http.Request) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Decode the request.
	rd, err := unmarshalRequestBody(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[getNonce] Failed to unmarshal request: %v\n", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	c := s.clientInfo(rd.AIK.Public)

	// Generate a random nonce.
	n := make([]byte, 32)
	io.ReadFull(rand.Reader, n)

	c.Nonce = n
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responseData{Nonce: n})
	fmt.Printf("Sent nonce to %x\n", sha256.Sum256(rd.AIK.Public))
}

// attest handles RPCs to /do/attest.
func (s *server) attest(w http.ResponseWriter, r *http.Request) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Decode the request.
	rd, err := unmarshalRequestBody(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[getNonce] Failed to unmarshal request: %v\n", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	c := s.clientInfo(rd.AIK.Public)
	qVerification, err := verifier.VerifyQuote(tpb.TpmVersion(rd.TPMVersion), rd.AIK.Public, rd.Quote.Quote, rd.Quote.Signature, rd.PCRs, c.Nonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[attest] Failed to verify quote: %v\n", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	fmt.Printf("Quote verification for %x:\n  %+v\n", sha256.Sum256(rd.AIK.Public), qVerification)
	c.AttestResults = qVerification

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responseData{})
}

// RunServer creates and starts a remote attestation server on the specified
// listening port & optional interface.
func RunServer(listeningAddr string) error {
	mux := http.NewServeMux()
	s := &server{
		s: http.Server{
			Addr:    listeningAddr,
			Handler: mux,
		},
	}

	mux.HandleFunc("/get/activation-challenge", s.activationGetChallenge)
	mux.HandleFunc("/do/activation", s.activate)
	mux.HandleFunc("/get/attest-nonce", s.getNonce)
	mux.HandleFunc("/do/attest", s.attest)
	return s.s.ListenAndServe()
}
