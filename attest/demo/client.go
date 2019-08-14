package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
)

// runAttest is run when the demo is invoked with sub-command 'attest'.
func runAttest(tpm *attest.TPM) error {
	aik, err := loadAIK(tpm)
	if err != nil {
		return err
	}

	nonce, err := sendRequest("/get/attest-nonce", requestData{AIK: aik.AttestationParameters()})
	if err != nil {
		return err
	}

	pcrs, alg, err := tpm.PCRs()
	if err != nil {
		return fmt.Errorf("failed to read PCRs: %v", err)
	}
	outPCRs := map[uint32][]byte{}
	for _, p := range pcrs {
		outPCRs[uint32(p.Index)] = p.Digest
	}

	var attestAlg attest.HashAlg
	switch alg {
	case tpm2.AlgSHA256:
		attestAlg = attest.HashSHA256
	case tpm2.AlgSHA1:
		attestAlg = attest.HashSHA1
	default:
		return fmt.Errorf("unknown tpm2.Algorithm: %v", alg)
	}

	q, err := aik.Quote(tpm, nonce.Nonce, attestAlg)
	if err != nil {
		return fmt.Errorf("failed to generate quote: %v", err)
	}

	_, err = sendRequest("/do/attest", requestData{
		TPMVersion: tpm.Version(),
		AIK:        aik.AttestationParameters(),
		Quote:      *q,
		PCRs:       outPCRs,
	})
	return err
}

// runActivateCredential is run when the demo is invoked with sub-command
// 'activate-credential'.
func runActivateCredential(tpm *attest.TPM) error {
	aik, err := loadAIK(tpm)
	if err != nil {
		return err
	}

	ek, err := rsaEKPEM(tpm)
	if err != nil {
		return err
	}

	challenge, err := sendRequest("/get/activation-challenge", requestData{
		TPMVersion: tpm.Version(),
		EKPem:      ek,
		AIK:        aik.AttestationParameters(),
	})
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}

	secret, err := aik.ActivateCredential(tpm, challenge.ActivationChallenge)
	if err != nil {
		return fmt.Errorf("failed to activate credential: %v", err)
	}

	_, err = sendRequest("/do/activation", requestData{DecryptedCredential: secret, AIK: aik.AttestationParameters()})
	return err
}

func loadAIK(tpm *attest.TPM) (*attest.AIK, error) {
	d, err := ioutil.ReadFile(*keyfile)
	if err != nil {
		return nil, err
	}

	return tpm.LoadAIK(d)
}

func runMintAIK(tpm *attest.TPM) error {
	aik, err := tpm.MintAIK(nil)
	if err != nil {
		return err
	}
	defer aik.Close(tpm)

	d, err := aik.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal AIK: %v", err)
	}

	return ioutil.WriteFile(*keyfile, d, 0644)
}

func rsaEKPEM(tpm *attest.TPM) ([]byte, error) {
	eks, err := tpm.EKs()
	if err != nil {
		return nil, fmt.Errorf("failed to read EKs: %v", err)
	}

	var (
		pk  *rsa.PublicKey
		buf bytes.Buffer
	)
	for _, ek := range eks {
		if ek.Cert != nil && ek.Cert.PublicKeyAlgorithm == x509.RSA {
			pk = ek.Cert.PublicKey.(*rsa.PublicKey)
			break
		} else if ek.Public != nil {
			pk = ek.Public.(*rsa.PublicKey)
			break
		}
	}

	if pk == nil {
		return nil, errors.New("no EK available")
	}

	if err := pem.Encode(&buf, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pk)}); err != nil {
		return nil, fmt.Errorf("failed to PEM encode: %v", err)
	}
	return buf.Bytes(), nil
}
