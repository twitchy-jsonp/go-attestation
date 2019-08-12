// Binary client demonstrates how to build a remote attestation client.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/go-attestation/attest"
)

var (
	addr    = flag.String("addr", "http://localhost:8080", "HTTP endpoint of the attestation server.")
	keyfile = flag.String("keyfile", "aik.json", "Path to the AIK file.")
)

func main() {
	flag.Parse()
	if err := checkArgs(); err != nil {
		fmt.Fprintf(os.Stderr, "Bad invocation: %v.\n", err)
		printUsage()
		os.Exit(1)
	}

	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open TPM: %v", err)
		os.Exit(1)
	}

	defer func() {
		tpm.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}()

	switch flag.Arg(0) {
	case "mint-aik":
		err = runMintAIK(tpm)
	case "attest":
		err = runAttest(tpm)
	case "get-info":
		err = runGetInfo(tpm)
	default:
		printUsage()
		err = fmt.Errorf("unrecognised command: %q", flag.Arg(0))
	}
}

func checkArgs() error {
	if *addr == "" {
		return errors.New("addr must be specified")
	}
	if *keyfile == "" {
		return errors.New("keyfile must be specified")
	}

	if flag.NArg() < 1 {
		return errors.New("sub-command must be specified")
	}
	return nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "USAGE: ./%s [-addr <endpoint] [-keyfile <path>] <command>\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "COMMANDS:")
	fmt.Fprintln(os.Stderr, "  mint-aik - Creates an attestation key, storing it in the parameter given by -keyfile.")
	fmt.Fprintln(os.Stderr, "  get-info - Dumps the parameters of the key given by -keyfile to stdout.")
	fmt.Fprintln(os.Stderr)
}

func runAttest(tpm *attest.TPM) error {
	return nil
}

func runGetInfo(tpm *attest.TPM) error {
	aik, err := loadAIK(tpm)
	if err != nil {
		return err
	}

	ap := aik.AttestationParameters()
	fmt.Printf("public blob: %x\n", ap.Public)
	fmt.Printf("using tcsd: %t\n", ap.UseTCSDActivationFormat)
	fmt.Printf("creation blob: %x\n", ap.CreateData)
	fmt.Printf("attestation blob: %x\n", ap.CreateAttestation)
	fmt.Printf("signature blob: %x\n", ap.CreateSignature)
	return nil
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
