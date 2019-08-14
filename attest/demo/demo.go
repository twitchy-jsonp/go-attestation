// Binary demo demonstrates the attestation flow.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-attestation/attest"
)

var (
	keyfile = flag.String("keyfile", "aik.json", "Path to the AIK file.")
	addr    = flag.String("addr", "localhost:8030", "Address to listen on or make RPCs to.")
)

func main() {
	flag.Parse()
	if err := checkArgs(); err != nil {
		fmt.Fprintf(os.Stderr, "Bad invocation: %v.\n", err)
		printUsage()
		os.Exit(1)
	}

	// Handle running the server separately from other commands as there
	// is no need to open a TPM (and one is unlikely to be present).
	if flag.Arg(0) == "run-server" {
		if err := RunServer(*addr); err != nil {
			fmt.Fprintf(os.Stderr, "Server failed to start: %v", err)
			os.Exit(1)
		}
	}

	// Open a handle to the TPM device.
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

	// Run the client command.
	switch flag.Arg(0) {
	case "mint-aik":
		err = runMintAIK(tpm)
	case "attest":
		err = runAttest(tpm)
	case "activate-credential":
		err = runActivateCredential(tpm)
	default:
		printUsage()
		err = fmt.Errorf("unrecognised command: %q", flag.Arg(0))
	}
}

func checkArgs() error {
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
	fmt.Fprintln(os.Stderr, "  activate-credential - Activates the attestation key against the server.")
	fmt.Fprintln(os.Stderr, "  attest - Requests a nonce & submits a quote to the server.")
	fmt.Fprintln(os.Stderr)
}
