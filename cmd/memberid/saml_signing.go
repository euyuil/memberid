package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"

	"github.com/euyuil/memberid/internal/config"
)

func manageSAMLSigning(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("saml signing "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "protected installation directory")
	keyFile := flags.String("key-file", "", "candidate private key file relative to the installation directory")
	certificateFile := flags.String("certificate-file", "", "candidate certificate file relative to the installation directory")
	expected, backup := "", ""
	switch args[0] {
	case "inspect", "export-certificate":
	case "activate":
		flags.StringVar(&expected, "expected-sha256", "", "inspected current certificate SHA-256")
		flags.StringVar(&backup, "backup-file", "", "new configuration backup file relative to the installation directory")
	default:
		return errors.New("unknown SAML signing operation")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *directory == "" || flags.NArg() != 0 {
		return errors.New("SAML signing commands require --directory and flags only")
	}
	switch args[0] {
	case "inspect":
		result, err := config.InspectSAMLSigning(*directory, *keyFile, *certificateFile)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(result)
	case "export-certificate":
		public, err := config.ExportSAMLSigningCertificate(*directory, *keyFile, *certificateFile)
		if err != nil {
			return err
		}
		_, err = stdout.Write(public)
		return err
	default:
		result, err := config.ActivateSAMLSigning(*directory, *keyFile, *certificateFile, expected, backup)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(struct {
			config.SAMLSigningInspection
			RestartRequired bool `json:"restartRequired"`
		}{result, true})
	}
}
