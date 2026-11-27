package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/sms"
)

type repeatedFlag []string

func (values *repeatedFlag) String() string         { return "" }
func (values *repeatedFlag) Set(value string) error { *values = append(*values, value); return nil }

func configure(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: memberid config <init|check|export-jwks|rotate-management-secret> | client <add|rotate-secret>")
	}
	flags := flag.NewFlagSet(args[0]+" "+args[1], flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "protected installation directory")
	switch args[0] {
	case "config":
		if args[1] == "export-jwks" {
			if err := flags.Parse(args[2:]); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return nil
				}
				return err
			}
			if *directory == "" || flags.NArg() != 0 {
				return errors.New("--directory is required; positional arguments are not accepted")
			}
			loaded, err := config.Load(*directory)
			if err != nil {
				return err
			}
			return json.NewEncoder(stdout).Encode(loaded.JWKS())
		}
		if args[1] == "rotate-management-secret" {
			outputFile := flags.String("output-file", "", "new credential file in a protected directory; existing files are refused")
			if err := flags.Parse(args[2:]); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return nil
				}
				return err
			}
			if *directory == "" || *outputFile == "" || flags.NArg() != 0 {
				return errors.New("--directory and --output-file are required; positional arguments are not accepted")
			}
			if err := config.RotateManagementSecret(*directory, *outputFile); err != nil {
				return err
			}
			return json.NewEncoder(stdout).Encode(map[string]bool{"rotated": true, "restartRequired": true})
		}
		if args[1] != "init" && args[1] != "check" {
			return errors.New("unknown configuration operation")
		}
		issuer := flags.String("issuer", "", "exact public HTTPS issuer origin")
		loopback := flags.Bool("allow-loopback-http", false, "allow 127.0.0.1 HTTP for development")
		if err := flags.Parse(args[2:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if *directory == "" || flags.NArg() != 0 {
			return errors.New("--directory is required; positional arguments are not accepted")
		}
		if args[1] == "init" {
			if err := config.Initialize(*directory, *issuer, *loopback); err != nil {
				return err
			}
		} else if *issuer != "" || *loopback {
			return errors.New("config check reads the existing installation")
		}
		loaded, err := config.Load(*directory)
		if err != nil {
			return err
		}
		phone, err := sms.FromEnvironment(os.Getenv)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(map[string]any{"valid": true, "issuer": loaded.Issuer, "keyId": loaded.KeyID, "phoneEnabled": phone != nil})
	case "client":
		if args[1] != "add" && args[1] != "rotate-secret" {
			return errors.New("unknown client operation")
		}
		var client identity.OIDCClient
		var system bool
		var displayName, ownerOrganizationID string
		if args[1] == "rotate-secret" {
			flags.StringVar(&client.ID, "id", "", "assigned client identifier")
		}
		var redirects, logouts, accountReturns repeatedFlag
		if args[1] == "add" {
			flags.BoolVar(&system, "system", false, "protect an all-organization console client from administrative mutation")
			flags.StringVar(&displayName, "name", "", "application display name (defaults to the generated ID)")
			flags.StringVar(&ownerOrganizationID, "owner-organization", identity.SystemOrganizationID, "organization that owns the registration")
			flags.Var(&redirects, "redirect", "exact callback URL; repeat for multiple URLs")
			flags.Var(&logouts, "post-logout-redirect", "exact post-logout URL")
			flags.Var(&accountReturns, "account-return", "exact account-management return URL")
			flags.StringVar(&client.OrganizationID, "organization", "", "restrict login to one organization")
			flags.StringVar(&client.SubjectKind, "subject", "member", "member, or explicitly authorized factor identity")
			flags.StringVar(&client.EvidenceScope, "evidence-scope", "", "custom scope releasing identity evidence")
			flags.StringVar(&client.EvidenceAudience, "evidence-audience", "", "fixed resource audience for identity evidence")
			flags.BoolVar(&client.Refresh, "refresh", false, "allow standard refresh grants")
			flags.BoolVar(&client.Preauthorized, "preauthorized", false, "operator grants consent to registered scope policy")
		}
		if err := flags.Parse(args[2:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if *directory == "" || (args[1] == "rotate-secret" && client.ID == "") || flags.NArg() != 0 {
			return errors.New("provide --directory and, for rotate-secret, --id; positional arguments are not accepted")
		}
		secret := config.RandomSecret()
		client.SecretSHA256 = config.SecretHash(secret)
		client.RedirectURIs, client.PostLogoutRedirectURIs, client.AccountReturnURIs = redirects, logouts, accountReturns
		installation, err := config.Load(*directory)
		if err != nil {
			return err
		}
		store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
		if err != nil {
			return err
		}
		defer store.Close()
		principal := identity.OperatorPrincipal()
		if args[1] == "add" {
			var application identity.OIDCApplication
			application, err = store.CreateOIDCClient(ctx, principal, identity.OIDCClientRegistration{
				Client: client, DisplayName: displayName, System: system, OwnerOrganizationID: ownerOrganizationID,
			}, installation.AllowLoopbackHTTP)
			client.ID = application.ClientID
		} else {
			_, err = store.RotateOIDCClientSecret(ctx, principal, client.ID, 0, client.SecretSHA256)
		}
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(map[string]string{"client_id": client.ID, "client_secret": secret})
	}
	return errors.New("unknown configuration command")
}
