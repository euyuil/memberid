package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"

	"github.com/euyuil/memberid/internal/config"
)

type repeatedFlag []string

func (values *repeatedFlag) String() string         { return "" }
func (values *repeatedFlag) Set(value string) error { *values = append(*values, value); return nil }

func configure(args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: memberid config <init|check> | client <add|rotate-secret>")
	}
	flags := flag.NewFlagSet(args[0]+" "+args[1], flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "protected installation directory")
	switch args[0] {
	case "config":
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
		return json.NewEncoder(stdout).Encode(map[string]any{"valid": true, "issuer": loaded.Issuer, "keyId": loaded.KeyID, "clients": len(loaded.Clients)})
	case "client":
		if args[1] != "add" && args[1] != "rotate-secret" {
			return errors.New("unknown client operation")
		}
		var client config.Client
		flags.StringVar(&client.ID, "id", "", "client identifier")
		var redirects, logouts, accountReturns repeatedFlag
		if args[1] == "add" {
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
		if *directory == "" || client.ID == "" || flags.NArg() != 0 {
			return errors.New("--directory and --id are required; positional arguments are not accepted")
		}
		secret := config.RandomSecret()
		client.SecretSHA256 = config.SecretHash(secret)
		client.RedirectURIs, client.PostLogoutRedirectURIs, client.AccountReturnURIs = redirects, logouts, accountReturns
		err := config.ChangeClients(*directory, func(clients []config.Client) ([]config.Client, error) {
			for index := range clients {
				if clients[index].ID == client.ID {
					if args[1] == "add" {
						return nil, errors.New("client already exists")
					}
					clients[index].SecretSHA256 = client.SecretSHA256
					return clients, nil
				}
			}
			if args[1] == "rotate-secret" {
				return nil, errors.New("client not found")
			}
			return append(clients, client), nil
		})
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(map[string]string{"client_id": client.ID, "client_secret": secret})
	}
	return errors.New("unknown configuration command")
}
