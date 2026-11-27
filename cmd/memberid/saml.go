package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/identity"
)

func manageSAML(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: memberid saml sp <apply|list|inspect|disable|retire|enable-use|withdraw-use> or saml signing <inspect|export-certificate|activate> or saml nameid <inspect|provision>")
	}
	if args[0] == "signing" {
		return manageSAMLSigning(args[1:], stdout, stderr)
	}
	if args[0] == "nameid" {
		return manageSAMLNameID(ctx, args[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("saml "+args[0]+" "+args[1], flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "protected installation directory")
	id, file, organizationID := "", "", ""
	revision := int64(0)
	if args[0] == "sp" {
		switch args[1] {
		case "apply":
			flags.StringVar(&file, "file", "", "registration JSON; revision zero creates")
		case "enable-use", "withdraw-use":
			flags.StringVar(&id, "id", "", "registered service provider ID")
			flags.StringVar(&organizationID, "organization", "", "consumer organization ID")
		case "inspect", "disable", "retire":
			flags.StringVar(&id, "id", "", "registered service provider ID")
			if args[1] != "inspect" {
				flags.Int64Var(&revision, "revision", 0, "expected current revision")
			}
		case "list":
		default:
			return errors.New("unknown SAML SP operation")
		}
	} else {
		return errors.New("unknown SAML operation")
	}
	if err := flags.Parse(args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || *directory == "" {
		return errors.New("SAML commands require --directory and flags only")
	}
	loaded, err := config.Load(*directory)
	if err != nil {
		return err
	}
	store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer store.Close()
	var result any
	switch args[1] {
	case "list":
		result, err = store.SAMLServiceProviders(ctx)
	case "inspect":
		if id == "" {
			return errors.New("--id is required")
		}
		result, err = store.SAMLServiceProvider(ctx, id)
	case "apply":
		var sp identity.SAMLServiceProvider
		if file == "" {
			return errors.New("--file is required")
		}
		if err = config.ReadJSON(file, &sp); err == nil {
			result, err = store.PutSAMLServiceProvider(ctx, identity.OperatorPrincipal(), sp, loaded.AllowLoopbackHTTP)
		}
	case "enable-use", "withdraw-use":
		enabled := args[1] == "enable-use"
		err = store.SetSAMLEnablement(ctx, identity.OperatorPrincipal(), organizationID, id, enabled)
		result = map[string]bool{"enabled": enabled}
	case "disable", "retire":
		if id == "" || revision < 1 {
			return errors.New("--id and --revision are required")
		}
		var sp identity.SAMLServiceProvider
		sp, err = store.SAMLServiceProvider(ctx, id)
		if err == nil {
			sp.Enabled = false
			sp.Retired = args[1] == "retire"
			sp.Revision = revision
			result, err = store.PutSAMLServiceProvider(ctx, identity.OperatorPrincipal(), sp, loaded.AllowLoopbackHTTP)
		}
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}
