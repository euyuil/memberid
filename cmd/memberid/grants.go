package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/oidcprovider"
)

func manageGrant(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		return errors.New("usage: memberid grant <list|inspect|revoke>")
	}
	flags := flag.NewFlagSet("grant "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	var id string
	var filter oidcprovider.GrantFilter
	switch args[0] {
	case "list":
		flags.StringVar(&filter.ClientID, "client", "", "filter by exact OIDC client identifier")
		flags.StringVar(&filter.Subject, "subject", "", "filter by exact Member or factor subject")
		flags.StringVar(&filter.After, "after", "", "last grant identifier from the previous page")
		flags.IntVar(&filter.Limit, "limit", 50, "page size from 1 to 100")
	case "inspect", "revoke":
		flags.StringVar(&id, "id", "", "grant identifier")
	default:
		return errors.New("unknown grant operation")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || args[0] != "list" && id == "" {
		return errors.New("grant inspect/revoke requires --id; positional arguments are not accepted")
	}
	store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer store.Close()
	var result any
	switch args[0] {
	case "list":
		result, err = oidcprovider.ListGrants(ctx, store, filter)
	case "inspect":
		result, err = oidcprovider.InspectGrant(ctx, store, id)
	case "revoke":
		result, err = oidcprovider.RevokeGrant(ctx, store, id)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}
