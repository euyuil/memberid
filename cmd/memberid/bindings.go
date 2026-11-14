package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/euyuil/memberid/internal/identity"
)

func manageBinding(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet(args[0]+" "+args[1], flag.ContinueOnError)
	flags.SetOutput(stderr)
	var phone, organizationID, memberID, factorID string
	if args[0] == "factor" && args[1] == "inspect" {
		flags.StringVar(&phone, "phone", "", "already verified phone number")
	} else if args[0] == "member" && args[1] == "bind-factor" {
		flags.StringVar(&organizationID, "organization", "", "organization identifier")
		flags.StringVar(&memberID, "member", "", "member identifier")
		flags.StringVar(&factorID, "factor", "", "already verified authentication factor identifier")
	} else {
		return errors.New("unknown binding operation")
	}
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer store.Close()
	var result any
	if args[0] == "factor" {
		result, err = store.PhoneFactor(ctx, phone)
	} else {
		result, err = store.BindFactor(ctx, identity.OperatorPrincipal(), organizationID, memberID, factorID)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}
