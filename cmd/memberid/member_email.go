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

func manageMemberEmail(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "inspect" && args[0] != "set" {
		return errors.New("usage: memberid member email <inspect|set> --organization ID --member ID")
	}
	flags := flag.NewFlagSet("member email "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	organizationID := flags.String("organization", "", "organization identifier")
	memberID := flags.String("member", "", "Member identifier")
	address := ""
	revision := int64(-1)
	if args[0] == "set" {
		flags.StringVar(&address, "address", "", "administrator-managed email; empty clears")
		flags.Int64Var(&revision, "revision", -1, "expected current revision; zero creates")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	addressSupplied := false
	flags.Visit(func(f *flag.Flag) { addressSupplied = addressSupplied || f.Name == "address" })
	if flags.NArg() != 0 || *organizationID == "" || *memberID == "" || args[0] == "set" && (!addressSupplied || revision < 0) {
		return errors.New("supply --organization and --member; set also requires --address and --revision")
	}
	store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer store.Close()
	var result identity.MemberEmail
	if args[0] == "inspect" {
		result, err = store.MemberEmail(ctx, identity.OperatorPrincipal(), *organizationID, *memberID)
	} else {
		result, err = store.PutMemberEmail(ctx, identity.OperatorPrincipal(), *organizationID, *memberID, identity.MemberEmailInput{Address: address, Revision: revision})
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}
