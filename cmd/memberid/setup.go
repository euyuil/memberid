package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/euyuil/memberid/internal/identity"
)

func manageSetup(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 1 || (args[0] != "code" && args[0] != "reset-password") {
		return errors.New("usage: memberid setup <code|reset-password>")
	}
	store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer store.Close()
	var secret string
	if args[0] == "code" {
		secret, err = store.IssueSetupCode(ctx, identity.OperatorPrincipal())
	} else {
		secret, err = store.ResetRootPassword(ctx, identity.OperatorPrincipal())
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, secret)
	return err
}

func manageMemberPassword(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("member set-password", flag.ContinueOnError)
	flags.SetOutput(stderr)
	organizationID := flags.String("organization", "", "organization identifier")
	memberID := flags.String("member", "", "existing Member identifier")
	username := flags.String("username", "", "organization-scoped username")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *organizationID == "" || *memberID == "" || *username == "" {
		return errors.New("supply --organization, --member, and --username")
	}
	store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer store.Close()
	password, err := store.SetMemberPassword(ctx, identity.OperatorPrincipal(), *organizationID, *memberID, *username)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, password)
	return err
}
