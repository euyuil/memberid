package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/zhizhun-tech/memberid/internal/identity"
)

func manageSetup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) != 1 || (args[0] != "reset-password" && args[0] != "identities") {
		return errors.New("usage: memberid setup identities | reset-password")
	}
	store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer store.Close()
	if args[0] == "identities" {
		ids := map[string]string{"organizationId": store.SystemOrganizationID()}
		if _, err := store.Member(ctx, store.SystemOrganizationID(), store.RootMemberID()); err == nil {
			ids["rootMemberId"] = store.RootMemberID()
		} else if !errors.Is(err, identity.ErrNotFound) {
			return err
		}
		return json.NewEncoder(stdout).Encode(ids)
	}
	secret, err := store.ResetRootPassword(ctx, identity.OperatorPrincipal())
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, secret.Password); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stderr, "Login %s/%s\n", identity.SystemOrganizationSlug, secret.Username)
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
