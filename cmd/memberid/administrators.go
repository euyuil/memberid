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

func manageAdministrator(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || (args[0] != "grant" && args[0] != "revoke") {
		return errors.New("usage: memberid administrator <grant|revoke> --organization ID --member ID")
	}
	f := flag.NewFlagSet("administrator", flag.ContinueOnError)
	f.SetOutput(stderr)
	org := f.String("organization", "", "organization identifier")
	member := f.String("member", "", "existing verified and bound Member identifier")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer store.Close()
	if err = store.SetAdministrator(ctx, identity.ManagementActor{}, *org, *member, args[0] == "grant"); err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]any{"organizationId": *org, "memberId": *member, "administrator": args[0] == "grant"})
}

func prepareSystemDingTalk(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	f := flag.NewFlagSet("dingtalk "+args[0], flag.ContinueOnError)
	f.SetOutput(stderr)
	member := f.String("member", "", "existing system organization Member identifier")
	union, providerID := "", ""
	if args[0] == "allow-system-member" {
		f.StringVar(&providerID, "provider", "", "system organization DingTalk provider ID when multiple are configured")
		f.StringVar(&union, "union-id", "", "exact union ID from the system organization's provider namespace")
	}
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 || args[0] == "allow-system-member" && union == "" {
		return errors.New("supply --member and, for admission, --union-id")
	}
	store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer store.Close()
	if err = store.PrepareSystemDingTalkAdmissionForSource(ctx, *member, union, providerID); err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]any{"memberId": *member, "admissionPrepared": union != ""})
}
