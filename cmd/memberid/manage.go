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

func manage(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: memberid database <init|check|application-id-plan|upgrade-plan|upgrade|backup-check> | organization create | member <create|block|unblock>")
	}
	if args[0] == "database" && (args[1] == "application-id-plan" || args[1] == "upgrade-plan" || args[1] == "upgrade" || args[1] == "backup-check") {
		return databaseUpgrade(ctx, args[1:], stdout, stderr)
	}
	if args[0] == "factor" || args[0] == "member" && args[1] == "bind-factor" {
		return manageBinding(ctx, args, stdout, stderr)
	}
	if args[0] == "member" && args[1] == "set-password" {
		return manageMemberPassword(ctx, args[2:], stdout, stderr)
	}
	if args[0] == "member" && args[1] == "email" {
		return manageMemberEmail(ctx, args[2:], stdout, stderr)
	}
	databaseURL := os.Getenv("MEMBERID_DATABASE_URL")
	if databaseURL == "" {
		return errors.New("MEMBERID_DATABASE_URL is required")
	}
	if args[0] == "database" {
		if args[1] != "init" && args[1] != "check" || args[1] == "check" && len(args) != 2 {
			return errors.New("usage: memberid database <init|check|application-id-plan|upgrade-plan|upgrade|backup-check>")
		}
		if args[1] == "check" {
			store, err := identity.Open(ctx, databaseURL)
			if err != nil {
				return err
			}
			defer store.Close()
			return json.NewEncoder(stdout).Encode(map[string]bool{"compatible": true})
		}
		initialization := flag.NewFlagSet("database init", flag.ContinueOnError)
		initialization.SetOutput(stderr)
		passwordFile := initialization.String("initial-root-password-file", "", "new password file inside a protected directory")
		if err := initialization.Parse(args[2:]); err != nil {
			return err
		}
		if initialization.NArg() != 0 || initialization.NFlag() != 0 && *passwordFile == "" {
			return errors.New("usage: memberid database init [--initial-root-password-file FILE]")
		}
		var err error
		if *passwordFile == "" {
			err = identity.Initialize(ctx, databaseURL)
		} else {
			if _, err := os.Lstat(*passwordFile); err == nil {
				return &os.PathError{Op: "create", Path: *passwordFile, Err: os.ErrExist}
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			err = identity.InitializeWithRoot(ctx, databaseURL, func(password string) error {
				return config.WriteExclusive(*passwordFile, []byte(password+"\n"))
			})
		}
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(map[string]bool{"initialized": true})
	}
	flags := flag.NewFlagSet(args[0]+" "+args[1], flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", "", "display name")
	organizationID := flags.String("organization", "", "organization identifier")
	memberID := flags.String("member", "", "member identifier")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if args[0] == "organization" && args[1] != "create" || args[0] == "member" && args[1] != "create" && args[1] != "block" && args[1] != "unblock" {
		return errors.New("unknown management operation")
	}
	store, err := identity.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	var result any
	switch args[0] {
	case "organization":
		if *organizationID != "" || *memberID != "" {
			return errors.New("organization create accepts only --name")
		}
		result, err = store.CreateOrganization(ctx, identity.OperatorPrincipal(), "", *name)
	case "member":
		switch args[1] {
		case "create":
			if *memberID != "" {
				return errors.New("member create accepts --organization and --name")
			}
			result, err = store.CreateMember(ctx, identity.OperatorPrincipal(), *organizationID, "", *name)
		case "block", "unblock":
			if *name != "" {
				return errors.New("member block/unblock accepts --organization and --member")
			}
			result, err = store.SetManualBlock(ctx, identity.OperatorPrincipal(), *organizationID, *memberID, args[1] == "block")
		}
	default:
		return errors.New("unknown management command")
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}
