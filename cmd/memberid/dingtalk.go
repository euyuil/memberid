package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strings"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/dingtalk"
	"github.com/euyuil/memberid/internal/identity"
)

func manageDingTalk(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && (args[0] == "allow-system-member" || args[0] == "cancel-system-member") {
		return prepareSystemDingTalk(ctx, args, stdout, stderr)
	}
	if len(args) == 0 || args[0] != "inspect" && args[0] != "configure" && args[0] != "sync" && args[0] != "reconcile" {
		return errors.New("usage: memberid dingtalk <inspect|configure|sync|reconcile|allow-system-member|cancel-system-member>")
	}
	flags := flag.NewFlagSet("dingtalk "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "protected installation directory")
	organizationID := flags.String("organization", "", "MemberID organization identifier")
	namespace := flags.String("provider", "", "application provider ID when the organization has multiple applications")
	var input identity.DingTalkApplicationInput
	var secretFile string
	if args[0] == "configure" {
		flags.StringVar(&input.CorpID, "corp", "", "DingTalk corporation identifier")
		flags.StringVar(&input.ClientID, "client", "", "DingTalk application client identifier")
		flags.Int64Var(&input.ExpectedRevision, "expected-revision", -1, "0 for initial configuration; current revision for updates")
		flags.StringVar(&secretFile, "secret-file", "", "protected file containing the application secret")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || *directory == "" || !identity.ValidID(*organizationID, identity.OrganizationKind) {
		return errors.New("dingtalk requires --directory and --organization and takes flags only")
	}
	if args[0] == "configure" {
		if secretFile == "" || input.ExpectedRevision < 0 {
			return errors.New("configure requires --secret-file and --expected-revision")
		}
		file, err := os.Open(secretFile)
		if err != nil {
			return errors.New("cannot open provider secret file")
		}
		data, err := io.ReadAll(io.LimitReader(file, 4099))
		closeErr := file.Close()
		if err != nil || closeErr != nil || len(data) > 4098 {
			return errors.New("cannot read provider secret file")
		}
		input.ClientSecret = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
		if !dingtalk.ValidCredentials(input.CorpID, input.ClientID, input.ClientSecret) {
			return errors.New("invalid DingTalk application credentials")
		}
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
	key, err := base64.StdEncoding.DecodeString(loaded.Secrets.ProviderKey)
	if err != nil {
		return err
	}
	client := dingtalk.New()
	applications, err := identity.NewDingTalkApplications(store, key, client)
	if err != nil {
		return err
	}
	if args[0] == "reconcile" {
		directory, err := identity.NewDingTalkDirectory(applications, client)
		if err != nil {
			return err
		}
		result, err := directory.ReconcileSource(ctx, *organizationID, *namespace)
		if result.Application.OrganizationID != "" {
			if encodeErr := json.NewEncoder(stdout).Encode(result); encodeErr != nil {
				return encodeErr
			}
		}
		return err
	}
	var result identity.DingTalkApplication
	if args[0] == "inspect" {
		result, err = applications.InspectSource(ctx, *organizationID, *namespace)
	} else if args[0] == "sync" {
		result, err = applications.SynchronizeSource(ctx, *organizationID, *namespace)
	} else {
		result, err = applications.ConfigureSource(ctx, identity.OperatorPrincipal(), *organizationID, *namespace, input)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}
