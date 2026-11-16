package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
)

func manageSAMLNameID(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "inspect" && args[0] != "provision" {
		return errors.New("usage: memberid saml nameid <inspect|provision> --directory PATH --organization ID --sp ID --member ID")
	}
	flags := flag.NewFlagSet("saml nameid "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "protected installation directory")
	organizationID := flags.String("organization", "", "organization identifier")
	serviceProviderID := flags.String("sp", "", "registered service provider ID")
	memberID := flags.String("member", "", "Member identifier")
	value, revision := "", int64(0)
	if args[0] == "provision" {
		flags.StringVar(&value, "value", "", "exact legacy NameID; never inferred from profile attributes")
		flags.Int64Var(&revision, "revision", 0, "expected current SP revision")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || *directory == "" || *organizationID == "" || *serviceProviderID == "" || *memberID == "" || args[0] == "provision" && (value == "" || revision < 1) {
		return errors.New("supply --directory, --organization, --sp and --member; provision also requires --value and --revision")
	}
	if _, err := config.Load(*directory); err != nil {
		return err
	}
	store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer store.Close()
	var result identity.SAMLNameIDMapping
	if args[0] == "inspect" {
		result, err = store.InspectSAMLNameID(ctx, identity.OperatorPrincipal(), *organizationID, *serviceProviderID, *memberID)
	} else {
		result, err = store.ProvisionSAMLNameID(ctx, identity.OperatorPrincipal(), *organizationID, *serviceProviderID, *memberID, value, revision)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}
