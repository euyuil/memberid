package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/recovery"
)

func databaseUpgrade(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("database "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	var directory, backup, pgDump string
	var maintenance bool
	if args[0] == "upgrade" {
		flags.StringVar(&directory, "directory", "", "protected installation directory")
		flags.StringVar(&backup, "backup-directory", "", "new recovery directory outside the installation")
		flags.StringVar(&pgDump, "pg-dump", "pg_dump", "PostgreSQL 18 pg_dump executable")
		flags.BoolVar(&maintenance, "maintenance-confirmed", false, "all service replicas, operator/configuration writers and automatic restarts are stopped")
	} else if args[0] == "backup-check" {
		flags.StringVar(&backup, "backup-directory", "", "recovery directory to verify")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if args[0] == "backup-check" {
		if backup == "" {
			return errors.New("--backup-directory is required")
		}
		manifest, receipt, err := recovery.Verify(backup)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(struct {
			SchemaVersion int `json:"schemaVersion"`
			identity.UpgradeBackup
		}{manifest.SchemaVersion, receipt})
	}
	databaseURL := os.Getenv("MEMBERID_DATABASE_URL")
	if args[0] == "upgrade-plan" {
		plan, err := identity.InspectDatabase(ctx, databaseURL)
		if err != nil {
			return err
		}
		if err := json.NewEncoder(stdout).Encode(plan); err != nil {
			return err
		}
		if !plan.Supported {
			return identity.ErrUpgradeUnsupported
		}
		return nil
	}
	if directory == "" || backup == "" || !maintenance {
		return errors.New("upgrade requires --directory, --backup-directory and --maintenance-confirmed")
	}
	result, err := identity.UpgradeDatabase(ctx, databaseURL, func(ctx context.Context, snapshot string, version int) (identity.UpgradePreparation, error) {
		receipt, err := recovery.Create(ctx, databaseURL, directory, backup, pgDump, snapshot, version)
		if err != nil {
			return identity.UpgradePreparation{}, err
		}
		if version >= 29 {
			return identity.UpgradePreparation{Backup: receipt}, nil
		}
		clients, err := legacyOIDCRegistrations(filepath.Join(backup, "installation"))
		return identity.UpgradePreparation{Backup: receipt, OIDCClients: clients}, err
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}

// Read from the completed recovery set so imported registrations and the
// paired installation are kept together even if the live files later change.
func legacyOIDCRegistrations(directory string) ([]identity.OIDCClientRegistration, error) {
	var installation config.Installation
	if err := config.ReadJSON(filepath.Join(directory, "memberid.json"), &installation); err != nil {
		return nil, err
	}
	clients, err := config.LoadLegacyClients(directory, installation)
	if err != nil {
		return nil, err
	}
	settings, secret, err := consoleConfiguration(directory)
	consolePresent := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var registrations []identity.OIDCClientRegistration
	consoleFound := false
	for _, client := range clients {
		registration := identity.OIDCClientRegistration{Client: client, DisplayName: client.ID}
		if consolePresent && client.ID == settings.ClientID {
			if client.OrganizationID != "" || client.SubjectKind != "member" || client.SecretSHA256 != config.SecretHash(secret) ||
				!slices.Contains(client.RedirectURIs, settings.Origin+"/auth/callback") {
				return nil, errors.New("legacy console client and its configured credential or callback do not match")
			}
			registration.System, consoleFound = true, true
			registration.DisplayName = "MemberID 管理台"
		}
		registrations = append(registrations, registration)
	}
	if consolePresent && !consoleFound {
		return nil, errors.New("configured legacy console client is missing from the registry")
	}
	return registrations, nil
}
