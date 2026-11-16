package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

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
	result, err := identity.UpgradeDatabase(ctx, databaseURL, func(ctx context.Context, snapshot string, version int) (identity.UpgradeBackup, error) {
		return recovery.Create(ctx, databaseURL, directory, backup, pgDump, snapshot, version)
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}
