package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDatabaseUpgradeRequiresMaintenanceBeforeConnecting(t *testing.T) {
	t.Setenv("MEMBERID_DATABASE_URL", "invalid-database-url")
	var output, diagnostic bytes.Buffer
	err := run(t.Context(), []string{"database", "upgrade", "--directory", "unused", "--backup-directory", "unused-backup"}, &output, &diagnostic)
	if err == nil || !strings.Contains(err.Error(), "--maintenance-confirmed") || output.Len() != 0 {
		t.Fatal("upgrade did not enforce maintenance precondition", err)
	}
}

func TestDatabaseUpgradeHasNoDowngradeOrTargetOverride(t *testing.T) {
	for _, args := range [][]string{{"database", "downgrade"}, {"database", "upgrade", "--target", "26"}, {"database", "backup-check", "extra"}} {
		var output, diagnostic bytes.Buffer
		if err := run(t.Context(), args, &output, &diagnostic); err == nil || output.Len() != 0 {
			t.Fatal("unsupported operation admitted", args, err)
		}
	}
}
