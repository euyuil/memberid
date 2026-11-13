//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/testdb"
	"github.com/jackc/pgx/v5"
)

func TestDatabaseCheckPreservesUninitializedDatabases(t *testing.T) {
	for _, foreignTable := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "unrelated data"}[foreignTable], func(t *testing.T) {
			database := testdb.Create(t)
			t.Setenv("MEMBERID_DATABASE_URL", database)
			connection, err := pgx.Connect(t.Context(), database)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close(t.Context())
			if foreignTable {
				if _, err := connection.Exec(t.Context(), "CREATE TABLE retained_example(value text); INSERT INTO retained_example VALUES ('preserve');"); err != nil {
					t.Fatal(err)
				}
			}
			var output, diagnostic bytes.Buffer
			if err := run(t.Context(), []string{"database", "check"}, &output, &diagnostic); !errors.Is(err, identity.ErrSchemaRequired) {
				t.Fatalf("uninitialized check: %v", err)
			}
			if output.Len() != 0 || diagnostic.Len() != 0 {
				t.Fatal("unsuccessful check emitted a success result or diagnostics")
			}
			var count int
			if err := connection.QueryRow(t.Context(), "SELECT count(*) FROM pg_tables WHERE schemaname='public'").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != map[bool]int{false: 0, true: 1}[foreignTable] {
				t.Fatal("check changed the database schema")
			}
			if foreignTable {
				var value string
				if err := connection.QueryRow(t.Context(), "SELECT value FROM retained_example").Scan(&value); err != nil || value != "preserve" {
					t.Fatal("check changed existing data", err)
				}
			}
		})
	}
}

func TestDatabaseCheckUsesReadOnlyStartupValidation(t *testing.T) {
	database := testdb.Create(t)
	if err := identity.Initialize(t.Context(), database); err != nil {
		t.Fatal(err)
	}
	connection, err := pgx.Connect(t.Context(), database)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(t.Context())
	address, err := url.Parse(database)
	if err != nil {
		t.Fatal(err)
	}
	query := address.Query()
	query.Set("default_transaction_read_only", "on")
	address.RawQuery = query.Encode()
	t.Setenv("MEMBERID_DATABASE_URL", address.String())
	t.Setenv("MEMBERID_PHONE_ENABLED", "invalid-provider-setting")
	t.Setenv("MEMBERID_DINGTALK_ENABLED", "invalid-provider-setting")
	var output, diagnostic bytes.Buffer
	if err := run(t.Context(), []string{"database", "check"}, &output, &diagnostic); err != nil {
		t.Fatal("read-only database check failed", err)
	}
	var result map[string]bool
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || len(result) != 1 || !result["compatible"] || diagnostic.Len() != 0 {
		t.Fatal("unexpected compatibility result", err)
	}
	if _, err := connection.Exec(t.Context(), "ALTER TABLE memberid_schema DROP CONSTRAINT memberid_schema_version_check; UPDATE memberid_schema SET version=version-1"); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run(t.Context(), []string{"database", "check"}, &output, &diagnostic); !errors.Is(err, identity.ErrSchemaRequired) || output.Len() != 0 {
		t.Fatal("incompatible schema check did not fail without success output", err)
	}
	var version int
	if err := connection.QueryRow(t.Context(), "SELECT version FROM memberid_schema").Scan(&version); err != nil || version != 13 {
		t.Fatal("incompatible schema was changed", err)
	}
}

func TestDatabaseCheckRejectsArgumentsBeforeConnecting(t *testing.T) {
	t.Setenv("MEMBERID_DATABASE_URL", "invalid-database-url")
	for _, args := range [][]string{{"database", "check", "extra"}, {"database", "check", "--directory", "unused"}, {"database", "unknown"}} {
		var output, diagnostic bytes.Buffer
		if err := run(t.Context(), args, &output, &diagnostic); err == nil || !strings.Contains(err.Error(), "usage: memberid database <init|check>") {
			t.Fatal("unsupported database arguments were not rejected", err)
		}
		if output.Len() != 0 || diagnostic.Len() != 0 {
			t.Fatal("invalid arguments emitted unexpected output")
		}
	}
}
