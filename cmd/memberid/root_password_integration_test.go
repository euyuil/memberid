//go:build integration

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/testdb"
)

func TestDatabaseInitSavesInitialRootPasswordExclusively(t *testing.T) {
	databaseURL := testdb.Create(t)
	t.Setenv("MEMBERID_DATABASE_URL", databaseURL)
	protected := t.TempDir()
	existing := filepath.Join(protected, "retained-file")
	if err := os.WriteFile(existing, []byte("preserve existing contents"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	initialize := func(path string) error {
		stdout.Reset()
		stderr.Reset()
		return run(t.Context(), []string{"database", "init", "--initial-root-password-file", path}, &stdout, &stderr)
	}
	t.Setenv("MEMBERID_DATABASE_URL", "invalid-database-settings")
	if err := initialize(existing); !errors.Is(err, os.ErrExist) {
		t.Fatal("initialization did not detect the existing file before connecting", err)
	}
	t.Setenv("MEMBERID_DATABASE_URL", databaseURL)
	if data, err := os.ReadFile(existing); err != nil || string(data) != "preserve existing contents" {
		t.Fatal("an existing operator-owned file was changed", err)
	}
	competing := filepath.Join(protected, "competing-password-file")
	err := identity.InitializeWithRoot(t.Context(), databaseURL, func(password string) error {
		if err := os.WriteFile(competing, []byte("created during initialization"), 0600); err != nil {
			return err
		}
		return config.WriteExclusive(competing, []byte(password+"\n"))
	})
	if !errors.Is(err, os.ErrExist) {
		t.Fatal("password write did not refuse a file created during initialization", err)
	}
	if data, err := os.ReadFile(competing); err != nil || string(data) != "created during initialization" {
		t.Fatal("initialization changed a competing writer's file", err)
	}
	if store, err := identity.Open(t.Context(), databaseURL); store != nil || !errors.Is(err, identity.ErrSchemaRequired) {
		t.Fatal("a failed password write did not roll back initialization", err)
	}

	path := filepath.Join(protected, "initial-root-password")
	if err := initialize(path); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil || !regexp.MustCompile(`^[A-Za-z0-9_-]{32}\n$`).Match(contents) {
		t.Fatal("initial password file was not created with the expected format", err)
	}
	if password := strings.TrimSpace(string(contents)); strings.Contains(stdout.String(), password) || strings.Contains(stderr.String(), password) {
		t.Fatal("initialization disclosed the password in command output")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("initial password file permits access beyond its owner")
	}
	store, err := identity.Open(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	admins, err := store.AdministratorIDs(t.Context(), identity.SystemOrganizationID)
	if err != nil || len(admins) != 1 {
		t.Fatal("fresh installation did not create exactly one platform administrator", err)
	}
	root, err := store.Member(t.Context(), identity.SystemOrganizationID, admins[0])
	if err != nil || root.DisplayName != identity.RootUsername {
		t.Fatal("the initial administrator was not the system root Member", err)
	}
	retryPath := filepath.Join(protected, "retry-password")
	if err := initialize(retryPath); !errors.Is(err, identity.ErrDatabaseNotEmpty) {
		t.Fatal("reinitialization did not refuse a populated database", err)
	}
	if _, err := os.Stat(retryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reinitialization created a new password file", err)
	}
	if err := run(t.Context(), []string{"setup", "reset-password"}, &stdout, &stderr); err != nil {
		t.Fatal("local root password reset failed", err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{32}\n$`).Match(stdout.Bytes()) || bytes.Equal(stdout.Bytes(), contents) {
		t.Fatal("local reset did not return a newly generated password")
	}
	if stderr.String() != "Login org_system/root\n" {
		t.Fatal("local reset did not report the current login alongside the password")
	}
	if retained, err := os.ReadFile(path); err != nil || !bytes.Equal(retained, contents) {
		t.Fatal("local reset changed the initial password file", err)
	}
}
