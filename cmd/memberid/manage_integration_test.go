//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/testdb"
)

func TestOperatorCommands(t *testing.T) {
	t.Setenv("MEMBERID_DATABASE_URL", testdb.Create(t))
	var output, diagnostic bytes.Buffer
	execute := func(args ...string) {
		t.Helper()
		output.Reset()
		diagnostic.Reset()
		if err := run(t.Context(), args, &output, &diagnostic); err != nil {
			t.Fatalf("command failed: %v", err)
		}
	}
	execute("database", "init")
	execute("organization", "create", "--name", "Example organization")
	var organization identity.Organization
	if err := json.Unmarshal(output.Bytes(), &organization); err != nil {
		t.Fatal(err)
	}
	execute("member", "create", "--organization", organization.ID, "--name", "Example member")
	var member identity.Member
	if err := json.Unmarshal(output.Bytes(), &member); err != nil {
		t.Fatal(err)
	}
	execute("member", "block", "--organization", organization.ID, "--member", member.ID)
	if err := json.Unmarshal(output.Bytes(), &member); err != nil || member.Status != "blocked" {
		t.Fatalf("block result: %+v, %v", member, err)
	}
	execute("member", "unblock", "--organization", organization.ID, "--member", member.ID)
	if err := json.Unmarshal(output.Bytes(), &member); err != nil || member.Status != "active" {
		t.Fatalf("unblock result: %+v, %v", member, err)
	}
	if err := run(t.Context(), []string{"database", "init"}, &output, &diagnostic); err != identity.ErrDatabaseNotEmpty {
		t.Fatalf("reinitialization did not refuse existing data: %v", err)
	}
}
