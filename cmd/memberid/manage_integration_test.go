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

func TestExplicitPhoneBindingCommands(t *testing.T) {
	database := testdb.Create(t)
	t.Setenv("MEMBERID_DATABASE_URL", database)
	var output, diagnostic bytes.Buffer
	execute := func(args ...string) {
		t.Helper()
		output.Reset()
		if err := run(t.Context(), args, &output, &diagnostic); err != nil {
			t.Fatal(err)
		}
	}
	execute("database", "init")
	store, err := identity.Open(t.Context(), database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	organization, err := store.CreateOrganization(t.Context(), identity.OperatorPrincipal(), "", "Example Team")
	if err != nil {
		t.Fatal(err)
	}
	member, err := store.CreateMember(t.Context(), identity.OperatorPrincipal(), organization.ID, "", "Example Member")
	if err != nil {
		t.Fatal(err)
	}
	if err := run(t.Context(), []string{"factor", "inspect", "--phone", "19900000001"}, &output, &diagnostic); err != identity.ErrNotFound {
		t.Fatal("lookup created unverified evidence", err)
	}
	factor, err := store.EnsureFactor(t.Context(), "phone", "phone:e164", "+8619900000001")
	if err != nil {
		t.Fatal(err)
	}
	execute("factor", "inspect", "--phone", "19900000001")
	var found identity.Factor
	if err := json.Unmarshal(output.Bytes(), &found); err != nil || found.ID != factor.ID {
		t.Fatal("incorrect verified factor lookup", err)
	}
	execute("member", "bind-factor", "--organization", organization.ID, "--member", member.ID, "--factor", factor.ID)
	var binding identity.Binding
	if err := json.Unmarshal(output.Bytes(), &binding); err != nil || binding.MemberID != member.ID || binding.FactorID != factor.ID {
		t.Fatal("incorrect explicit binding", err)
	}
	if err := run(t.Context(), []string{"member", "bind-factor", "--organization", organization.ID, "--member", member.ID, "--phone", "19900000001"}, &output, &diagnostic); err == nil {
		t.Fatal("binding accepted a phone in place of verified factor evidence")
	}
}
