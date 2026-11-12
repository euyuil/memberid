//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/oidcprovider"
	"github.com/euyuil/memberid/internal/testdb"
)

func TestGrantOperatorCommands(t *testing.T) {
	databaseURL := testdb.Create(t)
	t.Setenv("MEMBERID_DATABASE_URL", databaseURL)
	if err := identity.Initialize(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	store, err := identity.Open(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	subject, err := identity.NewID(identity.FactorKind)
	if err != nil {
		t.Fatal(err)
	}
	const id = "00000000-0000-4000-8000-000000000001"
	const session = "00000000-0000-4000-8000-000000000002"
	now := time.Now().UTC()
	data, err := json.Marshal(map[string]any{"id": id, "clientId": "example-web", "sessionId": session, "factorId": subject, "factorType": "phone", "authTime": now, "absoluteExpiry": now.Add(365 * 24 * time.Hour), "scopes": []string{"openid"}, "audience": []string{"https://login.example.invalid/oauth/userinfo"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Database().Exec(t.Context(), "INSERT INTO oidc_sessions(id,secret_hash,verification,expires_at,absolute_expires_at) VALUES($1,$2,'{}',$3,$4)", session, config.SecretHash(config.RandomSecret()), now.Add(24*time.Hour), now.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Database().Exec(t.Context(), "INSERT INTO oidc_grants(id,client_id,session_id,data,expires_at,absolute_expires_at) VALUES($1,'example-web',$2,$3,$4,$5)", id, session, data, now.Add(24*time.Hour), now.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var output, diagnostic bytes.Buffer
	execute := func(args ...string) {
		t.Helper()
		output.Reset()
		if err := run(t.Context(), args, &output, &diagnostic); err != nil {
			t.Fatal(err)
		}
	}
	execute("grant", "list", "--client", "example-web", "--subject", subject, "--limit", "1")
	var page identity.Page[oidcprovider.GrantInfo]
	if err := json.Unmarshal(output.Bytes(), &page); err != nil || len(page.Items) != 1 || page.Items[0].ID != id {
		t.Fatalf("list result: %+v %v", page, err)
	}
	execute("grant", "inspect", "--id", id)
	var info oidcprovider.GrantInfo
	if err := json.Unmarshal(output.Bytes(), &info); err != nil || info.State != "active" {
		t.Fatal("inspect failed", err)
	}
	execute("grant", "revoke", "--id", id)
	if err := json.Unmarshal(output.Bytes(), &info); err != nil || info.State != "revoked" {
		t.Fatal("revoke failed", err)
	}
	for _, args := range [][]string{{"grant"}, {"grant", "unknown"}, {"grant", "inspect"}, {"grant", "revoke", "--client", "example-web"}, {"grant", "list", "--limit", "101"}} {
		if err := run(t.Context(), args, &output, &diagnostic); err == nil {
			t.Fatalf("invalid command accepted: %v", args)
		}
	}
}
