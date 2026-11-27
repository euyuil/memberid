//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/testdb"
)

func TestConfigurationCommands(t *testing.T) {
	databaseURL := testdb.Create(t)
	if err := identity.Initialize(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEMBERID_DATABASE_URL", databaseURL)
	store, err := identity.Open(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	directory := filepath.Join(t.TempDir(), "installation")
	var stdout, stderr bytes.Buffer
	execute := func(args ...string) {
		t.Helper()
		stdout.Reset()
		stderr.Reset()
		if err := run(t.Context(), args, &stdout, &stderr); err != nil {
			t.Fatal(err)
		}
	}
	execute("config", "init", "--directory", directory, "--issuer", "https://login.example.invalid")
	if strings.Contains(stdout.String(), "PRIVATE KEY") || strings.Contains(stdout.String(), "protocolKey") {
		t.Fatal("initialization exposed private material")
	}
	execute("client", "add", "--directory", directory, "--name", "example", "--redirect", "https://app.example.invalid/callback", "--refresh")
	var first map[string]string
	if json.Unmarshal(stdout.Bytes(), &first) != nil || len(first["client_secret"]) != 43 {
		t.Fatal("missing one-time client credential")
	}
	loaded, err := store.OIDCClient(t.Context(), first["client_id"])
	if err != nil || loaded.Client.SecretSHA256 != config.SecretHash(first["client_secret"]) {
		t.Fatal("invalid client registry")
	}
	if err := run(t.Context(), []string{"client", "add", "--directory", directory, "--id", "example", "--redirect", "https://app.example.invalid/callback"}, &stdout, &stderr); err == nil {
		t.Fatal("caller-supplied registration ID accepted")
	}
	execute("client", "rotate-secret", "--directory", directory, "--id", first["client_id"])
	var next map[string]string
	if json.Unmarshal(stdout.Bytes(), &next) != nil || next["client_secret"] == first["client_secret"] {
		t.Fatal("rotation reused secret")
	}
	loaded, err = store.OIDCClient(t.Context(), first["client_id"])
	if err != nil || loaded.Client.SecretSHA256 != config.SecretHash(next["client_secret"]) || !loaded.Client.Refresh || loaded.Client.SubjectKind != "member" {
		t.Fatal("rotation changed client policy or failed")
	}
	execute("config", "check", "--directory", directory)
	if strings.Contains(stdout.String(), next["client_secret"]) {
		t.Fatal("validation leaked client credential")
	}
}
