package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/config"
)

func TestConfigurationCommands(t *testing.T) {
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
	execute("client", "add", "--directory", directory, "--id", "example", "--redirect", "https://app.example.invalid/callback", "--refresh")
	var first map[string]string
	if json.Unmarshal(stdout.Bytes(), &first) != nil || len(first["client_secret"]) != 43 {
		t.Fatal("missing one-time client credential")
	}
	registry, _ := os.ReadFile(filepath.Join(directory, "clients.json"))
	if strings.Contains(string(registry), first["client_secret"]) {
		t.Fatal("stored plaintext client secret")
	}
	loaded, err := config.Load(directory)
	if err != nil || len(loaded.Clients) != 1 || loaded.Clients[0].SecretSHA256 != config.SecretHash(first["client_secret"]) {
		t.Fatal("invalid client registry")
	}
	if err := run(t.Context(), []string{"client", "add", "--directory", directory, "--id", "example", "--redirect", "https://app.example.invalid/callback"}, &stdout, &stderr); err == nil {
		t.Fatal("duplicate registration replaced existing client")
	}
	execute("client", "rotate-secret", "--directory", directory, "--id", "example")
	var next map[string]string
	if json.Unmarshal(stdout.Bytes(), &next) != nil || next["client_secret"] == first["client_secret"] {
		t.Fatal("rotation reused secret")
	}
	loaded, err = config.Load(directory)
	if err != nil || loaded.Clients[0].SecretSHA256 != config.SecretHash(next["client_secret"]) || !loaded.Clients[0].Refresh || loaded.Clients[0].SubjectKind != "member" {
		t.Fatal("rotation changed client policy or failed")
	}
	execute("config", "check", "--directory", directory)
	if strings.Contains(stdout.String(), next["client_secret"]) {
		t.Fatal("validation leaked client credential")
	}
}

func TestManagementCredentialRotationCommand(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "installation")
	if err := config.Initialize(directory, "https://login.example.invalid", false); err != nil {
		t.Fatal(err)
	}
	outputFile := filepath.Join(directory, "next-credential")
	var stdout, stderr bytes.Buffer
	args := []string{"config", "rotate-management-secret", "--directory", directory, "--output-file", outputFile}
	if err := run(t.Context(), args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var result map[string]bool
	if json.Unmarshal(stdout.Bytes(), &result) != nil || !result["rotated"] || !result["restartRequired"] || len(result) != 2 || stderr.Len() != 0 {
		t.Fatal("rotation did not return the safe restart acknowledgement")
	}
	credential, err := os.ReadFile(outputFile)
	if err != nil || strings.Contains(stdout.String()+stderr.String(), strings.TrimSpace(string(credential))) {
		t.Fatal("rotation disclosed its credential", err)
	}
	for _, invalid := range [][]string{
		{"config", "rotate-management-secret"},
		{"config", "rotate-management-secret", "--directory", directory},
		{"config", "rotate-management-secret", "--output-file", outputFile},
		append(append([]string{}, args...), "extra"),
		append(append([]string{}, args...), "--issuer", "https://other.example.invalid"),
		args, // Existing output must never be overwritten, including on retry.
	} {
		stdout.Reset()
		stderr.Reset()
		if err := run(t.Context(), invalid, &stdout, &stderr); err == nil || stdout.Len() != 0 {
			t.Fatal("invalid rotation succeeded or reported success")
		}
	}
}
