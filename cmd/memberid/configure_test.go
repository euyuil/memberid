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
