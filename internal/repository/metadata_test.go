package repository

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestMetadataChecks(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal("metadata checks require a POSIX shell:", err)
	}
	script, err := filepath.Abs("../../scripts/check-metadata.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		mode    string
		value   string
		allowed bool
	}{
		{"feature branch", "branch", "refs/heads/feat/member-directory", true},
		{"agent branch", "branch", "refs/heads/codex/member-directory", false},
		{"second agent branch", "branch", "claude/member-directory", false},
		{"ordinary message", "message", "feat: support a client integration\n", true},
		{"factual product reference", "message", "fix: document Codex client configuration\n", true},
		{"attribution trailer", "message", "feat: add login\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n", false},
		{"attribution footer", "message", "docs: add setup\n\nGenerated with Codex\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := test.value
			if test.mode == "message" {
				value = filepath.Join(t.TempDir(), "message.txt")
				if err := os.WriteFile(value, []byte(test.value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			output, err := exec.Command(shell, script, test.mode, value).CombinedOutput()
			if (err == nil) != test.allowed {
				t.Fatalf("allowed = %v, error = %v, output = %s", test.allowed, err, output)
			}
		})
	}
}
