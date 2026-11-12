package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestManagementRotationPreservesInstallation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "installation")
	if err := Initialize(directory, "https://login.example.invalid", false); err != nil {
		t.Fatal(err)
	}
	before, err := Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	// Respect a configured filename instead of assuming the initialization default.
	before.SecretsFile = "protected-secrets.json"
	if err := os.Rename(filepath.Join(directory, "secrets.json"), filepath.Join(directory, before.SecretsFile)); err != nil {
		t.Fatal(err)
	}
	installation, _ := json.Marshal(before.Installation)
	if err := os.WriteFile(filepath.Join(directory, "memberid.json"), installation, 0600); err != nil {
		t.Fatal(err)
	}
	unchanged := map[string]string{}
	for _, name := range []string{"memberid.json", "clients.json", "signing-key.pem", "public-keys.pem", "management-secret"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		unchanged[name] = string(data)
	}
	previousHash := before.Secrets.ManagementSecretSHA256
	for _, name := range []string{"first-credential", "second-credential"} {
		outputFile := filepath.Join(directory, name)
		if err := RotateManagementSecret(directory, outputFile); err != nil {
			t.Fatal(err)
		}
		credential, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatal(err)
		}
		secret := strings.TrimSpace(string(credential))
		after, err := Load(directory)
		if err != nil || len(secret) != 43 || after.Secrets.ManagementSecretSHA256 != SecretHash(secret) || after.Secrets.ManagementSecretSHA256 == previousHash {
			t.Fatal("new protected credential does not match the changed verifier", err)
		}
		previousHash = after.Secrets.ManagementSecretSHA256
		after.Secrets.ManagementSecretSHA256 = before.Secrets.ManagementSecretSHA256
		if after.Secrets != before.Secrets {
			t.Fatal("rotation changed an unrelated installation key")
		}
		stored, err := os.ReadFile(filepath.Join(directory, before.SecretsFile))
		if err != nil || strings.Contains(string(stored), secret) {
			t.Fatal("secrets configuration contains a plaintext management credential", err)
		}
		for file, original := range unchanged {
			data, err := os.ReadFile(filepath.Join(directory, file))
			if err != nil || string(data) != original {
				t.Fatal("rotation changed unrelated installation material", file, err)
			}
		}
		if runtime.GOOS != "windows" {
			for _, file := range []string{outputFile, filepath.Join(directory, before.SecretsFile)} {
				info, err := os.Stat(file)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatal("rotation left unprotected material", err)
				}
			}
		}
	}
	leftovers, err := filepath.Glob(filepath.Join(directory, ".management-secret*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatal("rotation left a lock or temporary verifier file", err)
	}
}

func TestManagementRotationRefusesUnsafeChanges(t *testing.T) {
	for _, kind := range []string{"existing file", "existing directory", "missing parent", "locked", "invalid configuration"} {
		t.Run(kind, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "installation")
			if err := Initialize(directory, "https://login.example.invalid", false); err != nil {
				t.Fatal(err)
			}
			verifierFile := filepath.Join(directory, "secrets.json")
			before, err := os.ReadFile(verifierFile)
			if err != nil {
				t.Fatal(err)
			}
			outputFile := filepath.Join(directory, "next-credential")
			lockFile := filepath.Join(directory, ".management-secret.lock")
			switch kind {
			case "existing file":
				err = os.WriteFile(outputFile, []byte("operator-owned data"), 0600)
			case "existing directory":
				err = os.Mkdir(outputFile, 0700)
			case "missing parent":
				outputFile = filepath.Join(directory, "missing", "credential")
			case "locked":
				err = os.WriteFile(lockFile, []byte("another operator"), 0600)
			case "invalid configuration":
				err = os.WriteFile(filepath.Join(directory, "clients.json"), []byte("invalid"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if RotateManagementSecret(directory, outputFile) == nil {
				t.Fatal("unsafe rotation succeeded")
			}
			after, err := os.ReadFile(verifierFile)
			if err != nil || string(after) != string(before) {
				t.Fatal("failed rotation changed the active verifier", err)
			}
			if kind == "existing file" {
				data, err := os.ReadFile(outputFile)
				if err != nil || string(data) != "operator-owned data" {
					t.Fatal("replaced an operator file", err)
				}
			} else if kind == "existing directory" {
				info, err := os.Stat(outputFile)
				if err != nil || !info.IsDir() {
					t.Fatal("replaced an operator directory", err)
				}
			} else if _, err := os.Lstat(outputFile); !os.IsNotExist(err) {
				t.Fatal("failed prerequisite created a credential file", err)
			}
			if kind == "locked" {
				data, err := os.ReadFile(lockFile)
				if err != nil || string(data) != "another operator" {
					t.Fatal("removed another operator's lock", err)
				}
			} else if _, err := os.Lstat(lockFile); !os.IsNotExist(err) {
				t.Fatal("failed rotation retained its own lock", err)
			}
		})
	}
}
