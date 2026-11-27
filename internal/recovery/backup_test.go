package recovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/identity"
)

func TestRecoveryRejectsChangedMissingAndExtraFiles(t *testing.T) {
	dir := t.TempDir()
	if err := config.Initialize(filepath.Join(dir, "installation"), "https://auth.example.test", false); err != nil {
		t.Fatal(err)
	}
	dump := filepath.Join(dir, "database.dump")
	if err := os.WriteFile(dump, []byte("synthetic archive bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	files, err := inventory(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{Version: 1, ID: "synthetic-recovery", SchemaVersion: identity.SchemaVersion, CreatedAt: time.Now().UTC(), Files: files}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.WriteExclusive(filepath.Join(dir, "manifest.json"), data); err != nil {
		t.Fatal(err)
	}
	if _, receipt, err := Verify(dir); err != nil || receipt.ID != manifest.ID || len(receipt.SHA256) != 64 {
		t.Fatal(receipt, err)
	}
	for _, change := range []string{"modified dump", "missing dump", "extra file", "changed key"} {
		t.Run(change, func(t *testing.T) {
			var path string
			var original []byte
			switch change {
			case "modified dump", "missing dump":
				path = dump
			case "extra file":
				path = filepath.Join(dir, "unexpected")
			case "changed key":
				path = filepath.Join(dir, "installation", "signing-key.pem")
			}
			if change != "extra file" {
				original, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			if change == "missing dump" {
				err = os.Remove(path)
			} else {
				err = os.WriteFile(path, []byte("changed"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := Verify(dir); err == nil {
				t.Fatal("accepted mismatched recovery set")
			}
			if change == "extra file" {
				err = os.Remove(path)
			} else {
				err = os.WriteFile(path, original, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
