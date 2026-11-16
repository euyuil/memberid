// Package recovery creates and verifies offline database/configuration recovery sets.
package recovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
)

type Manifest struct {
	Version       int               `json:"version"`
	ID            string            `json:"id"`
	SchemaVersion int               `json:"schemaVersion"`
	CreatedAt     time.Time         `json:"createdAt"`
	Files         map[string]string `json:"files"`
}

type diagnosticCount int64

func (count *diagnosticCount) Write(data []byte) (int, error) {
	*count += diagnosticCount(len(data))
	return len(data), nil
}

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// inventory rejects symlinks and special files rather than following them into
// other installations. The operator must quiesce all configuration writers.
func inventory(directory string, manifest bool) (map[string]string, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("recovery directory must be a real directory")
	}
	files := map[string]string{}
	err = filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("recovery set contains a symlink or special file")
		}
		rel, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		if manifest && rel == "manifest.json" {
			return nil
		}
		hash, err := fileHash(path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = hash
		return nil
	})
	return files, err
}

func copyInstallation(source, destination string) error {
	if err := os.Mkdir(destination, 0700); err != nil {
		return err
	}
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(destination, rel)
		if entry.IsDir() {
			return os.Mkdir(target, 0700)
		}
		if !entry.Type().IsRegular() {
			return errors.New("installation contains a symlink or special file")
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		syncErr := output.Sync()
		closeErr := output.Close()
		return errors.Join(copyErr, syncErr, closeErr)
	})
}

// Create is called only while UpgradeDatabase holds table locks excluding
// writes. pg_dump uses a separate read connection, then exits before migration.
func Create(ctx context.Context, databaseURL, directory, destination, pgDump, snapshot string, schemaVersion int) (identity.UpgradeBackup, error) {
	if schemaVersion < 26 || schemaVersion >= identity.SchemaVersion {
		return identity.UpgradeBackup{}, errors.New("unsupported recovery source schema")
	}
	var receipt identity.UpgradeBackup
	if snapshot == "" {
		return receipt, errors.New("an exported database snapshot is required")
	}
	if _, err := config.Load(directory); err != nil {
		return receipt, err
	}
	before, err := inventory(directory, false)
	if err != nil {
		return receipt, err
	}
	source, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return receipt, err
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return receipt, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(destination))
	if err != nil {
		return receipt, err
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return receipt, err
	}
	target := filepath.Join(parent, filepath.Base(destination))
	rel, err := filepath.Rel(source, target)
	if err != nil && strings.EqualFold(filepath.VolumeName(source), filepath.VolumeName(target)) {
		return receipt, err
	}
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return receipt, errors.New("backup must be outside the installation directory")
	}
	version, err := exec.CommandContext(ctx, pgDump, "--version").Output()
	if err != nil || !strings.HasPrefix(string(version), "pg_dump (PostgreSQL) 18.") {
		return receipt, errors.New("PostgreSQL 18 pg_dump is required")
	}
	if err := os.Mkdir(target, 0700); err != nil {
		return receipt, err
	}
	if err := copyInstallation(directory, filepath.Join(target, "installation")); err != nil {
		return receipt, err
	}
	dump, err := os.OpenFile(filepath.Join(target, "database.dump"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return receipt, err
	}
	command := exec.CommandContext(ctx, pgDump, "--format=custom", "--no-owner", "--no-acl", "--no-password", "--lock-wait-timeout=5s", "--snapshot="+snapshot)
	// libpq accepts a connection URI through PGDATABASE. Credentials never become
	// command arguments, backup metadata, error output or ordinary service logs.
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "PGDATABASE=") {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, "PGDATABASE="+databaseURL)
	command.Stdout = dump
	var diagnostics diagnosticCount
	command.Stderr = &diagnostics
	err = command.Run()
	syncErr, closeErr := dump.Sync(), dump.Close()
	if err != nil || diagnostics != 0 {
		return receipt, errors.New("pg_dump failed or reported warnings; incomplete recovery directory retained, database unchanged")
	}
	if err = errors.Join(syncErr, closeErr); err != nil {
		return receipt, err
	}
	// Verify both the copy and the still-quiescent source, including key files.
	copied, err := inventory(filepath.Join(target, "installation"), false)
	if err != nil {
		return receipt, err
	}
	after, err := inventory(directory, false)
	if err != nil {
		return receipt, err
	}
	if !reflect.DeepEqual(before, copied) || !reflect.DeepEqual(before, after) {
		return receipt, errors.New("installation changed during backup")
	}
	files, err := inventory(target, false)
	if err != nil {
		return receipt, err
	}
	manifest := Manifest{Version: 1, ID: rand.Text(), SchemaVersion: schemaVersion, CreatedAt: time.Now().UTC(), Files: files}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return receipt, err
	}
	data = append(data, '\n')
	if err := config.WriteExclusive(filepath.Join(target, "manifest.json"), data); err != nil {
		return receipt, err
	}
	_, receipt, err = Verify(target)
	return receipt, err
}

// Verify checks every file before the operator restores to new destinations.
// Hashes detect damage or mismatched sets, not a malicious backup administrator.
func Verify(directory string) (Manifest, identity.UpgradeBackup, error) {
	var manifest Manifest
	var receipt identity.UpgradeBackup
	if err := config.ReadJSON(filepath.Join(directory, "manifest.json"), &manifest); err != nil {
		return manifest, receipt, err
	}
	if manifest.Version != 1 || (manifest.SchemaVersion < 26 || manifest.SchemaVersion > identity.SchemaVersion) || manifest.ID == "" || manifest.CreatedAt.IsZero() {
		return manifest, receipt, errors.New("unsupported recovery manifest")
	}
	files, err := inventory(directory, true)
	if err != nil {
		return manifest, receipt, err
	}
	if len(files) < 2 || files["database.dump"] == "" || !reflect.DeepEqual(files, manifest.Files) {
		return manifest, receipt, errors.New("recovery file checksums do not match")
	}
	if _, err := config.Load(filepath.Join(directory, "installation")); err != nil {
		return manifest, receipt, fmt.Errorf("recovery configuration: %w", err)
	}
	digest, err := fileHash(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return manifest, receipt, err
	}
	receipt = identity.UpgradeBackup{ID: manifest.ID, SHA256: digest}
	return manifest, receipt, nil
}
