package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// RotateManagementSecret saves a new credential before replacing its verifier.
// The operator must protect both directories and restart management processes.
func RotateManagementSecret(directory, outputFile string) error {
	if directory == "" || outputFile == "" {
		return errors.New("installation directory and a new credential file are required")
	}
	lockName := filepath.Join(directory, ".management-secret.lock")
	lock, err := os.OpenFile(lockName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("management credential configuration is locked or unavailable")
	}
	defer os.Remove(lockName)
	if err := lock.Close(); err != nil {
		return err
	}
	loaded, err := Load(directory)
	if err != nil {
		return err
	}
	secret := RandomSecret()
	loaded.Secrets.ManagementSecretSHA256 = SecretHash(secret)
	data, err := json.MarshalIndent(loaded.Secrets, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".management-secret-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	if err := temporary.Chmod(0600); err != nil {
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	// Never overwrite an operator file. If this or the final replacement fails,
	// a candidate file can remain, but it does not establish successful rotation.
	if err := writeExclusive(outputFile, []byte(secret+"\n")); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), filepath.Join(directory, loaded.SecretsFile))
}
