package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
)

// Initialize creates a new directory exclusively. Existing installations are never overwritten.
func Initialize(directory, issuer string, allowLoopback bool) error {
	installation := Installation{Issuer: issuer, AllowLoopbackHTTP: allowLoopback, SigningKeyFile: "signing-key.pem", PublicKeysFile: "public-keys.pem", SecretsFile: "secrets.json"}
	if err := installation.Validate(); err != nil {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	randomKey := func() string {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			panic(err)
		}
		return base64.StdEncoding.EncodeToString(key[:])
	}
	managementSecret := RandomSecret()
	secrets := Secrets{ProtocolKey: randomKey(), PhoneCodeKey: randomKey(), ProviderKey: randomKey(), ManagementSecretSHA256: SecretHash(managementSecret)}
	if err := os.Mkdir(directory, 0700); err != nil {
		return errors.New("create a new installation directory inside an existing protected parent; existing directories are refused")
	}
	files := map[string]any{"memberid.json": installation, "secrets.json": secrets}
	for name, value := range files {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		if err := WriteExclusive(filepath.Join(directory, name), append(data, '\n')); err != nil {
			return err
		}
	}
	for name, data := range map[string][]byte{
		"signing-key.pem":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}),
		"public-keys.pem":   pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}),
		"management-secret": []byte(managementSecret + "\n"),
	} {
		if err := WriteExclusive(filepath.Join(directory, name), data); err != nil {
			return err
		}
	}
	return nil
}

// WriteExclusive creates and syncs an owner-only file in a protected directory.
// The caller must arrange the directory's access controls, including Windows ACLs.
func WriteExclusive(file string, data []byte) error {
	handle, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer handle.Close()
	if _, err := handle.Write(data); err != nil {
		return err
	}
	if err := handle.Sync(); err != nil {
		return err
	}
	return handle.Close()
}
