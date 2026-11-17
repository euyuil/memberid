package config

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/euyuil/memberid/internal/identity"
)

const MaximumFileSize = 1 << 20

// Installation contains references to protected local files, not database credentials.
type Installation struct {
	SAML                             *SAML                    `json:"saml,omitempty"`
	AuthenticationEventRetentionDays int                      `json:"authenticationEventRetentionDays,omitempty"`
	PhoneSendLimitsPerHour           identity.PhoneSendLimits `json:"phoneSendLimitsPerHour,omitzero"`
	PhoneTrustedProxyCIDRs           []string                 `json:"phoneTrustedProxyCidrs,omitempty"`
	Issuer                           string                   `json:"issuer"`
	AllowLoopbackHTTP                bool                     `json:"allowLoopbackHttp"`
	SigningKeyFile                   string                   `json:"signingKeyFile"`
	PublicKeysFile                   string                   `json:"publicKeysFile"`
	SecretsFile                      string                   `json:"secretsFile"`
	ClientsFile                      string                   `json:"clientsFile,omitempty"`
}

type Secrets struct {
	ProtocolKey            string `json:"protocolKey"`
	PhoneCodeKey           string `json:"phoneCodeKey"`
	ProviderKey            string `json:"providerKey"`
	ManagementSecretSHA256 string `json:"managementSecretSha256"`
}

// Client is the registration format used by legacy installation backups.
type Client = identity.OIDCClient

type Loaded struct {
	Installation
	SAMLSigning *SAMLSigning
	Secrets     Secrets
	SigningKey  *rsa.PrivateKey
	KeyID       string
	PublicKeys  map[string]*rsa.PublicKey
}

func ReadJSON(file string, target any) error {
	handle, err := os.Open(file)
	if err != nil {
		return err
	}
	defer handle.Close()
	decoder := json.NewDecoder(io.LimitReader(handle, MaximumFileSize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid configuration JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("configuration must contain one JSON value")
	}
	info, err := handle.Stat()
	if err != nil || info.Size() > MaximumFileSize {
		return errors.New("configuration file is too large")
	}
	return nil
}

func Load(directory string) (*Loaded, error) {
	return load(directory, nil, false)
}

// Signing inspection can read an expired certificate without making it usable
// by a running server. An override validates candidate files before activation.
func load(directory string, samlOverride *SAML, inspectSigning bool) (*Loaded, error) {
	result := new(Loaded)
	if err := ReadJSON(filepath.Join(directory, "memberid.json"), &result.Installation); err != nil {
		return nil, err
	}
	if err := result.Installation.Validate(); err != nil {
		return nil, err
	}
	if samlOverride != nil {
		result.SAML = samlOverride
	}
	var signingErr error
	result.SAMLSigning, signingErr = readSAMLSigning(directory, result.SAML)
	if signingErr != nil {
		return nil, signingErr
	}
	if result.SAMLSigning != nil && !inspectSigning {
		if err := result.SAMLSigning.Validate(time.Now()); err != nil {
			return nil, err
		}
	}
	if err := ReadJSON(filepath.Join(directory, result.SecretsFile), &result.Secrets); err != nil {
		return nil, err
	}
	if err := result.Secrets.Validate(); err != nil {
		return nil, err
	}
	var err error
	result.SigningKey, err = ReadSigningKey(filepath.Join(directory, result.SigningKeyFile))
	if err != nil {
		return nil, err
	}
	result.PublicKeys, err = ReadPublicKeys(filepath.Join(directory, result.PublicKeysFile))
	if err != nil {
		return nil, err
	}
	result.KeyID = KeyID(&result.SigningKey.PublicKey)
	if result.SAMLSigning != nil {
		if _, reused := result.PublicKeys[KeyID(&result.SAMLSigning.Key.PublicKey)]; reused {
			return nil, errors.New("SAML must use a separate signing key from OIDC")
		}
	}
	retained, ok := result.PublicKeys[result.KeyID]
	if !ok || !retained.Equal(&result.SigningKey.PublicKey) {
		return nil, errors.New("public key set must include the active signing key")
	}
	return result, nil
}

func (installation Installation) Validate() error {
	if installation.AuthenticationEventRetentionDays < 0 || installation.AuthenticationEventRetentionDays > 36500 {
		return errors.New("authentication event retention must be 1 through 36500 days; zero selects 90 days")
	}
	if _, err := installation.PhoneSendLimitsPerHour.WithDefaults(); err != nil {
		return errors.New("phone send limits must be nonnegative; zero selects defaults")
	}
	for _, value := range installation.PhoneTrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix.Bits() == 0 {
			return errors.New("phone trusted proxies must be explicit IPv4 or IPv6 CIDRs, not all addresses")
		}
	}
	issuer, err := identity.ParseExactURL(installation.Issuer, installation.AllowLoopbackHTTP)
	if err != nil || issuer.Path != "" || issuer.RawQuery != "" || issuer.ForceQuery {
		return errors.New("issuer must be an exact HTTPS origin; loopback HTTP requires explicit development configuration")
	}
	for _, file := range []string{installation.SigningKeyFile, installation.PublicKeysFile, installation.SecretsFile} {
		if file == "" || filepath.IsAbs(file) || filepath.Base(file) != file || file == "." || file == ".." || strings.ContainsAny(file, `/\:`) {
			return errors.New("configuration references must be local file names")
		}
	}
	if file := installation.ClientsFile; file != "" && (filepath.IsAbs(file) || filepath.Base(file) != file || file == "." || file == ".." || strings.ContainsAny(file, `/\:`)) {
		return errors.New("configuration references must be local file names")
	}
	return nil
}

func (secrets Secrets) Validate() error {
	for _, value := range []string{secrets.ProtocolKey, secrets.PhoneCodeKey, secrets.ProviderKey} {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			return errors.New("installation keys must encode 32 bytes")
		}
	}
	if !validHash(secrets.ManagementSecretSHA256) {
		return errors.New("invalid management credential verifier")
	}
	return nil
}

// LoadLegacyClients reads the installation-bound registry for a schema 26–28 backup.
func LoadLegacyClients(directory string, installation Installation) ([]Client, error) {
	if installation.ClientsFile == "" {
		return nil, errors.New("legacy installation must reference its OIDC client registry")
	}
	var clients []Client
	if err := ReadJSON(filepath.Join(directory, installation.ClientsFile), &clients); err != nil {
		return nil, err
	}
	if err := ValidateClients(clients, installation.AllowLoopbackHTTP); err != nil {
		return nil, err
	}
	return clients, nil
}

func ValidateClients(clients []Client, allowLoopback bool) error {
	return identity.ValidateOIDCClients(clients, allowLoopback)
}

func validHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

// AuthenticationEventRetention is shared by writers, cleanup, and query expiry.
func (installation Installation) AuthenticationEventRetention() time.Duration {
	days := installation.AuthenticationEventRetentionDays
	if days == 0 {
		days = 90
	}
	return time.Duration(days) * 24 * time.Hour
}
