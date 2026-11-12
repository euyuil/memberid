package config

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/euyuil/memberid/internal/identity"
)

const MaximumFileSize = 1 << 20

// Installation contains references to protected local files, not database credentials.
type Installation struct {
	Issuer            string `json:"issuer"`
	AllowLoopbackHTTP bool   `json:"allowLoopbackHttp"`
	SigningKeyFile    string `json:"signingKeyFile"`
	PublicKeysFile    string `json:"publicKeysFile"`
	SecretsFile       string `json:"secretsFile"`
	ClientsFile       string `json:"clientsFile"`
}

type Secrets struct {
	ProtocolKey            string `json:"protocolKey"`
	PhoneCodeKey           string `json:"phoneCodeKey"`
	ProviderKey            string `json:"providerKey"`
	ManagementSecretSHA256 string `json:"managementSecretSha256"`
}

// Client is operator-controlled registration, not a dynamic registration endpoint.
type Client struct {
	ID                     string   `json:"client_id"`
	SecretSHA256           string   `json:"secret_sha256"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	AccountReturnURIs      []string `json:"accountReturnUris,omitempty"`
	OrganizationID         string   `json:"organizationId,omitempty"`
	SubjectKind            string   `json:"subjectKind"`
	EvidenceScope          string   `json:"evidenceScope,omitempty"`
	EvidenceAudience       string   `json:"evidenceAudience,omitempty"`
	Refresh                bool     `json:"refresh,omitempty"`
	Preauthorized          bool     `json:"preauthorized,omitempty"`
}

type Loaded struct {
	Installation
	Secrets    Secrets
	Clients    []Client
	SigningKey *rsa.PrivateKey
	KeyID      string
	PublicKeys map[string]*rsa.PublicKey
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
	result := new(Loaded)
	if err := ReadJSON(filepath.Join(directory, "memberid.json"), &result.Installation); err != nil {
		return nil, err
	}
	if err := result.Installation.Validate(); err != nil {
		return nil, err
	}
	if err := ReadJSON(filepath.Join(directory, result.SecretsFile), &result.Secrets); err != nil {
		return nil, err
	}
	if err := result.Secrets.Validate(); err != nil {
		return nil, err
	}
	if err := ReadJSON(filepath.Join(directory, result.ClientsFile), &result.Clients); err != nil {
		return nil, err
	}
	if err := ValidateClients(result.Clients, result.AllowLoopbackHTTP); err != nil {
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
	retained, ok := result.PublicKeys[result.KeyID]
	if !ok || !retained.Equal(&result.SigningKey.PublicKey) {
		return nil, errors.New("public key set must include the active signing key")
	}
	return result, nil
}

func (installation Installation) Validate() error {
	issuer, err := exactURL(installation.Issuer, installation.AllowLoopbackHTTP)
	if err != nil || issuer.Path != "" || issuer.RawQuery != "" || issuer.ForceQuery {
		return errors.New("issuer must be an exact HTTPS origin; loopback HTTP requires explicit development configuration")
	}
	for _, file := range []string{installation.SigningKeyFile, installation.PublicKeysFile, installation.SecretsFile, installation.ClientsFile} {
		if file == "" || filepath.IsAbs(file) || filepath.Base(file) != file || file == "." || file == ".." || strings.ContainsAny(file, `/\:`) {
			return errors.New("configuration references must be local file names")
		}
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

var clientID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var evidenceScope = regexp.MustCompile(`^[a-z][a-z0-9:_-]{0,127}$`)

func ValidateClients(clients []Client, allowLoopback bool) error {
	seen := map[string]bool{}
	for _, client := range clients {
		if !clientID.MatchString(client.ID) || seen[client.ID] || !validHash(client.SecretSHA256) {
			return errors.New("invalid or repeated client identifier or credential verifier")
		}
		seen[client.ID] = true
		if client.SubjectKind != "member" && client.SubjectKind != "factor" {
			return errors.New("client subjectKind must be member or factor")
		}
		if client.OrganizationID != "" && !identity.ValidID(client.OrganizationID, identity.OrganizationKind) {
			return errors.New("invalid client organization restriction")
		}
		if len(client.RedirectURIs) == 0 {
			return errors.New("client requires an exact redirect URI")
		}
		for _, list := range [][]string{client.RedirectURIs, client.PostLogoutRedirectURIs, client.AccountReturnURIs} {
			locations := map[string]bool{}
			for _, location := range list {
				if _, err := exactURL(location, allowLoopback); err != nil || locations[location] {
					return errors.New("client return locations must be distinct exact HTTPS URLs or explicitly enabled loopback HTTP")
				}
				locations[location] = true
			}
		}
		if (client.EvidenceScope == "") != (client.EvidenceAudience == "") {
			return errors.New("evidence scope and audience must be configured together")
		}
		if client.EvidenceScope != "" {
			if !evidenceScope.MatchString(client.EvidenceScope) || strings.Contains(" openid profile email phone address offline_access ", " "+client.EvidenceScope+" ") {
				return errors.New("evidence scope must be a distinct custom scope")
			}
			audience, err := exactURL(client.EvidenceAudience, allowLoopback)
			if err != nil || audience.RawQuery != "" || audience.ForceQuery {
				return errors.New("evidence audience must be an exact resource URL")
			}
		}
		if client.SubjectKind == "factor" && (client.OrganizationID != "" || client.EvidenceScope == "") {
			return errors.New("factor clients require explicit evidence policy and cannot claim organization membership")
		}
	}
	return nil
}

func exactURL(raw string, allowLoopback bool) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || strings.ContainsAny(raw, "*#\\\r\n\t ") || parsed.Opaque != "" || (parsed.Scheme != "https" && !(allowLoopback && parsed.Scheme == "http" && parsed.Hostname() == "127.0.0.1")) {
		return nil, errors.New("invalid URL")
	}
	if parsed.Port() != "" {
		var port int
		if _, err := fmt.Sscanf(parsed.Port(), "%d", &port); err != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid URL port")
		}
	}
	return parsed, nil
}

func validHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
