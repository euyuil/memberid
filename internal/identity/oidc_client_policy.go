package identity

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// OIDCClient is the protocol policy and credential verifier for one registered client.
type OIDCClient struct {
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

var clientID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validOIDCClientID(id string) bool { return clientID.MatchString(id) }

var evidenceScope = regexp.MustCompile(`^[a-z][a-z0-9:_-]{0,127}$`)

func ValidateOIDCClients(clients []OIDCClient, allowLoopback bool) error {
	return validateClients(clients, allowLoopback, false)
}

// ValidateLegacyOIDCClients checks the source configuration during an explicit upgrade.
func ValidateLegacyOIDCClients(clients []OIDCClient, allowLoopback bool) error {
	return validateClients(clients, allowLoopback, true)
}

func validateClients(clients []OIDCClient, allowLoopback, legacy bool) error {
	seen := map[string]bool{}
	for _, client := range clients {
		if !validOIDCClientID(client.ID) || seen[client.ID] || !validOIDCSecretHash(client.SecretSHA256) {
			return errors.New("invalid or repeated client identifier or credential verifier")
		}
		seen[client.ID] = true
		if client.SubjectKind != "member" && client.SubjectKind != "factor" {
			return errors.New("client subjectKind must be member or factor")
		}
		if client.OrganizationID != "" && !ValidID(client.OrganizationID, OrganizationKind) && !(legacy && client.OrganizationID == "org_system") {
			return errors.New("invalid client organization restriction")
		}
		if len(client.RedirectURIs) == 0 {
			return errors.New("client requires an exact redirect URI")
		}
		for _, list := range [][]string{client.RedirectURIs, client.PostLogoutRedirectURIs, client.AccountReturnURIs} {
			locations := map[string]bool{}
			for _, location := range list {
				if _, err := ParseExactURL(location, allowLoopback); err != nil || locations[location] {
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
			audience, err := ParseExactURL(client.EvidenceAudience, allowLoopback)
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

func ParseExactURL(raw string, allowLoopback bool) (*url.URL, error) {
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

func validOIDCSecretHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
