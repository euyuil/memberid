package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/euyuil/memberid/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// SAMLServiceProvider is organization-owned protocol admission, not application authorization.
type SAMLServiceProvider struct {
	ID                    string   `json:"id"`
	DisplayName           string   `json:"displayName"`
	EntityID              string   `json:"entityId"`
	OrganizationID        string   `json:"organizationId"`
	ACSURL                string   `json:"acsUrl"`
	Enabled               bool     `json:"enabled"`
	AllowUnsignedRequests bool     `json:"allowUnsignedRequests"`
	SigningCertificates   []string `json:"signingCertificates"`
	Preauthorized         bool     `json:"preauthorized"`
	Attributes            []string `json:"attributes"`
	Revision              int64    `json:"revision"`
	Retired               bool     `json:"retired"`
}

func (sp SAMLServiceProvider) Validate(loopback bool) error {
	if !validSAMLServiceProviderID(sp.ID) || !ValidID(sp.OrganizationID, OrganizationKind) || sp.DisplayName != "" && !validText(sp.DisplayName, 128) {
		return ErrInvalid
	}
	entity, err := url.Parse(sp.EntityID)
	if err != nil || len(sp.EntityID) > 1024 || !entity.IsAbs() || entity.Fragment != "" || entity.User != nil || strings.ContainsAny(sp.EntityID, "\r\n\t ") {
		return ErrInvalid
	}
	acs, err := url.Parse(sp.ACSURL)
	if err != nil || acs.Hostname() == "" || acs.User != nil || acs.Fragment != "" || len(sp.ACSURL) > 2048 || strings.ContainsAny(sp.ACSURL, "*#\\\r\n\t ") || strings.ContainsAny(acs.Host, "\"'<>;") || acs.Scheme != "https" && !(loopback && acs.Scheme == "http" && acs.Hostname() == "127.0.0.1") {
		return ErrInvalid
	}
	if len(sp.Attributes) > 2 || len(sp.SigningCertificates) > 4 || !sp.AllowUnsignedRequests && len(sp.SigningCertificates) == 0 {
		return ErrInvalid
	}
	for index, attribute := range sp.Attributes {
		if attribute != "DisplayName" && attribute != "Email" || slices.Contains(sp.Attributes[:index], attribute) {
			return ErrInvalid
		}
	}
	for _, encoded := range sp.SigningCertificates {
		if len(encoded) > 32<<10 {
			return ErrInvalid
		}
		block, rest := pem.Decode([]byte(encoded))
		if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
			return ErrInvalid
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return ErrInvalid
		}
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok || key.N.BitLen() < 2048 || cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return ErrInvalid
		}
	}
	return nil
}

func validSAMLServiceProviderID(id string) bool {
	return len(id) >= 1 && len(id) <= 64 && strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") == ""
}

func readSAMLProvider(row pgx.Row) (SAMLServiceProvider, error) {
	var sp SAMLServiceProvider
	var data []byte
	var revision int64
	var retired bool
	if err := row.Scan(&data, &revision, &retired); err != nil {
		return sp, storageError(err)
	}
	if err := json.Unmarshal(data, &sp); err != nil {
		return sp, err
	}
	sp.Revision, sp.Retired = revision, retired
	return sp, nil
}

func (store *Store) SAMLServiceProvider(ctx context.Context, id string) (SAMLServiceProvider, error) {
	return readSAMLProvider(store.pool.QueryRow(ctx, "SELECT data,revision,retired_at IS NOT NULL FROM saml_service_providers WHERE id=$1", id))
}

func (store *Store) SAMLServiceProviderByEntityID(ctx context.Context, entityID string) (SAMLServiceProvider, error) {
	return readSAMLProvider(store.pool.QueryRow(ctx, "SELECT data,revision,retired_at IS NOT NULL FROM saml_service_providers WHERE entity_id=$1", entityID))
}

// LockSAMLServiceProvider serializes issuance with registration policy changes.
func LockSAMLServiceProvider(ctx context.Context, tx pgx.Tx, id string) (SAMLServiceProvider, error) {
	return readSAMLProvider(tx.QueryRow(ctx, "SELECT data,revision,retired_at IS NOT NULL FROM saml_service_providers WHERE id=$1 FOR SHARE", id))
}

func (store *Store) SAMLServiceProviders(ctx context.Context) ([]SAMLServiceProvider, error) {
	rows, err := store.pool.Query(ctx, "SELECT data,revision,retired_at IS NOT NULL FROM saml_service_providers ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []SAMLServiceProvider{}
	for rows.Next() {
		sp, err := readSAMLProvider(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, sp)
	}
	return result, rows.Err()
}

// PutSAMLServiceProvider is the installation entry point. Console callers use
// ManagementService, which retains Member authority instead of impersonating an operator.
func (store *Store) PutSAMLServiceProvider(ctx context.Context, principal Principal, sp SAMLServiceProvider, loopback bool) (SAMLServiceProvider, error) {
	if !principal.installation() {
		return SAMLServiceProvider{}, ErrForbidden
	}
	return store.putSAMLServiceProvider(ctx, principal, sp, loopback)
}

func (store *Store) putSAMLServiceProvider(ctx context.Context, principal Principal, sp SAMLServiceProvider, loopback bool) (SAMLServiceProvider, error) {
	if err := sp.Validate(loopback); err != nil || sp.Revision < 0 {
		return SAMLServiceProvider{}, ErrInvalid
	}
	return store.mutateSAMLServiceProvider(ctx, principal, sp.OrganizationID, sp.ID, sp.Revision, &sp)
}

func (store *Store) mutateSAMLServiceProvider(ctx context.Context, principal Principal, organizationID, id string, revision int64, update *SAMLServiceProvider) (SAMLServiceProvider, error) {
	var result SAMLServiceProvider
	if !ValidID(organizationID, OrganizationKind) || !validSAMLServiceProviderID(id) || revision < 0 || update == nil && revision == 0 {
		return result, ErrInvalid
	}
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		requirements := []authorization.Requirement{samlServiceProviderResource.require(actionUpdate, organizationID, id), samlServiceProviderResource.require(actionStatusUpdate, organizationID, id)}
		if update == nil || update.Retired {
			requirements = []authorization.Requirement{samlServiceProviderResource.require(actionDelete, organizationID, id)}
		} else if revision == 0 {
			requirements = []authorization.Requirement{samlServiceProvidersResource.require(actionCreate, organizationID)}
		}
		if err := authorizeAll(ctx, tx, principal, requirements...); err != nil {
			return err
		}
		current, err := readSAMLProvider(tx.QueryRow(ctx, "SELECT data,revision,retired_at IS NOT NULL FROM saml_service_providers WHERE id=$1 FOR UPDATE", id))
		var previous map[string]any
		if errors.Is(err, ErrNotFound) {
			if revision != 0 || update == nil || update.Retired {
				return ErrConflict
			}
		} else if err != nil {
			return err
		} else {
			if current.OrganizationID != organizationID {
				return ErrNotFound
			}
			if current.Retired || current.Revision != revision || update != nil && current.EntityID != update.EntityID {
				return ErrConflict
			}
			data, err := json.Marshal(current)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(data, &previous); err != nil {
				return err
			}
		}
		sp := current
		if update != nil {
			sp = *update
		} else {
			sp.Retired = true
		}
		sp.Revision = revision + 1
		if sp.Retired {
			sp.Enabled = false
		}
		data, err := json.Marshal(sp)
		if err != nil {
			return err
		}
		var retired *time.Time
		if sp.Retired {
			now := time.Now().UTC()
			retired = &now
		}
		_, err = tx.Exec(ctx, `INSERT INTO saml_service_providers(id,entity_id,organization_id,revision,data,retired_at) VALUES($1,$2,$3,$4,$5,$6)
 ON CONFLICT(id) DO UPDATE SET revision=EXCLUDED.revision,data=EXCLUDED.data,retired_at=EXCLUDED.retired_at`, sp.ID, sp.EntityID, sp.OrganizationID, sp.Revision, data, retired)
		if err != nil {
			return storageError(err)
		}
		if err := managementEvent(ctx, tx, principal, sp.OrganizationID, "", "saml.serviceProvider.configure", sp, previous); err != nil {
			return err
		}
		result = sp
		return nil
	})
	if err != nil {
		return SAMLServiceProvider{}, err
	}
	return result, nil
}

// SAMLNameID never uses profile attributes, provider subjects, or an operator-
// supplied identifier. Retired registrations retain their mappings permanently.
func SAMLNameID(ctx context.Context, tx pgx.Tx, sp SAMLServiceProvider, memberID string, allowCreate bool) (string, error) {
	var value string
	err := tx.QueryRow(ctx, "SELECT value FROM saml_name_ids WHERE service_provider_id=$1 AND member_id=$2", sp.ID, memberID).Scan(&value)
	if err == nil {
		return value, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if !allowCreate {
		return "", ErrNotFound
	}
	value = rand.Text()
	err = tx.QueryRow(ctx, `INSERT INTO saml_name_ids(service_provider_id,member_id,value)
 SELECT $1,id,$3 FROM members WHERE id=$2 AND organization_id=$4
 ON CONFLICT(service_provider_id,member_id) DO UPDATE SET value=saml_name_ids.value RETURNING value`, sp.ID, memberID, value, sp.OrganizationID).Scan(&value)
	return value, storageError(err)
}

// LockSAMLMemberEvidence prevents a concurrent local eligibility mutation from
// committing between the final check and assertion issuance.
func LockSAMLMemberEvidence(ctx context.Context, tx pgx.Tx, sp SAMLServiceProvider, memberID, factorID string) (string, error) {
	var binding string
	err := tx.QueryRow(ctx, "SELECT b.id::text"+eligibleBindings+" AND b.organization_id=$1 AND m.id=$2 AND f.id=$3 FOR SHARE OF b,m,o,f", sp.OrganizationID, memberID, factorID).Scan(&binding)
	if err != nil {
		return "", storageError(err)
	}
	var factorType, namespace string
	if err := tx.QueryRow(ctx, "SELECT type,namespace FROM authentication_factors WHERE id=$1", factorID).Scan(&factorType, &namespace); err != nil {
		return "", err
	}
	if slices.Contains([]string{"dingtalk", "feishu"}, factorType) {
		table := "dingtalk_applications"
		if factorType == "feishu" {
			table = "feishu_applications"
		}
		var enabled bool
		if err := tx.QueryRow(ctx, "SELECT enabled AND authorization_status='active' FROM "+table+" WHERE organization_id=$1 AND namespace=$2 FOR SHARE", sp.OrganizationID, namespace).Scan(&enabled); err != nil {
			return "", storageError(err)
		}
		if !enabled {
			return "", ErrIneligible
		}
	}
	return binding, nil
}
