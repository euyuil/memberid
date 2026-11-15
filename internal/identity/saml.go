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

	"github.com/jackc/pgx/v5"
)

// SAMLServiceProvider is operator-owned protocol admission, not application authorization.
type SAMLServiceProvider struct {
	ID                    string   `json:"id"`
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
	if len(sp.ID) < 1 || len(sp.ID) > 64 || strings.Trim(sp.ID, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" || !ValidID(sp.OrganizationID, OrganizationKind) {
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
	if len(sp.Attributes) > 1 || len(sp.Attributes) == 1 && sp.Attributes[0] != "DisplayName" || len(sp.SigningCertificates) > 4 || !sp.AllowUnsignedRequests && len(sp.SigningCertificates) == 0 {
		return ErrInvalid
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

// LockSAMLServiceProvider serializes issuance with operator policy changes.
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

// PutSAMLServiceProvider accepts only the in-process operator principal. Revision
// zero creates; subsequent writes require the currently inspected revision.
func (store *Store) PutSAMLServiceProvider(ctx context.Context, principal Principal, sp SAMLServiceProvider, loopback bool) (SAMLServiceProvider, error) {
	if principal.kind != operatorPrincipal {
		return sp, ErrForbidden
	}
	if err := sp.Validate(loopback); err != nil || sp.Revision < 0 {
		return sp, ErrInvalid
	}
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		current, err := readSAMLProvider(tx.QueryRow(ctx, "SELECT data,revision,retired_at IS NOT NULL FROM saml_service_providers WHERE id=$1 FOR UPDATE", sp.ID))
		if errors.Is(err, ErrNotFound) {
			if sp.Revision != 0 || sp.Retired {
				return ErrConflict
			}
		} else if err != nil {
			return err
		} else if current.Retired || current.Revision != sp.Revision || current.EntityID != sp.EntityID || current.OrganizationID != sp.OrganizationID {
			return ErrConflict
		}
		sp.Revision++
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
		return managementEvent(ctx, tx, principal, sp.OrganizationID, "", "saml.serviceProvider.configure", sp, nil)
	})
	return sp, err
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
		if err := tx.QueryRow(ctx, "SELECT enabled AND authorization_status='active' FROM "+table+" WHERE organization_id=$1 AND namespace=$2 FOR SHARE", sp.OrganizationID, namespace).Scan(&enabled); err != nil || !enabled {
			return "", ErrIneligible
		}
	}
	return binding, nil
}
