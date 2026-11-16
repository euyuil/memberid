package identity

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type SAMLNameIDMapping struct {
	OrganizationID    string    `json:"organizationId"`
	ServiceProviderID string    `json:"serviceProviderId"`
	MemberID          string    `json:"memberId"`
	Value             string    `json:"value"`
	NameIDFormat      string    `json:"nameIdFormat"`
	Source            string    `json:"source"`
	CreatedBy         string    `json:"createdBy"`
	CreatedAt         time.Time `json:"createdAt"`
}

func validLegacyNameID(value string) bool {
	return validText(value, 256) && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\ufffe\uffff")
}

func readSAMLNameIDMapping(ctx context.Context, db queryer, organizationID, serviceProviderID, memberID string) (SAMLNameIDMapping, error) {
	result := SAMLNameIDMapping{OrganizationID: organizationID, ServiceProviderID: serviceProviderID, MemberID: memberID}
	err := db.QueryRow(ctx, `SELECT n.value,s.data->>'nameIdFormat',n.source,n.created_by,n.created_at
 FROM saml_name_ids n JOIN saml_service_providers s ON s.id=n.service_provider_id
 JOIN members m ON m.id=n.member_id AND m.organization_id=s.organization_id
 WHERE s.organization_id=$1 AND s.id=$2 AND n.member_id=$3`, organizationID, serviceProviderID, memberID).
		Scan(&result.Value, &result.NameIDFormat, &result.Source, &result.CreatedBy, &result.CreatedAt)
	return result, storageError(err)
}

// InspectSAMLNameID is operator-only and never allocates an absent mapping.
func (store *Store) InspectSAMLNameID(ctx context.Context, principal Principal, organizationID, serviceProviderID, memberID string) (SAMLNameIDMapping, error) {
	if principal.kind != operatorPrincipal {
		return SAMLNameIDMapping{}, ErrForbidden
	}
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) || !validSAMLServiceProviderID(serviceProviderID) {
		return SAMLNameIDMapping{}, ErrInvalid
	}
	return readSAMLNameIDMapping(ctx, store.pool, organizationID, serviceProviderID, memberID)
}

// ProvisionSAMLNameID establishes a legacy value before any allocation for this
// pair. No replacement, deletion, reassignment or caller-selected actor exists.
// Legacy values use unspecified; persistent identifiers remain random pseudonyms.
func (store *Store) ProvisionSAMLNameID(ctx context.Context, principal Principal, organizationID, serviceProviderID, memberID, value string, revision int64) (SAMLNameIDMapping, error) {
	var result SAMLNameIDMapping
	if principal.kind != operatorPrincipal {
		return result, ErrForbidden
	}
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) || !validSAMLServiceProviderID(serviceProviderID) || !validLegacyNameID(value) || revision < 1 {
		return result, ErrInvalid
	}
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		// Same lock order as SP configuration and issuance: SP before Member.
		sp, err := readSAMLProvider(tx.QueryRow(ctx, "SELECT data,revision,retired_at IS NOT NULL FROM saml_service_providers WHERE organization_id=$1 AND id=$2 FOR UPDATE", organizationID, serviceProviderID))
		if err != nil {
			return err
		}
		if sp.Retired || sp.Revision != revision {
			return ErrConflict
		}
		if sp.NameIDFormat != "unspecified" {
			return ErrInvalid
		}
		var id string
		if err := tx.QueryRow(ctx, "SELECT id FROM members WHERE organization_id=$1 AND id=$2 FOR SHARE", organizationID, memberID).Scan(&id); err != nil {
			return storageError(err)
		}
		current, err := readSAMLNameIDMapping(ctx, tx, organizationID, serviceProviderID, memberID)
		if err == nil {
			if current.Source != "legacy" || current.Value != value {
				return ErrConflict
			}
			result = current
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		actor, err := principal.auditID()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO saml_name_ids(service_provider_id,member_id,value,source,created_by) VALUES($1,$2,$3,'legacy',$4)", serviceProviderID, memberID, value, actor); err != nil {
			return storageError(err)
		}
		result, err = readSAMLNameIDMapping(ctx, tx, organizationID, serviceProviderID, memberID)
		if err != nil {
			return err
		}
		return managementEvent(ctx, tx, principal, organizationID, memberID, "saml.nameId.provision", result, nil)
	})
	if err != nil {
		return SAMLNameIDMapping{}, err
	}
	return result, nil
}
