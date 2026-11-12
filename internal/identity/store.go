package identity

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

const organizationColumns = "id,name,status,created_at,updated_at"
const memberColumns = "id,organization_id,display_name,manual_block,external_departure,created_at,updated_at"
const factorColumns = "id,type,namespace,subject,status,created_at,updated_at"
const bindingColumns = "id::text,member_id,organization_id,authentication_factor_id,factor_type,status,created_at,revoked_at"

func readOrganization(row pgx.Row) (Organization, error) {
	var organization Organization
	err := row.Scan(&organization.ID, &organization.Name, &organization.Status, &organization.CreatedAt, &organization.UpdatedAt)
	organization.CreatedAt = organization.CreatedAt.UTC()
	organization.UpdatedAt = organization.UpdatedAt.UTC()
	return organization, storageError(err)
}

func readMember(row pgx.Row) (Member, error) {
	var member Member
	var manual, departed bool
	err := row.Scan(&member.ID, &member.OrganizationID, &member.DisplayName, &manual, &departed, &member.CreatedAt, &member.UpdatedAt)
	member.Status, member.BlockSources = "active", []string{}
	if manual {
		member.BlockSources = append(member.BlockSources, "manual")
	}
	if departed {
		member.BlockSources = append(member.BlockSources, "externalDeparture")
	}
	if len(member.BlockSources) > 0 {
		member.Status = "blocked"
	}
	member.CreatedAt, member.UpdatedAt = member.CreatedAt.UTC(), member.UpdatedAt.UTC()
	return member, storageError(err)
}

func readFactor(row pgx.Row) (Factor, error) {
	var factor Factor
	err := row.Scan(&factor.ID, &factor.Type, &factor.Namespace, &factor.Subject, &factor.Status, &factor.CreatedAt, &factor.UpdatedAt)
	factor.CreatedAt, factor.UpdatedAt = factor.CreatedAt.UTC(), factor.UpdatedAt.UTC()
	return factor, storageError(err)
}

func readBinding(row pgx.Row) (Binding, error) {
	var binding Binding
	err := row.Scan(&binding.ID, &binding.MemberID, &binding.OrganizationID, &binding.FactorID, &binding.FactorType, &binding.Status, &binding.CreatedAt, &binding.RevokedAt)
	binding.CreatedAt = binding.CreatedAt.UTC()
	if binding.RevokedAt != nil {
		value := binding.RevokedAt.UTC()
		binding.RevokedAt = &value
	}
	return binding, storageError(err)
}

func (store *Store) CreateOrganization(ctx context.Context, id, name string) (Organization, error) {
	if !validText(name, 128) {
		return Organization{}, ErrInvalid
	}
	if id == "" {
		var err error
		id, err = NewID(OrganizationKind)
		if err != nil {
			return Organization{}, err
		}
	}
	if !ValidID(id, OrganizationKind) {
		return Organization{}, ErrInvalid
	}
	return readOrganization(store.pool.QueryRow(ctx, "INSERT INTO organizations(id,name) VALUES($1,$2) RETURNING "+organizationColumns, id, name))
}

func (store *Store) Organization(ctx context.Context, id string) (Organization, error) {
	if !ValidID(id, OrganizationKind) {
		return Organization{}, ErrInvalid
	}
	return readOrganization(store.pool.QueryRow(ctx, "SELECT "+organizationColumns+" FROM organizations WHERE id=$1", id))
}

func (store *Store) CreateMember(ctx context.Context, organizationID, id, name string) (Member, error) {
	if !ValidID(organizationID, OrganizationKind) || !validText(name, 128) {
		return Member{}, ErrInvalid
	}
	if id == "" {
		var err error
		id, err = NewID(MemberKind)
		if err != nil {
			return Member{}, err
		}
	}
	if !ValidID(id, MemberKind) {
		return Member{}, ErrInvalid
	}
	return readMember(store.pool.QueryRow(ctx, "INSERT INTO members(id,organization_id,display_name) VALUES($1,$2,$3) RETURNING "+memberColumns, id, organizationID, name))
}

func (store *Store) Member(ctx context.Context, organizationID, memberID string) (Member, error) {
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) {
		return Member{}, ErrInvalid
	}
	return readMember(store.pool.QueryRow(ctx, "SELECT "+memberColumns+" FROM members WHERE id=$1 AND organization_id=$2", memberID, organizationID))
}

// Manual blocking and provider departure are independent evidence sources.
func (store *Store) SetManualBlock(ctx context.Context, organizationID, memberID string, blocked bool) (Member, error) {
	return store.setMemberBlock(ctx, organizationID, memberID, "manual_block", blocked)
}

func (store *Store) SetExternalDeparture(ctx context.Context, organizationID, memberID string, departed bool) (Member, error) {
	return store.setMemberBlock(ctx, organizationID, memberID, "external_departure", departed)
}

func (store *Store) setMemberBlock(ctx context.Context, organizationID, memberID, column string, value bool) (Member, error) {
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) {
		return Member{}, ErrInvalid
	}
	return readMember(store.pool.QueryRow(ctx, "UPDATE members SET "+column+"=$3,updated_at=clock_timestamp() WHERE id=$1 AND organization_id=$2 RETURNING "+memberColumns, memberID, organizationID, value))
}

// EnsureFactor records provider-verified evidence; it never infers a Member binding.
func (store *Store) EnsureFactor(ctx context.Context, kind, namespace, subject string) (Factor, error) {
	return ensureFactor(ctx, store.pool, kind, namespace, subject)
}

type queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func ensureFactor(ctx context.Context, database queryer, kind, namespace, subject string) (Factor, error) {
	if !validFactorType(kind) || !validText(namespace, 512) || !validText(subject, 512) {
		return Factor{}, ErrInvalid
	}
	id, err := NewID(FactorKind)
	if err != nil {
		return Factor{}, err
	}
	factor, err := readFactor(database.QueryRow(ctx, "INSERT INTO authentication_factors(id,type,namespace,subject) VALUES($1,$2,$3,$4) ON CONFLICT(type,namespace,subject) DO UPDATE SET subject=EXCLUDED.subject RETURNING "+factorColumns, id, kind, namespace, subject))
	if err == nil && factor.Status != "active" {
		return Factor{}, ErrIneligible
	}
	return factor, err
}

func (store *Store) Factor(ctx context.Context, id string) (Factor, error) {
	if !ValidID(id, FactorKind) {
		return Factor{}, ErrInvalid
	}
	return readFactor(store.pool.QueryRow(ctx, "SELECT "+factorColumns+" FROM authentication_factors WHERE id=$1", id))
}

// BindFactor is an explicit trusted operation, not proof of successful authentication.
// Revoked relationships still occupy their slots and are never silently replaced.
func (store *Store) BindFactor(ctx context.Context, organizationID, memberID, factorID string) (Binding, error) {
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) || !ValidID(factorID, FactorKind) {
		return Binding{}, ErrInvalid
	}
	var result Binding
	err := pgx.BeginFunc(ctx, store.pool, func(transaction pgx.Tx) error {
		factor, err := readFactor(transaction.QueryRow(ctx, "SELECT "+factorColumns+" FROM authentication_factors WHERE id=$1 FOR UPDATE", factorID))
		if err != nil {
			return err
		}
		if factor.Status != "active" {
			return ErrIneligible
		}
		var existingMember string
		if err := transaction.QueryRow(ctx, "SELECT id FROM members WHERE id=$1 AND organization_id=$2", memberID, organizationID).Scan(&existingMember); err != nil {
			return storageError(err)
		}
		_, err = transaction.Exec(ctx, "INSERT INTO member_auth_factor_bindings(member_id,organization_id,authentication_factor_id,factor_type) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING", memberID, organizationID, factorID, factor.Type)
		if err != nil {
			return storageError(err)
		}
		result, err = readBinding(transaction.QueryRow(ctx, "SELECT "+bindingColumns+" FROM member_auth_factor_bindings WHERE member_id=$1 AND factor_type=$2", memberID, factor.Type))
		if errors.Is(err, ErrNotFound) || err == nil && (result.FactorID != factorID || result.Status != "active") {
			return ErrConflict
		}
		return err
	})
	return result, err
}

func (store *Store) RevokeBinding(ctx context.Context, organizationID, memberID, factorID string) error {
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) || !ValidID(factorID, FactorKind) {
		return ErrInvalid
	}
	result, err := store.pool.Exec(ctx, "UPDATE member_auth_factor_bindings SET status='revoked',revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE member_id=$1 AND organization_id=$2 AND authentication_factor_id=$3", memberID, organizationID, factorID)
	if err != nil {
		return storageError(err)
	}
	if result.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}
