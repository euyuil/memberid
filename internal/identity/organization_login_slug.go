package identity

import (
	"context"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

var organizationSlugPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// CanonicalLoginName folds only ASCII letters in human-entered usernames and slugs.
func CanonicalLoginName(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, value)
}

func ValidOrganizationSlug(slug string) bool {
	return len(slug) <= 63 && organizationSlugPattern.MatchString(CanonicalLoginName(slug))
}

// ChangeOrganizationSlug compares the observed slug with the current mapping.
// Only an administrator who belongs to the organization can first assign its name.
func (service *ManagementService) ChangeOrganizationSlug(ctx context.Context, principal Principal, id, expected, slug string) error {
	if principal.kind != memberPrincipal {
		return ErrForbidden
	}
	expected, slug = CanonicalLoginName(expected), CanonicalLoginName(slug)
	if !ValidID(id, OrganizationKind) || !ValidOrganizationSlug(slug) || slug == SystemOrganizationSlug || expected != "" && !ValidOrganizationSlug(expected) {
		return ErrInvalid
	}
	if id == service.store.systemOrganizationID {
		return ErrForbidden
	}
	return pgx.BeginFunc(ctx, service.store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		actor, err := managementActor(ctx, tx, principal.memberID, principal.grantID)
		if err != nil {
			return err
		}
		action, event := actionUpdate, "organization.slug.update"
		if expected == "" {
			if actor.OrganizationID != id {
				return ErrForbidden
			}
			action, event = actionCreate, "organization.slug.create"
		}
		if err := checkManagementPermissions(managementPermissions(actor), organizationSlugResource.require(action, id)); err != nil {
			return err
		}
		if expected == "" {
			_, err = tx.Exec(ctx, "INSERT INTO organization_login_slugs(organization_id,slug) VALUES($1,$2)", id, slug)
			if err != nil {
				return storageError(err)
			}
		} else {
			result, err := tx.Exec(ctx, "UPDATE organization_login_slugs SET slug=$3 WHERE organization_id=$1 AND slug=$2", id, expected, slug)
			if err != nil {
				return storageError(err)
			}
			if result.RowsAffected() == 0 {
				return ErrConflict
			}
			if expected == slug {
				return nil
			}
		}
		return managementEvent(ctx, tx, principal, id, "", event, map[string]string{"slug": slug}, map[string]any{"slug": expected})
	})
}

// OrganizationLoginSuffix returns the current slug or the permanent ID for a password login.
func (store *Store) OrganizationLoginSuffix(ctx context.Context, id string) (string, error) {
	var suffix string
	err := store.pool.QueryRow(ctx, `SELECT COALESCE(s.slug,o.id) FROM organizations o
		LEFT JOIN organization_login_slugs s ON s.organization_id=o.id WHERE o.id=$1`, id).Scan(&suffix)
	return suffix, storageError(err)
}

func (store *Store) LoginOrganizationIDBySlug(ctx context.Context, slug string) (string, error) {
	if !ValidOrganizationSlug(slug) {
		return "", ErrInvalid
	}
	var id string
	err := store.pool.QueryRow(ctx, `SELECT o.id FROM organization_login_slugs s
		JOIN organizations o ON o.id=s.organization_id WHERE s.slug=$1 AND o.status='enabled'`, CanonicalLoginName(slug)).Scan(&id)
	return id, storageError(err)
}
