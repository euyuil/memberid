package identity

import (
	"context"
	"regexp"
)

var organizationSlugPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func ValidOrganizationSlug(slug string) bool {
	return len(slug) <= 63 && organizationSlugPattern.MatchString(slug)
}

// AssignOrganizationSlug reserves both identifiers in one insert. Disabled
// organizations retain their mapping, and there is no reassignment operation.
func (store *Store) AssignOrganizationSlug(ctx context.Context, principal Principal, id, slug string) error {
	if principal.kind != operatorPrincipal {
		return ErrForbidden
	}
	if !ValidID(id, OrganizationKind) || id == store.systemOrganizationID || slug == SystemOrganizationSlug || !ValidOrganizationSlug(slug) {
		return ErrInvalid
	}
	_, err := store.pool.Exec(ctx, "INSERT INTO organization_login_slugs(organization_id,slug) VALUES($1,$2)", id, slug)
	return storageError(err)
}

func (store *Store) LoginOrganizationIDBySlug(ctx context.Context, slug string) (string, error) {
	if !ValidOrganizationSlug(slug) {
		return "", ErrInvalid
	}
	var id string
	err := store.pool.QueryRow(ctx, `SELECT o.id FROM organization_login_slugs s
		JOIN organizations o ON o.id=s.organization_id WHERE s.slug=$1 AND o.status='enabled'`, slug).Scan(&id)
	return id, storageError(err)
}
