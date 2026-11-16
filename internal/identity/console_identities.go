package identity

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ConsoleIdentity describes an administrator reachable through the current
// console grant's verified phone. It carries no authority from another Member.
type ConsoleIdentity struct {
	MemberID         string `json:"memberId"`
	OrganizationID   string `json:"organizationId"`
	OrganizationName string `json:"organizationName"`
	DisplayName      string `json:"displayName"`
	Platform         bool   `json:"platform"`
}

func (service *ManagementService) consolePhoneSource(ctx context.Context, principal Principal) (factorID, sessionID string, err error) {
	if _, err = service.store.managementReadActor(ctx, principal); err != nil {
		return
	}
	err = service.store.pool.QueryRow(ctx, `SELECT data->>'factorId',session_id FROM oidc_grants
 WHERE id=$1 AND data->>'factorType'='phone'`, principal.grantID).Scan(&factorID, &sessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	return
}

// ConsoleIdentities is a self-service identity view, not an organization
// directory. Even platform administrators see only their verified phone's
// currently eligible, explicitly assigned administrator Members here.
func (service *ManagementService) ConsoleIdentities(ctx context.Context, principal Principal, after string, limit int) (Page[ConsoleIdentity], error) {
	page := Page[ConsoleIdentity]{Items: []ConsoleIdentity{}}
	if after != "" && !ValidID(after, MemberKind) || limit < 1 || limit > 100 {
		return page, ErrInvalid
	}
	factorID, _, err := service.consolePhoneSource(ctx, principal)
	if err != nil || factorID == "" {
		return page, err
	}
	rows, err := service.store.pool.Query(ctx, `SELECT m.id,m.organization_id,o.name,m.display_name`+eligibleBindings+`
 AND f.id=$1 AND m.id>$2 AND EXISTS(SELECT 1 FROM administrators a WHERE a.member_id=m.id)
 ORDER BY m.id LIMIT $3`, factorID, after, limit+1)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var item ConsoleIdentity
		if err := rows.Scan(&item.MemberID, &item.OrganizationID, &item.OrganizationName, &item.DisplayName); err != nil {
			return page, err
		}
		if len(page.Items) == limit {
			page.NextAfter = page.Items[len(page.Items)-1].MemberID
			break
		}
		item.Platform = item.OrganizationID == SystemOrganizationID
		page.Items = append(page.Items, item)
	}
	return page, rows.Err()
}

// CheckConsoleIdentity rechecks the source and target at initiation and callback.
// A callback grant must retain the same phone and authentication session; changing
// the issuer's browser identity cannot turn a pending switch into another login.
func (service *ManagementService) CheckConsoleIdentity(ctx context.Context, principal Principal, memberID, grantID string) error {
	if !ValidID(memberID, MemberKind) {
		return ErrInvalid
	}
	factorID, sessionID, err := service.consolePhoneSource(ctx, principal)
	if err != nil {
		return err
	}
	if factorID == "" {
		return ErrForbidden
	}
	var allowed bool
	err = service.store.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1"+eligibleBindings+`
 AND f.id=$1 AND m.id=$2 AND EXISTS(SELECT 1 FROM administrators a WHERE a.member_id=m.id))`, factorID, memberID).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrForbidden
	}
	if grantID == "" {
		return nil
	}
	if _, err := managementActor(ctx, service.store.pool, memberID, grantID); err != nil {
		return err
	}
	err = service.store.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oidc_grants
 WHERE id=$1 AND session_id=$2 AND data->>'factorId'=$3)`, grantID, sessionID, factorID).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrForbidden
	}
	return nil
}
