package oidcprovider

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
)

// GrantInfo contains operator-visible metadata, never credential values or verifiers.
// State describes persisted lifecycle only; token use still checks current eligibility and client policy.
type GrantInfo struct {
	ID                string     `json:"id"`
	ClientID          string     `json:"clientId"`
	SessionID         string     `json:"sessionId"`
	Subject           string     `json:"subject"`
	OrganizationID    string     `json:"organizationId,omitempty"`
	FactorID          string     `json:"authenticationFactorId"`
	FactorType        string     `json:"authenticationFactorType"`
	AuthenticatedAt   time.Time  `json:"authenticatedAt"`
	OriginalScopes    []string   `json:"originalScopes"`
	Audience          []string   `json:"audience"`
	State             string     `json:"state"`
	ExpiresAt         time.Time  `json:"expiresAt"`
	AbsoluteExpiresAt time.Time  `json:"absoluteExpiresAt"`
	RevokedAt         *time.Time `json:"revokedAt"`
	SessionRevokedAt  *time.Time `json:"sessionRevokedAt"`
}

type GrantFilter struct {
	ClientID string
	Subject  string
	After    string
	Limit    int
}

const grantInfoColumns = `g.id,g.client_id,g.session_id,g.data,g.expires_at,g.absolute_expires_at,g.revoked_at,s.revoked_at,s.absolute_expires_at`

func readGrantInfo(row pgx.Row) (GrantInfo, error) {
	var result GrantInfo
	var data []byte
	var sessionDeadline time.Time
	err := row.Scan(&result.ID, &result.ClientID, &result.SessionID, &data, &result.ExpiresAt, &result.AbsoluteExpiresAt, &result.RevokedAt, &result.SessionRevokedAt, &sessionDeadline)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, identity.ErrNotFound
	}
	if err != nil {
		return result, err
	}
	var stored grant
	if json.Unmarshal(data, &stored) != nil {
		return result, errors.New("invalid stored grant metadata")
	}
	result.Subject = stored.GetSubject()
	result.OrganizationID = stored.OrganizationID
	result.FactorID, result.FactorType = stored.FactorID, stored.FactorType
	result.AuthenticatedAt = stored.AuthTime.UTC()
	result.OriginalScopes, result.Audience = stored.Scopes, stored.Audience
	result.ExpiresAt, result.AbsoluteExpiresAt = result.ExpiresAt.UTC(), result.AbsoluteExpiresAt.UTC()
	if result.RevokedAt != nil {
		value := result.RevokedAt.UTC()
		result.RevokedAt = &value
	}
	if result.SessionRevokedAt != nil {
		value := result.SessionRevokedAt.UTC()
		result.SessionRevokedAt = &value
	}
	result.State = "active"
	now := time.Now()
	if result.RevokedAt != nil || result.SessionRevokedAt != nil {
		result.State = "revoked"
	} else if !result.ExpiresAt.After(now) || !result.AbsoluteExpiresAt.After(now) || !sessionDeadline.After(now) {
		result.State = "expired"
	}
	return result, nil
}

func InspectGrant(ctx context.Context, store *identity.Store, id string) (GrantInfo, error) {
	if !validTokenID(id) {
		return GrantInfo{}, identity.ErrInvalid
	}
	return readGrantInfo(store.Database().QueryRow(ctx, "SELECT "+grantInfoColumns+" FROM oidc_grants g JOIN oidc_sessions s ON s.id=g.session_id WHERE g.id=$1", id))
}

func ListGrants(ctx context.Context, store *identity.Store, filter GrantFilter) (identity.Page[GrantInfo], error) {
	result := identity.Page[GrantInfo]{Items: []GrantInfo{}}
	if filter.Limit < 1 || filter.Limit > 100 || filter.After != "" && !validTokenID(filter.After) || filter.Subject != "" && !identity.ValidID(filter.Subject, identity.MemberKind) && !identity.ValidID(filter.Subject, identity.FactorKind) {
		return result, identity.ErrInvalid
	}
	rows, err := store.Database().Query(ctx, "SELECT "+grantInfoColumns+` FROM oidc_grants g JOIN oidc_sessions s ON s.id=g.session_id
        WHERE ($1='' OR g.client_id=$1) AND ($2='' OR COALESCE(NULLIF(g.data->>'memberId',''),g.data->>'factorId')=$2)
        AND g.id>$3 ORDER BY g.id LIMIT $4`, filter.ClientID, filter.Subject, filter.After, filter.Limit+1)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		info, err := readGrantInfo(rows)
		if err != nil {
			return result, err
		}
		if len(result.Items) == filter.Limit {
			result.NextAfter = result.Items[filter.Limit-1].ID
			break
		}
		result.Items = append(result.Items, info)
	}
	return result, rows.Err()
}

// RevokeGrant serializes with token rotation on the grant row, so refresh cannot resurrect it.
func RevokeGrant(ctx context.Context, store *identity.Store, id string) (GrantInfo, error) {
	if !validTokenID(id) {
		return GrantInfo{}, identity.ErrInvalid
	}
	return readGrantInfo(store.Database().QueryRow(ctx, `WITH changed AS (
        UPDATE oidc_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE id=$1 RETURNING *
        ) SELECT `+grantInfoColumns+" FROM changed g JOIN oidc_sessions s ON s.id=g.session_id", id))
}
