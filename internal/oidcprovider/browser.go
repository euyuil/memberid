package oidcprovider

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/euyuil/memberid/internal/browserauth"
	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type loginPolicy struct {
	registration browserauth.Policy
	displayName  string
}

func directLoginPolicy(organizationID string) loginPolicy {
	return loginPolicy{registration: browserauth.Policy{ID: "MemberID account", OrganizationID: organizationID, SubjectKind: "member", Preauthorized: true}, displayName: "MemberID account"}
}

func (service *Service) loginPolicy(ctx context.Context, request *authorizationRequest) (loginPolicy, error) {
	if request.ClientID == "" {
		return directLoginPolicy(request.ProviderOrganizationID), nil
	}
	if request.SAML != nil {
		if service.saml == nil {
			return loginPolicy{}, identity.ErrIneligible
		}
		sp, err := service.store.SAMLServiceProvider(ctx, request.SAML.ServiceProviderID)
		if err != nil {
			return loginPolicy{}, err
		}
		if !sp.Enabled || sp.Retired || sp.Revision != request.SAML.Revision {
			return loginPolicy{}, identity.ErrIneligible
		}
		return loginPolicy{registration: browserauth.Policy{ID: sp.ID, OrganizationID: sp.OrganizationID, SubjectKind: "member", Preauthorized: sp.Preauthorized, ReturnURI: sp.ACSURL, IdentityInformation: strings.Join(append([]string{"persistent identifier"}, sp.Attributes...), ", ")}}, nil
	}
	registered, err := service.storage.client(ctx, request.ClientID)
	if err != nil {
		return loginPolicy{}, err
	}
	if !request.permitsClient(registered) {
		return loginPolicy{}, identity.ErrIneligible
	}
	c := registered.registration
	return loginPolicy{
		registration: browserauth.Policy{ID: c.ID, OrganizationID: c.OrganizationID, SubjectKind: c.SubjectKind, Preauthorized: c.Preauthorized, ReturnURI: request.Input.RedirectURI, IdentityInformation: strings.Join(request.Scopes, ", ")},
		displayName:  registered.displayName,
	}, nil
}

func (request *authorizationRequest) prompts() []string {
	if request.SAML != nil {
		if request.SAML.Passive {
			return []string{"none"}
		}
		return nil
	}
	return request.Input.Prompt
}

// Recheck the protocol admission inside the transaction that establishes fresh
// authentication, including after external provider I/O.
func (service *Service) validateLoginPolicy(ctx context.Context, tx pgx.Tx, request *authorizationRequest) error {
	if request.ClientID == "" {
		var status string
		if err := tx.QueryRow(ctx, "SELECT status FROM organizations WHERE id=$1", request.ProviderOrganizationID).Scan(&status); err != nil {
			return err
		}
		if status != "enabled" {
			return identity.ErrIneligible
		}
		return nil
	}
	if request.SAML == nil {
		client, err := service.storage.clientAt(ctx, tx, request.ClientID)
		if err != nil {
			return err
		}
		if !request.permitsClient(client) {
			return identity.ErrIneligible
		}
		return nil
	}
	sp, err := identity.LockSAMLServiceProvider(ctx, tx, request.SAML.ServiceProviderID)
	if err != nil {
		return err
	}
	if service.saml == nil || !sp.Enabled || sp.Retired || sp.Revision != request.SAML.Revision {
		return identity.ErrIneligible
	}
	return nil
}

// Store fresh verification and its session in the credential verification
// transaction. The request revision prevents a competing transition from
// creating a session for a canceled or already verified interaction.
func (service *Service) persistVerifiedSession(ctx context.Context, tx pgx.Tx, completed *authorizationRequest, verified identity.Verification, secret string) (time.Time, error) {
	if err := service.validateLoginPolicy(ctx, tx, completed); err != nil {
		return time.Time{}, err
	}
	setVerification(completed, verified)
	now := service.now()
	data, err := json.Marshal(completed)
	if err != nil {
		return time.Time{}, err
	}
	result, err := tx.Exec(ctx, "UPDATE authentication_requests SET data=$2,revision=revision+1 WHERE id=$1 AND revision=$3 AND code_hash IS NULL AND consumed_at IS NULL AND expires_at>$4", completed.ID, data, completed.Revision, now)
	if err != nil {
		return time.Time{}, err
	}
	if result.RowsAffected() != 1 {
		return time.Time{}, oidc.ErrInvalidRequest()
	}
	session, err := json.Marshal(completed.Verification)
	if err != nil {
		return time.Time{}, err
	}
	expires := minimum(now.Add(sessionIdleLifetime), completed.AbsoluteExpiry)
	_, err = tx.Exec(ctx, "INSERT INTO authentication_sessions(id,secret_hash,verification,expires_at,absolute_expires_at) VALUES($1,$2,$3,$4,$5)", completed.SessionID, config.SecretHash(secret), session, expires, completed.AbsoluteExpiry)
	return expires, err
}
