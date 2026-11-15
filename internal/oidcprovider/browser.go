package oidcprovider

import (
	"context"
	"strings"

	"github.com/euyuil/memberid/internal/browserauth"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
)

type loginPolicy struct{ registration browserauth.Policy }

func (service *Service) loginPolicy(ctx context.Context, request *authorizationRequest) (loginPolicy, error) {
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
		return loginPolicy{browserauth.Policy{ID: sp.ID, OrganizationID: sp.OrganizationID, SubjectKind: "member", Preauthorized: sp.Preauthorized, ReturnURI: sp.ACSURL, IdentityInformation: strings.Join(append([]string{"persistent identifier"}, sp.Attributes...), ", ")}}, nil
	}
	registered, err := service.storage.client(request.ClientID)
	if err != nil {
		return loginPolicy{}, err
	}
	c := registered.registration
	return loginPolicy{browserauth.Policy{ID: c.ID, OrganizationID: c.OrganizationID, SubjectKind: c.SubjectKind, Preauthorized: c.Preauthorized, ReturnURI: request.Input.RedirectURI, IdentityInformation: strings.Join(request.Scopes, ", ")}}, nil
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
	if request.SAML == nil {
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
