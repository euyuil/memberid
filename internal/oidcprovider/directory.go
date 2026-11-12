package oidcprovider

import (
	"context"
	"errors"

	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (s *storage) observeDirectory(ctx context.Context, g *grant) (*identity.DingTalkDirectoryObservation, error) {
	if s.service.directory == nil || g.MemberID == "" {
		return nil, nil
	}
	return s.service.directory.Observe(ctx, g.OrganizationID, g.MemberID, g.FactorType)
}

func (s *storage) validateDirectory(ctx context.Context, tx pgx.Tx, observation *identity.DingTalkDirectoryObservation, err error) error {
	if err == nil && observation != nil {
		err = observation.Validate(ctx, tx)
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, identity.ErrIneligible) || errors.Is(err, identity.ErrConflict) || errors.Is(err, identity.ErrNotFound) {
		return oidc.ErrInvalidGrant()
	}
	return oidc.ErrServerError().WithDescription("Current identity verification is unavailable")
}
