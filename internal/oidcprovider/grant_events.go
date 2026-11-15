package oidcprovider

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/euyuil/memberid/internal/authevent"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const maxLogoutGrantEvents = 256

// A completed revocation must remain successful even if historical JSON cannot
// be decoded for auditing. The returned row ID still establishes its target;
// unavailable contextual fields stay absent rather than being reconstructed.
func revokedGrantEvent(ctx context.Context, id string, data []byte, actor authevent.Actor, trigger string) authevent.Event {
	var stored grant
	event := authevent.Event{RequestID: authevent.FromContext(ctx).RequestID}
	if json.Unmarshal(data, &stored) == nil {
		event = grantEvent(ctx, &stored)
	}
	event.GrantID, event.Type, event.Trigger, event.Actor = id, "grant.revoke", trigger, actor
	return event
}

// These references come from validated protocol state, not submitted token text.
// Reuse identifies the affected subject, never the presenter as that Member.
func grantEvent(ctx context.Context, g *grant) authevent.Event {
	return authevent.Event{
		RequestID: authevent.FromContext(ctx).RequestID, InteractionID: g.InteractionID,
		OrganizationID: g.OrganizationID, MemberID: g.MemberID, ClientID: g.ClientID,
		FactorID: g.FactorID, BindingID: g.BindingID, SessionID: g.SessionID,
		GrantID: g.ID, Method: g.Method,
	}
}

func operationResult(event authevent.Event, err error, commitReady bool) authevent.Event {
	event.Outcome = "succeeded"
	if err == nil {
		return event
	}
	event.Outcome, event.ReasonCode = "failed", "backendUnavailable"
	var postgresError *pgconn.PgError
	var protocolError *oidc.Error
	switch {
	case commitReady && !errors.As(err, &postgresError) && !errors.Is(err, pgx.ErrTxCommitRollback):
		event.ReasonCode = "commitUnconfirmed"
	case errors.As(err, &protocolError) && (protocolError.ErrorType == oidc.InvalidGrant || protocolError.ErrorType == oidc.InvalidRequest):
		event.Outcome, event.ReasonCode = "rejected", "invalidCredential"
	case errors.Is(err, identity.ErrIneligible), errors.Is(err, identity.ErrNotFound), errors.Is(err, identity.ErrForbidden):
		event.Outcome, event.ReasonCode = "rejected", "ineligible"
	}
	return event
}

// A confirmed observation survives a failed protective transaction. Its outcome
// is separate from whether that transaction actually revoked a grant.
func (s *storage) recordReuse(event authevent.Event, revoked bool, err error, commitReady bool) {
	s.service.events.Offer(event)
	if !revoked && err == nil {
		return
	}
	event.CausationID, event.EventID = event.EventID, ""
	event.Type, event.Trigger = "grant.revoke", "replayDetection"
	event.OccurredAt = s.service.now().UTC()
	s.service.events.Offer(operationResult(event, err, commitReady))
}

// A missing eligibility record is a denial. A failed database read is not.
func grantEligibilityError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, identity.ErrNotFound) || errors.Is(err, identity.ErrIneligible) || errors.Is(err, identity.ErrInvalid) {
		return oidc.ErrInvalidGrant()
	}
	return err
}
