package oidcprovider

import (
	"errors"
	"net/http"

	"github.com/euyuil/memberid/internal/authevent"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (service *Service) recordVerification(r *http.Request, event authevent.Event, method string, err error) {
	event.RequestID = authevent.FromContext(r.Context()).RequestID
	event.Type, event.Method, event.Outcome = "authentication.verify", method, "succeeded"
	if err != nil {
		event.Outcome, event.ReasonCode = "failed", "backendUnavailable"
		var protocolError *oidc.Error
		switch {
		case errors.Is(err, identity.ErrVerificationCommitUnconfirmed):
			event.ReasonCode = "commitUnconfirmed"
		case errors.Is(err, identity.ErrPhoneChallenge):
			event.Outcome, event.ReasonCode = "rejected", "invalidCredential"
		case errors.Is(err, identity.ErrIneligible), errors.Is(err, identity.ErrForbidden), errors.Is(err, identity.ErrConflict):
			event.Outcome, event.ReasonCode = "rejected", "ineligible"
		case errors.As(err, &protocolError) && protocolError.ErrorType == oidc.InvalidRequest:
			event.Outcome, event.ReasonCode = "rejected", "ineligible"
		}
	}
	service.events.Offer(event)
}

func accountVerificationError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ErrIneligible
	}
	return err
}
