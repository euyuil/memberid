package oidcprovider

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/zhizhun-tech/memberid/internal/authevent"
	"github.com/zhizhun-tech/memberid/internal/identity"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var errCallbackRejected = errors.New("authentication callback rejected")
var errCallbackCanceled = errors.New("authentication canceled")

func (service *Service) recordVerification(r *http.Request, event authevent.Event, method string, err error) {
	event.RequestID = authevent.FromContext(r.Context()).RequestID
	event.Type, event.Method, event.Outcome = "authentication.verify", method, "succeeded"
	if err != nil {
		event.Outcome, event.ReasonCode = "failed", "backendUnavailable"
		var protocolError *oidc.Error
		switch {
		case errors.Is(err, identity.ErrVerificationCommitUnconfirmed):
			event.ReasonCode = "commitUnconfirmed"
		case errors.Is(err, identity.ErrProviderUnavailable):
			event.ReasonCode = "providerUnavailable"
		case errors.Is(err, errCallbackCanceled):
			event.Outcome, event.ReasonCode = "rejected", "canceled"
		case errors.Is(err, identity.ErrRateLimited):
			event.Outcome, event.ReasonCode = "rejected", "rateLimited"
		case errors.Is(err, identity.ErrPhoneChallenge), errors.Is(err, identity.ErrPasswordCredential), errors.Is(err, errCallbackRejected), errors.Is(err, pgx.ErrNoRows):
			event.Outcome, event.ReasonCode = "rejected", "invalidCredential"
		case errors.Is(err, identity.ErrIneligible), errors.Is(err, identity.ErrForbidden), errors.Is(err, identity.ErrConflict):
			event.Outcome, event.ReasonCode = "rejected", "ineligible"
		case errors.As(err, &protocolError) && protocolError.ErrorType == oidc.InvalidGrant:
			event.Outcome, event.ReasonCode = "rejected", "invalidCredential"
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

func callbackFailure(value string) error {
	switch value {
	case "access_denied":
		return errCallbackCanceled
	case "server_error", "temporarily_unavailable":
		return identity.ErrProviderUnavailable
	default:
		return errCallbackRejected
	}
}
