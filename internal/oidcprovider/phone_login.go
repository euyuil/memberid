package oidcprovider

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zhizhun-tech/memberid/internal/authevent"
	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/identity"
)

func (request *authorizationRequest) phonePending() bool { return request.PhoneNumber != "" }

func (service *Service) verifyPhoneLogin(w http.ResponseWriter, r *http.Request, request *authorizationRequest, code string) error {
	id, secret := newID(), config.RandomSecret()
	completed := *request
	var expires time.Time
	verified, err := service.phone.VerifyAndApply(r.Context(), request.ID, request.ChallengeID, code, func(tx pgx.Tx, verified identity.Verification) error {
		completed.SessionID = id
		var err error
		expires, err = service.persistVerifiedSession(r.Context(), tx, &completed, verified, secret)
		return err
	})
	event := service.loginEvent(r.Context(), request)
	if err == nil {
		event.Actor = authevent.Actor{Kind: "factor", ID: verified.Factor.ID}
		event.FactorID, event.SessionID = verified.Factor.ID, id
	}
	service.recordVerification(r, event, "sms", err)
	if err != nil {
		return err
	}
	*request = completed
	service.cookie(w, "session", secret, expires.Sub(service.now()))
	return nil
}
