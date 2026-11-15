package oidcprovider

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/euyuil/memberid/internal/authevent"
	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (request *authorizationRequest) phonePending() bool { return request.PhoneNumber != "" }

func (service *Service) verifyPhoneLogin(w http.ResponseWriter, r *http.Request, request *authorizationRequest, code string) error {
	id, secret := newID(), config.RandomSecret()
	completed := *request
	var expires time.Time
	verified, err := service.phone.VerifyAndApply(r.Context(), request.ID, request.ChallengeID, code, func(tx pgx.Tx, verified identity.Verification) error {
		if err := service.validateLoginPolicy(r.Context(), tx, request); err != nil {
			return err
		}
		completed.SessionID = id
		setVerification(&completed, verified)
		data, err := json.Marshal(&completed)
		if err != nil {
			return err
		}
		// Cancellation and competing transitions advance the revision. This
		// conditional write participates in the same transaction as consumption.
		result, err := tx.Exec(r.Context(), "UPDATE authentication_requests SET data=$2,revision=revision+1 WHERE id=$1 AND revision=$3 AND code_hash IS NULL AND consumed_at IS NULL AND expires_at>$4", request.ID, data, request.Revision, service.now())
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return oidc.ErrInvalidRequest()
		}
		session, err := json.Marshal(verified)
		if err != nil {
			return err
		}
		expires = minimum(service.now().Add(sessionIdleLifetime), completed.AbsoluteExpiry)
		_, err = tx.Exec(r.Context(), "INSERT INTO authentication_sessions(id,secret_hash,verification,expires_at,absolute_expires_at) VALUES($1,$2,$3,$4,$5)", id, config.SecretHash(secret), session, expires, completed.AbsoluteExpiry)
		return err
	})
	event := service.loginEvent(request)
	if err == nil {
		event.Actor = authevent.Actor{Kind: "factor", ID: verified.Factor.ID}
		event.FactorID, event.SessionID = verified.Factor.ID, id
	}
	service.recordVerification(r, event, "sms", err)
	if err != nil {
		return err
	}
	completed.Revision++
	*request = completed
	service.cookie(w, "session", secret, expires.Sub(service.now()))
	return nil
}
