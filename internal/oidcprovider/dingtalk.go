package oidcprovider

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type dingTalkAttempt struct {
	StateHash string `json:"stateHash"`
	identity.DingTalkLoginContext
	ExpiresAt time.Time `json:"expiresAt"`
	Consumed  bool      `json:"consumed"`
}

func (service *Service) startDingTalk(w http.ResponseWriter, r *http.Request, request *authorizationRequest, registered client) {
	if service.dingtalk == nil || registered.registration.SubjectKind != "member" || request.Verification != nil || request.ChallengeID != "" || request.DingTalk != nil {
		http.Error(w, "Cancel the current verification before starting DingTalk login.", http.StatusBadRequest)
		return
	}
	organizationID := r.PostForm.Get("organization")
	if registered.registration.OrganizationID != "" && organizationID != registered.registration.OrganizationID {
		http.Error(w, "Invalid organization", http.StatusBadRequest)
		return
	}
	app, err := service.dingtalk.Application(r.Context(), organizationID)
	if err != nil {
		service.renderLogin(w, r, request, registered, "DingTalk is not available for that organization.")
		return
	}
	state := config.RandomSecret()
	request.DingTalk = &dingTalkAttempt{StateHash: config.SecretHash(state), DingTalkLoginContext: app.LoginContext(), ExpiresAt: service.now().Add(5 * time.Minute)}
	request.Fresh = true
	if err := service.storage.saveRequest(r.Context(), request); err != nil {
		http.Error(w, "Login transaction expired", http.StatusBadRequest)
		return
	}
	query := url.Values{"client_id": {app.ClientID}, "redirect_uri": {service.configuration.Issuer + "/login/dingtalk/callback"}, "state": {state}, "response_type": {"code"}, "prompt": {"consent"}, "scope": {"openid corpid"}, "corpId": {app.CorpID}}
	http.Redirect(w, r, "https://login.dingtalk.com/oauth2/auth?"+query.Encode(), http.StatusSeeOther)
}

func (service *Service) dingTalkCallback(w http.ResponseWriter, r *http.Request) {
	if service.dingtalk == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	for name := range r.Form {
		if name != "state" && name != "authCode" && name != "error" && name != "error_description" {
			http.Error(w, "Invalid DingTalk callback", http.StatusBadRequest)
			return
		}
	}
	state := r.Form.Get("state")
	if len(state) != 43 {
		http.Error(w, "Invalid DingTalk callback", http.StatusBadRequest)
		return
	}
	found, err := service.storage.loadRequest(r.Context(), "data->'dingtalk'->>'stateHash'", config.SecretHash(state))
	if err != nil {
		http.Error(w, "Invalid or expired DingTalk login", http.StatusBadRequest)
		return
	}
	input, err := service.storage.AuthRequestByID(r.Context(), found.ID)
	if err != nil {
		http.Error(w, "Invalid or expired DingTalk login", http.StatusBadRequest)
		return
	}
	request := input.(*authorizationRequest)
	attempt := request.DingTalk
	registered, err := service.storage.client(request.ClientID)
	if err != nil || request.Complete || request.Verification != nil || attempt == nil || attempt.Consumed || !attempt.ExpiresAt.After(service.now()) || !sameSecret(attempt.StateHash, config.SecretHash(state)) || registered.registration.SubjectKind != "member" || registered.registration.OrganizationID != "" && registered.registration.OrganizationID != attempt.OrganizationID {
		http.Error(w, "Invalid or expired DingTalk login", http.StatusBadRequest)
		return
	}
	// Consume state before contacting the provider; a lost response requires a fresh authorization.
	attempt.Consumed = true
	if err := service.storage.saveRequest(r.Context(), request); err != nil {
		http.Error(w, "Invalid or expired DingTalk login", http.StatusBadRequest)
		return
	}
	if r.Form.Get("error") != "" || r.Form.Get("authCode") == "" {
		service.renderLogin(w, r, request, registered, "DingTalk login did not complete. Cancel verification to try again.")
		return
	}
	proof, err := service.dingtalk.Verify(r.Context(), attempt.DingTalkLoginContext, r.Form.Get("authCode"))
	if err != nil {
		service.renderLogin(w, r, request, registered, "Unable to verify DingTalk membership. Cancel verification to try again.")
		return
	}
	id, secret := newID(), config.RandomSecret()
	var expires time.Time
	err = pgx.BeginFunc(r.Context(), service.store.Database(), func(tx pgx.Tx) error {
		var revision int64
		if err := tx.QueryRow(r.Context(), "SELECT revision FROM oidc_authorization_requests WHERE id=$1 AND code_hash IS NULL AND consumed_at IS NULL AND expires_at>$2 FOR UPDATE", request.ID, service.now()).Scan(&revision); err != nil || revision != request.Revision {
			return oidc.ErrInvalidRequest()
		}
		if !attempt.ExpiresAt.After(service.now()) {
			return oidc.ErrInvalidRequest()
		}
		verified, err := service.dingtalk.Admit(r.Context(), tx, proof)
		if err != nil {
			return err
		}
		session, err := json.Marshal(verified)
		if err != nil {
			return err
		}
		absolute := verified.AuthenticatedAt.Add(maximumLifetime)
		expires = minimum(service.now().Add(sessionIdleLifetime), absolute)
		if _, err := tx.Exec(r.Context(), "INSERT INTO oidc_sessions(id,secret_hash,verification,expires_at,absolute_expires_at) VALUES($1,$2,$3,$4,$5)", id, config.SecretHash(secret), session, expires, absolute); err != nil {
			return err
		}
		request.SessionID = id
		setVerification(request, verified)
		data, err := json.Marshal(request)
		if err != nil {
			return err
		}
		_, err = tx.Exec(r.Context(), "UPDATE oidc_authorization_requests SET data=$2,revision=revision+1 WHERE id=$1", request.ID, data)
		return err
	})
	if err != nil {
		http.Error(w, "DingTalk login expired or the identity is no longer eligible. Start a new login.", http.StatusForbidden)
		return
	}
	service.cookie(w, "session", secret, expires.Sub(service.now()))
	http.Redirect(w, r, "/login?request="+url.QueryEscape(request.ID), http.StatusSeeOther)
}
