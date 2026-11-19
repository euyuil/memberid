package oidcprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/euyuil/memberid/internal/authevent"
	"github.com/euyuil/memberid/internal/browserauth"
	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type dingTalkAttempt = browserauth.DingTalkAttempt

func dingTalkCallbackCode(r *http.Request) (string, bool) {
	if !accountFields(r, "state", "authCode", "code", "error", "error_description") {
		return "", false
	}
	code := r.Form.Get("code")
	if !r.Form.Has("authCode") {
		return code, true
	}
	// DingTalk may return the authorization code under both names.
	authCode := r.Form.Get("authCode")
	return authCode, !r.Form.Has("code") || code == authCode
}

func (service *Service) startDingTalk(w http.ResponseWriter, r *http.Request, request *authorizationRequest, registered loginPolicy) {
	if service.dingtalk == nil || registered.registration.SubjectKind != "member" || request.Verification != nil || request.phonePending() || request.externalPending() {
		http.Error(w, "Cancel the current verification before starting DingTalk login.", http.StatusBadRequest)
		return
	}
	organizationID := loginOrganizationID(request, registered)
	if organizationID == "" || r.PostForm.Get("organization") != organizationID {
		http.Error(w, "Invalid organization", http.StatusBadRequest)
		return
	}
	app, err := service.dingtalk.ApplicationSource(r.Context(), organizationID, r.PostForm.Get("provider"))
	if err != nil {
		service.renderLogin(w, r, request, registered, "DingTalk is not available for that organization.")
		return
	}
	state := config.RandomSecret()
	request.DingTalk = &dingTalkAttempt{StateHash: config.SecretHash(state), DingTalkLoginContext: app.LoginContext(), ExpiresAt: service.now().Add(5 * time.Minute)}
	request.Fresh = true
	request.ProviderOrganizationID = organizationID
	if err := service.saveExternalLogin(w, r, request, state); err != nil {
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
	event := authevent.Event{Purpose: "login"}
	failure := errCallbackRejected
	completed := false
	defer func() {
		if !completed {
			service.recordVerification(r, event, "dingtalk", failure)
		}
	}()
	code, valid := dingTalkCallbackCode(r)
	state := r.Form.Get("state")
	if !valid || len(state) != 43 {
		http.Error(w, "Invalid DingTalk callback", http.StatusBadRequest)
		return
	}
	request, err := service.externalLoginRequest(r, state, "data->'dingtalk'->>'stateHash'")
	if err != nil {
		failure = err
		http.Error(w, "Invalid or expired DingTalk login", http.StatusBadRequest)
		return
	}
	attempt := request.DingTalk
	event = service.loginEvent(r.Context(), request)
	if attempt != nil {
		event.OrganizationID = attempt.OrganizationID
		event.ProviderID = attempt.Namespace
	}
	registered, err := service.loginPolicy(r.Context(), request)
	if err != nil || request.Complete || request.Verification != nil || attempt == nil || attempt.Consumed || !attempt.ExpiresAt.After(service.now()) || !sameSecret(attempt.StateHash, config.SecretHash(state)) || registered.registration.SubjectKind != "member" || registered.registration.OrganizationID != "" && registered.registration.OrganizationID != attempt.OrganizationID {
		http.Error(w, "Invalid or expired DingTalk login", http.StatusBadRequest)
		return
	}
	// Consume state before contacting the provider; a lost response requires a fresh authorization.
	attempt.Consumed = true
	if err := service.storage.saveRequest(r.Context(), request); err != nil {
		failure = err
		http.Error(w, "Invalid or expired DingTalk login", http.StatusBadRequest)
		return
	}
	if request.browserHeldSAML() {
		service.cookie(w, "saml_"+state, "", -time.Second)
	}
	if r.Form.Get("error") != "" || code == "" {
		if r.Form.Get("error") != "" {
			failure = callbackFailure(r.Form.Get("error"))
		}
		service.renderLogin(w, r, request, registered, "DingTalk login did not complete. Cancel verification to try again.")
		return
	}
	proof, err := service.dingtalk.Verify(r.Context(), attempt.DingTalkLoginContext, code)
	if err != nil {
		failure = err
		service.renderLogin(w, r, request, registered, "Unable to verify DingTalk membership. Cancel verification to try again.")
		return
	}
	completed = true
	service.completeExternalLogin(w, r, request, attempt.ExpiresAt, "DingTalk", event, func(ctx context.Context, tx pgx.Tx) (identity.MemberAdmission, error) {
		return service.dingtalk.Admit(ctx, tx, proof)
	})
}

func (service *Service) completeExternalLogin(w http.ResponseWriter, r *http.Request, request *authorizationRequest, deadline time.Time, name string, event authevent.Event, admit func(context.Context, pgx.Tx) (identity.MemberAdmission, error)) {
	id, secret := newID(), config.RandomSecret()
	var expires time.Time
	var admitted identity.MemberAdmission
	completed := *request
	err := pgx.BeginFunc(r.Context(), service.store.Database(), func(tx pgx.Tx) error {
		if err := service.validateLoginPolicy(r.Context(), tx, request); err != nil {
			return err
		}
		var revision int64
		if err := tx.QueryRow(r.Context(), "SELECT revision FROM authentication_requests WHERE id=$1 AND code_hash IS NULL AND consumed_at IS NULL AND expires_at>$2 FOR UPDATE", request.ID, service.now()).Scan(&revision); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return oidc.ErrInvalidRequest()
			}
			return err
		}
		if revision != request.Revision {
			return oidc.ErrInvalidRequest()
		}
		if !deadline.After(service.now()) {
			return oidc.ErrInvalidRequest()
		}
		var err error
		admitted, err = admit(r.Context(), tx)
		verified := admitted.Verification
		if err != nil {
			return err
		}
		session, err := json.Marshal(verified)
		if err != nil {
			return err
		}
		absolute := verified.AuthenticatedAt.Add(maximumLifetime)
		expires = minimum(service.now().Add(sessionIdleLifetime), absolute)
		if _, err := tx.Exec(r.Context(), "INSERT INTO authentication_sessions(id,secret_hash,verification,expires_at,absolute_expires_at) VALUES($1,$2,$3,$4,$5)", id, config.SecretHash(secret), session, expires, absolute); err != nil {
			return err
		}
		completed.DingTalk, completed.Feishu = nil, nil
		completed.SessionID = id
		setVerification(&completed, verified)
		return service.storage.advanceRequest(r.Context(), tx, &completed)
	})
	if err == nil {
		event.OrganizationID, event.MemberID, event.BindingID = admitted.OrganizationID, admitted.MemberID, admitted.BindingID
		event.FactorID, event.SessionID = admitted.Factor.ID, id
		event.Actor = authevent.Actor{Kind: "member", ID: admitted.MemberID}
	}
	service.recordVerification(r, event, strings.ToLower(name), err)
	if err != nil {
		http.Error(w, name+" login expired or the identity is no longer eligible. Start a new login.", http.StatusForbidden)
		return
	}
	*request = completed
	service.cookie(w, "session", secret, expires.Sub(service.now()))
	http.Redirect(w, r, requestLoginURL(request), http.StatusSeeOther)
}
