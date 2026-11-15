package oidcprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/euyuil/memberid/internal/authevent"
	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (service *Service) passwordLogin(w http.ResponseWriter, r *http.Request, request *authorizationRequest, registered client) {
	if registered.registration.SubjectKind != "member" || request.phonePending() || request.externalPending() || request.Verification != nil ||
		slices.Contains(request.Input.Prompt, "none") {
		http.Error(w, "Password login is unavailable for this request", http.StatusBadRequest)
		return
	}
	organizationID := r.PostForm.Get("password_organization")
	if restricted := registered.registration.OrganizationID; restricted != "" {
		organizationID = restricted
	}
	username := r.PostForm.Get("username")
	event := service.loginEvent(request)
	err := service.verifyPasswordLogin(w, r, request, organizationID, username, r.PostForm.Get("password"), &event)
	service.recordVerification(r, event, "pwd", err)
	if errors.Is(err, identity.ErrRateLimited) {
		service.renderLogin(w, r, request, registered, "Too many sign-in attempts. Try again later.")
		return
	}
	if errors.Is(err, identity.ErrPasswordCredential) {
		service.renderLogin(w, r, request, registered, "The organization, username, or password is incorrect.")
		return
	}
	if err != nil {
		http.Error(w, "Login could not complete. Start a new login.", http.StatusServiceUnavailable)
		return
	}
	if !registered.registration.Preauthorized || slices.Contains(request.Input.Prompt, "consent") {
		service.renderLogin(w, r, request, registered, "")
		return
	}
	request.MemberID, request.OrganizationID = event.MemberID, event.OrganizationID
	if err := service.finish(w, r, request); err != nil {
		http.Error(w, "Identity is no longer eligible. Start a new login.", http.StatusForbidden)
	}
}

func (service *Service) verifyPasswordLogin(w http.ResponseWriter, r *http.Request, request *authorizationRequest, organizationID, username, password string, event *authevent.Event) error {
	select {
	case service.passwordWork <- struct{}{}:
		defer func() { <-service.passwordWork }()
	default:
		return identity.ErrRateLimited
	}
	completed := *request
	completed.SessionID = newID()
	secret := config.RandomSecret()
	var expires time.Time
	var admission identity.MemberAdmission
	err := service.store.VerifyPasswordAndApply(r.Context(), organizationID, username, password, func(tx pgx.Tx, verified identity.MemberAdmission) error {
		admission = verified
		var err error
		expires, err = service.persistVerifiedSession(r.Context(), tx, &completed, verified.Verification, secret)
		return err
	})
	if err != nil {
		return err
	}
	completed.Revision++
	*request = completed
	event.Actor = authevent.Actor{Kind: "member", ID: admission.MemberID}
	event.MemberID, event.OrganizationID, event.BindingID = admission.MemberID, admission.OrganizationID, admission.BindingID
	event.FactorID, event.SessionID = admission.Factor.ID, completed.SessionID
	service.cookie(w, "session", secret, expires.Sub(service.now()))
	return nil
}

// Verify the request revision and create a session in the credential
// verification transaction so retries cannot issue another session.
func (service *Service) persistVerifiedSession(ctx context.Context, tx pgx.Tx, completed *authorizationRequest, verified identity.Verification, secret string) (time.Time, error) {
	setVerification(completed, verified)
	now := service.now()
	data, err := json.Marshal(completed)
	if err != nil {
		return time.Time{}, err
	}
	result, err := tx.Exec(ctx, "UPDATE oidc_authorization_requests SET data=$2,revision=revision+1 WHERE id=$1 AND revision=$3 AND code_hash IS NULL AND consumed_at IS NULL AND expires_at>$4", completed.ID, data, completed.Revision, now)
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
	_, err = tx.Exec(ctx, "INSERT INTO oidc_sessions(id,secret_hash,verification,expires_at,absolute_expires_at) VALUES($1,$2,$3,$4,$5)", completed.SessionID, config.SecretHash(secret), session, expires, completed.AbsoluteExpiry)
	return expires, err
}
