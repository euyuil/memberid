package oidcprovider

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/euyuil/memberid/internal/authevent"
	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
)

func (service *Service) passwordLogin(w http.ResponseWriter, r *http.Request, request *authorizationRequest, registered loginPolicy) {
	if registered.registration.SubjectKind != "member" || request.phonePending() || request.externalPending() || request.Verification != nil ||
		slices.Contains(request.prompts(), "none") {
		http.Error(w, "Password login is unavailable for this request", http.StatusBadRequest)
		return
	}
	organizationID := loginOrganizationID(request, registered)
	if organizationID == "" {
		http.Error(w, "Select an organization before password login", http.StatusBadRequest)
		return
	}
	username := r.PostForm.Get("username")
	if request.entry != nil {
		if err := service.storage.insertLoginEntry(r.Context(), request); err != nil {
			http.Error(w, "Login transaction expired", http.StatusBadRequest)
			return
		}
	}
	event := service.loginEvent(r.Context(), request)
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
	if !registered.registration.Preauthorized || slices.Contains(request.prompts(), "consent") {
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
	*request = completed
	event.Actor = authevent.Actor{Kind: "member", ID: admission.MemberID}
	event.MemberID, event.OrganizationID, event.BindingID = admission.MemberID, admission.OrganizationID, admission.BindingID
	event.FactorID, event.SessionID = admission.Factor.ID, completed.SessionID
	service.cookie(w, "session", secret, expires.Sub(service.now()))
	return nil
}
