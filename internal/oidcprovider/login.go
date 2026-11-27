package oidcprovider

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/identity"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func (service *Service) loadSession(r *http.Request, request *authorizationRequest) bool {
	if request.Fresh || request.externalPending() || slices.Contains(request.prompts(), "login") {
		return false
	}
	secret := service.cookieValue(r, "session")
	if len(secret) != 43 {
		return false
	}
	var data []byte
	var id string
	if err := service.store.Database().QueryRow(r.Context(), "SELECT id,verification FROM authentication_sessions WHERE secret_hash=$1 AND revoked_at IS NULL AND expires_at>$2 AND absolute_expires_at>$2", config.SecretHash(secret), service.now()).Scan(&id, &data); err != nil {
		return false
	}
	var verified identity.Verification
	if json.Unmarshal(data, &verified) != nil {
		return false
	}
	if request.SAML == nil && request.Input.MaxAge != nil && service.now().Sub(verified.AuthenticatedAt) > time.Duration(*request.Input.MaxAge)*time.Second {
		return false
	}
	if request.ClientID == "" && !service.freshAccountSession(accountSession{verified: verified}) {
		return false
	}
	factor, err := service.store.Factor(r.Context(), verified.Factor.ID)
	if err != nil || factor.Status != "active" {
		return false
	}
	registered, err := service.loginPolicy(r.Context(), request)
	if err != nil || registered.registration.SubjectKind == "factor" && factor.Type != "phone" {
		return false
	}
	if factor.Type != "phone" {
		members, err := service.store.EligibleMembers(r.Context(), factor.ID)
		if err != nil || len(members) == 0 {
			return false
		}
	}
	organizationID := loginOrganizationID(request, registered)
	switch factor.Type {
	case "dingtalk":
		if service.dingtalk == nil {
			return false
		}
		if organizationID != "" {
			if _, err := service.dingtalk.ApplicationSource(r.Context(), organizationID, factor.Namespace); err != nil {
				return false
			}
		}
	case "feishu":
		if service.feishu == nil {
			return false
		}
		if organizationID != "" {
			if _, _, err := service.feishu.LoginSource(r.Context(), organizationID, factor.Namespace); err != nil {
				return false
			}
		}
	}
	verified.Factor = factor
	request.SessionID = id
	setVerification(request, verified)
	return true
}

func setVerification(request *authorizationRequest, verified identity.Verification) {
	request.Verification = &verified
	request.FactorID, request.FactorType, request.Method = verified.Factor.ID, verified.Factor.Type, verified.Method
	request.AuthTime = verified.AuthenticatedAt
	request.AbsoluteExpiry = verified.AuthenticatedAt.Add(maximumLifetime)
	request.MemberID, request.OrganizationID, request.BindingID = "", "", ""
}
func (service *Service) members(r *http.Request, request *authorizationRequest, client loginPolicy) ([]identity.Member, error) {
	if request.Verification == nil || client.registration.SubjectKind == "factor" {
		return nil, nil
	}
	members, err := service.store.EligibleMembers(r.Context(), request.FactorID)
	if err != nil {
		return nil, err
	}
	organizationID := loginOrganizationID(request, client)
	filtered := members[:0]
	for _, member := range members {
		if (organizationID == "" || member.OrganizationID == organizationID) &&
			(request.SAML != nil || !identity.ValidID(request.Input.LoginHint, identity.MemberKind) || member.ID == request.Input.LoginHint) {
			if request.SAML != nil && organizationID == "" && client.activation != nil {
				if _, err := client.activation(r.Context(), member.OrganizationID); errors.Is(err, identity.ErrIneligible) {
					continue
				} else if err != nil {
					return nil, err
				}
			}
			filtered = append(filtered, member)
		}
	}
	return filtered, nil
}

func (service *Service) finish(w http.ResponseWriter, r *http.Request, request *authorizationRequest) error {
	if request.ClientID == "" {
		return service.finishDirectLogin(w, r, request)
	}
	if request.SAML != nil {
		return service.finishSAML(w, r, request, "")
	}
	if request.HintSubject != "" && request.GetSubject() != request.HintSubject {
		service.loginError(w, r, request, "login_required")
		return nil
	}
	if !request.AbsoluteExpiry.After(service.now().Add(5 * time.Minute)) {
		return oidc.ErrInvalidGrant()
	}
	if err := service.storage.eligible(r.Context(), service.store.Database(), &request.grant); err != nil {
		return err
	}
	request.Complete = true
	if err := service.storage.saveRequest(r.Context(), request); err != nil {
		return err
	}
	http.Redirect(w, r, service.configuration.Issuer+"/oauth/authorize/callback?id="+url.QueryEscape(request.ID), http.StatusSeeOther)
	return nil
}

func (service *Service) loginError(w http.ResponseWriter, r *http.Request, request *authorizationRequest, kind string) {
	if request.SAML != nil {
		if err := service.finishSAML(w, r, request, "NoPassive"); err != nil {
			http.Error(w, "SAML login could not complete", http.StatusBadRequest)
		}
		return
	}
	protocolError := &oidc.Error{ErrorType: "login_required"}
	switch kind {
	case "consent_required":
		protocolError.ErrorType = "consent_required"
	case "interaction_required":
		protocolError.ErrorType = "interaction_required"
	}
	op.AuthRequestError(w, r.WithContext(op.ContextWithIssuer(r.Context(), service.configuration.Issuer)), &request.Input, protocolError, service.protocol)
}

func loginOrganizationID(request *authorizationRequest, registered loginPolicy) string {
	if registered.registration.OrganizationID != "" {
		return registered.registration.OrganizationID
	}
	return request.ProviderOrganizationID
}

func organizationFromLoginPath(path string) (string, bool) {
	if path == "/login" {
		return "", true
	}
	organizationID := strings.TrimPrefix(path, "/login/")
	return organizationID, identity.ValidID(organizationID, identity.OrganizationKind)
}

func (service *Service) requireLoginOrganization(ctx context.Context, organizationID string) error {
	organization, err := service.store.Organization(ctx, organizationID)
	if errors.Is(err, identity.ErrNotFound) {
		return identity.ErrIneligible
	}
	if err != nil {
		return err
	}
	if organization.Status != "enabled" {
		return identity.ErrIneligible
	}
	return nil
}

func writeLoginOrganizationError(w http.ResponseWriter, err error) {
	if errors.Is(err, identity.ErrIneligible) || errors.Is(err, identity.ErrNotFound) {
		http.Error(w, "Organization login is unavailable", http.StatusNotFound)
		return
	}
	http.Error(w, "Login temporarily unavailable", http.StatusServiceUnavailable)
}

// Slugs are bookmarkable aliases. Only the permanent ID enters a transaction.
func (service *Service) organizationSlugLogin(w http.ResponseWriter, r *http.Request, slug string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := service.store.LoginOrganizationIDBySlug(r.Context(), slug)
	if err != nil {
		writeLoginOrganizationError(w, err)
		return
	}
	path := "/login/" + id
	if requestID := r.Form.Get("request"); requestID != "" {
		path = organizationLoginURL(id, requestID)
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

func (service *Service) selectLoginOrganization(ctx context.Context, request *authorizationRequest, policy loginPolicy, id string) error {
	if err := service.requireLoginOrganization(ctx, id); err != nil {
		return err
	}
	if policy.activation != nil {
		activation, err := policy.activation(ctx, id)
		if err != nil {
			return err
		}
		request.EnablementID = activation
	}
	request.ProviderOrganizationID = id
	return nil
}

func (service *Service) selectedLoginOrganization(w http.ResponseWriter, r *http.Request, request *authorizationRequest, policy loginPolicy) string {
	id := r.PostForm.Get("organization")
	if err := service.selectLoginOrganization(r.Context(), request, policy, id); err != nil {
		if errors.Is(err, identity.ErrInvalid) || errors.Is(err, identity.ErrIneligible) {
			service.renderLogin(w, r, request, policy, "Enter a valid organization ID.")
		} else {
			writeLoginOrganizationError(w, err)
		}
		return ""
	}
	return id
}

func (service *Service) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pathOrganizationID, validPath := organizationFromLoginPath(r.URL.Path)
	if !validPath {
		http.NotFound(w, r)
		return
	}
	id := r.Form.Get("request")
	if r.Method == http.MethodGet && id == "" || r.Method == http.MethodPost && strings.HasPrefix(id, "direct.") {
		service.directLogin(w, r, pathOrganizationID)
		return
	}
	var request *authorizationRequest
	var err error
	if strings.HasPrefix(id, oidcLoginPrefix) {
		request, err = service.readLoginEntry(r.Context(), id)
	} else if strings.HasPrefix(id, samlLoginPrefix) {
		request, err = service.readSAMLLogin(r.Context(), id)
	} else {
		request, err = service.storage.loginRequestByID(r.Context(), id)
	}
	if err != nil {
		http.Error(w, "Invalid or expired login transaction", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(id, oidcLoginPrefix) && request.entry == nil && r.PostForm.Get("action") == "continue" {
		http.Error(w, "Login has progressed. Reopen the login page.", http.StatusBadRequest)
		return
	}
	service.loginTransaction(w, r, request, pathOrganizationID)
}

func validLoginSubmission(r *http.Request, issuer, csrf string) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/x-www-form-urlencoded" && r.Header.Get("Origin") == issuer && sameSecret(csrf, r.PostForm.Get("csrf"))
}

func (service *Service) loginTransaction(w http.ResponseWriter, r *http.Request, request *authorizationRequest, pathOrganizationID string) {
	if request.Complete {
		http.Error(w, "Login transaction has already completed", http.StatusBadRequest)
		return
	}
	registered, err := service.loginPolicy(r.Context(), request)
	if err != nil {
		http.Error(w, "Invalid client", http.StatusBadRequest)
		return
	}
	if pathOrganizationID != "" {
		selectedOrganizationID := loginOrganizationID(request, registered)
		if registered.registration.SubjectKind != "member" || selectedOrganizationID != "" && selectedOrganizationID != pathOrganizationID {
			http.Error(w, "Invalid organization selection", http.StatusBadRequest)
			return
		}
		if request.ProviderOrganizationID == "" {
			if (r.Method != http.MethodGet && registered.registration.OrganizationID == "") || request.Verification != nil || request.phonePending() || request.externalPending() {
				http.Error(w, "Invalid organization selection", http.StatusBadRequest)
				return
			}
			if err := service.selectLoginOrganization(r.Context(), request, registered, pathOrganizationID); err != nil {
				writeLoginOrganizationError(w, err)
				return
			}
			if r.Method == http.MethodGet {
				if err := service.saveLoginNavigation(r.Context(), request); err != nil {
					http.Error(w, "Login transaction expired", http.StatusBadRequest)
					return
				}
			}
		} else if err := service.requireLoginOrganization(r.Context(), pathOrganizationID); err != nil {
			writeLoginOrganizationError(w, err)
			return
		}
	} else if r.Method == http.MethodGet && request.ProviderOrganizationID != "" {
		http.Redirect(w, r, requestLoginURL(request), http.StatusSeeOther)
		return
	}
	message := ""
	if r.Method == http.MethodGet && registered.registration.SubjectKind == "member" && loginOrganizationID(request, registered) == "" && slices.Contains(request.prompts(), "none") && request.SAML == nil && identity.ValidID(request.Input.LoginHint, identity.MemberKind) {
		var organizationID string
		err := service.store.Database().QueryRow(r.Context(), "SELECT organization_id FROM members WHERE id=$1", request.Input.LoginHint).Scan(&organizationID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "Login temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if err == nil && service.selectLoginOrganization(r.Context(), request, registered, organizationID) != nil {
			service.loginError(w, r, request, "login_required")
			return
		}
	}
	if r.Method == http.MethodPost {
		if !validLoginSubmission(r, service.configuration.Issuer, request.CSRF) {
			http.Error(w, "Invalid login submission", http.StatusForbidden)
			return
		}
		action := r.PostForm.Get("action")
		if request.entry != nil && request.SessionID != "" {
			shownSession := request.SessionID
			if !service.loadSession(r, request) || request.SessionID != shownSession {
				http.Error(w, "Login session changed. Reopen the login page.", http.StatusBadRequest)
				return
			}
		}
		if registered.registration.SubjectKind == "member" && loginOrganizationID(request, registered) == "" && action != "choose-organization" && action != "cancel" {
			http.Error(w, "Select an organization before continuing", http.StatusBadRequest)
			return
		}
		switch action {
		case "password":
			service.passwordLogin(w, r, request, registered)
			return
		case "choose-organization":
			if request.Verification != nil || request.phonePending() || request.externalPending() ||
				registered.registration.SubjectKind != "member" || loginOrganizationID(request, registered) != "" {
				http.Error(w, "Invalid organization selection", http.StatusBadRequest)
				return
			}
			organizationID := service.selectedLoginOrganization(w, r, request, registered)
			if organizationID == "" {
				return
			}
			if err := service.saveLoginNavigation(r.Context(), request); err != nil {
				http.Error(w, "Login transaction expired", http.StatusBadRequest)
				return
			}
			http.Redirect(w, r, requestLoginURL(request), http.StatusSeeOther)
			return
		case "feishu":
			service.startFeishu(w, r, request, registered)
			return
		case "dingtalk":
			service.startDingTalk(w, r, request, registered)
			return
		case "send":
			if service.phone == nil || request.externalPending() {
				http.Error(w, "Phone verification unavailable", http.StatusBadRequest)
				return
			}
			if request.phonePending() || request.Verification != nil {
				message = "Cancel the current verification before requesting another code."
				service.renderLogin(w, r, request, registered, message)
				return
			}
			phone, err := identity.NormalizePhone(r.PostForm.Get("phone"))
			if err != nil {
				service.rejectPhoneSend(r, service.loginEvent(r.Context(), request))
				message = "Enter a valid supported phone number."
				service.renderLogin(w, r, request, registered, message)
				return
			}
			// Reserve the attempt before provider I/O. Failed or uncertain delivery
			// stays pending until explicitly canceled.
			request.PhoneNumber, request.Fresh = phone, true
			if err := service.storage.saveRequest(r.Context(), request); err != nil {
				http.Error(w, "Login transaction expired", http.StatusBadRequest)
				return
			}
			challenge, err := service.startPhone(r, request.ID, phone, request.ClientID, service.loginEvent(r.Context(), request))
			if err != nil {
				message = "Unable to send a code. Cancel verification before trying again."
				if errors.Is(err, identity.ErrRateLimited) {
					message = "Please wait before requesting another verification code. Cancel verification to start again."
				}
				service.renderLogin(w, r, request, registered, message)
				return
			}
			request.ChallengeID = challenge.ID
			message = "Verification code requested. Enter the code within five minutes."
		case "verify":
			if service.phone == nil || request.externalPending() {
				http.Error(w, "Phone verification unavailable", http.StatusBadRequest)
				return
			}
			if request.ChallengeID == "" || request.Verification != nil {
				message = "Request a verification code first."
				service.renderLogin(w, r, request, registered, message)
				return
			}
			if err := service.verifyPhoneLogin(w, r, request, r.PostForm.Get("code")); err != nil {
				if errors.Is(err, identity.ErrPhoneChallenge) {
					service.renderLogin(w, r, request, registered, "The code is invalid, expired, or unavailable. Request a new code if needed.")
				} else {
					http.Error(w, "Login could not complete. Reopen the login page before trying again.", http.StatusBadRequest)
				}
				return
			}
			service.renderLogin(w, r, request, registered, "Phone verified.")
			return
		case "cancel":
			request.DingTalk, request.Feishu = nil, nil
			request.Verification = nil
			request.ChallengeID = ""
			request.PhoneNumber = ""
			request.SessionID = ""
			request.Fresh = true
			request.FactorID, request.MemberID, request.OrganizationID, request.BindingID = "", "", "", ""
			if registered.registration.OrganizationID == "" {
				if err := service.saveLoginNavigation(r.Context(), request); err != nil {
					http.Error(w, "Login transaction expired", http.StatusBadRequest)
					return
				}
				http.Redirect(w, r, requestLoginURL(request), http.StatusSeeOther)
				return
			}
		case "continue":
			if request.Verification == nil {
				message = "Verify your identity before continuing."
				service.renderLogin(w, r, request, registered, message)
				return
			}
			if (!registered.registration.Preauthorized || slices.Contains(request.prompts(), "consent")) && r.PostForm.Get("consent") != "yes" {
				message = "Approve the requested identity information before continuing."
				service.renderLogin(w, r, request, registered, message)
				return
			}
			if registered.registration.SubjectKind == "member" {
				members, err := service.members(r, request, registered)
				if err != nil {
					http.Error(w, "Login temporarily unavailable", http.StatusServiceUnavailable)
					return
				}
				found := false
				for _, member := range members {
					if member.ID == r.PostForm.Get("member") {
						request.MemberID, request.OrganizationID = member.ID, member.OrganizationID
						found = true
						break
					}
				}
				if !found {
					service.renderLogin(w, r, request, registered, "Select an available Member identity.")
					return
				}
			} else if r.PostForm.Get("member") != "" {
				http.Error(w, "Invalid subject selection", http.StatusBadRequest)
				return
			}
			if err := service.finish(w, r, request); err != nil {
				http.Error(w, "Identity is no longer eligible. Start a new login.", http.StatusForbidden)
			}
			return
		default:
			http.Error(w, "Invalid login action", http.StatusBadRequest)
			return
		}
		if err := service.saveLoginNavigation(r.Context(), request); err != nil {
			http.Error(w, "Login transaction expired", http.StatusBadRequest)
			return
		}
	} else if request.Verification == nil && (registered.registration.SubjectKind == "factor" || loginOrganizationID(request, registered) != "" || slices.Contains(request.prompts(), "none")) {
		hadSession := request.entry != nil && request.SessionID != ""
		if hadSession {
			request.SessionID = ""
		}
		if service.loadSession(r, request) || hadSession {
			if request.browserHeldSAML() {
				request.entryToken, err = service.sealSAMLLogin(request, request.Revision)
			} else {
				err = service.saveLoginNavigation(r.Context(), request)
			}
			if err != nil {
				http.Error(w, "Login transaction expired", http.StatusBadRequest)
				return
			}
		}
	}
	if slices.Contains(request.prompts(), "none") {
		if request.Verification == nil {
			service.loginError(w, r, request, "login_required")
			return
		}
		if !registered.registration.Preauthorized {
			service.loginError(w, r, request, "consent_required")
			return
		}
		if registered.registration.SubjectKind == "member" {
			members, err := service.members(r, request, registered)
			if err != nil || len(members) != 1 {
				service.loginError(w, r, request, "interaction_required")
				return
			}
			if registered.activation != nil && request.ProviderOrganizationID == "" {
				if err := service.selectLoginOrganization(r.Context(), request, registered, members[0].OrganizationID); err != nil {
					service.loginError(w, r, request, "login_required")
					return
				}
			}
			request.MemberID, request.OrganizationID = members[0].ID, members[0].OrganizationID
		}
		if err := service.finish(w, r, request); err != nil {
			service.loginError(w, r, request, "login_required")
		}
		return
	}
	service.renderLogin(w, r, request, registered, message)
}
