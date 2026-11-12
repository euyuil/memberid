package oidcprovider

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func (service *Service) loadSession(r *http.Request, request *authorizationRequest) bool {
	if request.Fresh || slices.Contains(request.Input.Prompt, "login") {
		return false
	}
	secret := service.cookieValue(r, "session")
	if len(secret) != 43 {
		return false
	}
	var data []byte
	var id string
	if err := service.store.Database().QueryRow(r.Context(), "SELECT id,verification FROM oidc_sessions WHERE secret_hash=$1 AND revoked_at IS NULL AND expires_at>$2 AND absolute_expires_at>$2", config.SecretHash(secret), service.now()).Scan(&id, &data); err != nil {
		return false
	}
	var verified identity.Verification
	if json.Unmarshal(data, &verified) != nil {
		return false
	}
	if request.Input.MaxAge != nil && service.now().Sub(verified.AuthenticatedAt) > time.Duration(*request.Input.MaxAge)*time.Second {
		return false
	}
	factor, err := service.store.Factor(r.Context(), verified.Factor.ID)
	if err != nil || factor.Status != "active" {
		return false
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
func (service *Service) createSession(w http.ResponseWriter, r *http.Request, request *authorizationRequest, verified identity.Verification) error {
	id, secret := newID(), config.RandomSecret()
	data, err := json.Marshal(verified)
	if err != nil {
		return err
	}
	absolute := verified.AuthenticatedAt.Add(maximumLifetime)
	expiry := minimum(service.now().Add(sessionIdleLifetime), absolute)
	if _, err := service.store.Database().Exec(r.Context(), "INSERT INTO oidc_sessions(id,secret_hash,verification,expires_at,absolute_expires_at) VALUES($1,$2,$3,$4,$5)", id, config.SecretHash(secret), data, expiry, absolute); err != nil {
		return err
	}
	service.cookie(w, "session", secret, expiry.Sub(service.now()))
	request.SessionID = id
	setVerification(request, verified)
	return nil
}

func (service *Service) members(r *http.Request, request *authorizationRequest, client client) ([]identity.Member, error) {
	if request.Verification == nil || client.registration.SubjectKind == "factor" {
		return nil, nil
	}
	members, err := service.store.EligibleMembers(r.Context(), request.FactorID)
	if err != nil {
		return nil, err
	}
	filtered := members[:0]
	for _, member := range members {
		if client.registration.OrganizationID == "" || member.OrganizationID == client.registration.OrganizationID {
			filtered = append(filtered, member)
		}
	}
	return filtered, nil
}

func (service *Service) finish(w http.ResponseWriter, r *http.Request, request *authorizationRequest) error {
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
	protocolError := &oidc.Error{ErrorType: "login_required"}
	switch kind {
	case "consent_required":
		protocolError.ErrorType = "consent_required"
	case "interaction_required":
		protocolError.ErrorType = "interaction_required"
	}
	op.AuthRequestError(w, r.WithContext(op.ContextWithIssuer(r.Context(), service.configuration.Issuer)), &request.Input, protocolError, service.protocol)
}

func (service *Service) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	input, err := service.storage.AuthRequestByID(r.Context(), r.Form.Get("request"))
	if err != nil {
		http.Error(w, "Invalid or expired login transaction", http.StatusBadRequest)
		return
	}
	request := input.(*authorizationRequest)
	if request.Complete {
		http.Error(w, "Login transaction has already completed", http.StatusBadRequest)
		return
	}
	registered, err := service.storage.client(request.ClientID)
	if err != nil {
		http.Error(w, "Invalid client", http.StatusBadRequest)
		return
	}
	message := ""
	if r.Method == http.MethodPost {
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/x-www-form-urlencoded" || r.Header.Get("Origin") != service.configuration.Issuer || !sameSecret(request.CSRF, r.PostForm.Get("csrf")) {
			http.Error(w, "Invalid login submission", http.StatusForbidden)
			return
		}
		switch r.PostForm.Get("action") {
		case "send":
			if request.ChallengeID != "" || request.Verification != nil {
				message = "Cancel the current verification before requesting another code."
				break
			}
			challenge, err := service.phone.Start(r.Context(), request.ID, r.PostForm.Get("phone"))
			if err != nil {
				message = "Unable to send a code. Check the number and try again later."
				if errors.Is(err, identity.ErrRateLimited) {
					message = "Please wait before requesting another verification code."
				}
				break
			}
			request.PhoneNumber, _ = identity.NormalizePhone(r.PostForm.Get("phone"))
			request.ChallengeID = challenge.ID
			request.Fresh = true
			message = "Verification code requested. Enter the code within five minutes."
		case "verify":
			if request.ChallengeID == "" || request.Verification != nil {
				message = "Request a verification code first."
				break
			}
			verified, err := service.phone.Verify(r.Context(), request.ID, request.ChallengeID, r.PostForm.Get("code"))
			if err != nil {
				message = "The code is invalid, expired, or unavailable. Request a new code if needed."
				break
			}
			if err := service.createSession(w, r, request, verified); err != nil {
				http.Error(w, "Login temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			message = "Phone verified. Select your identity and continue."
		case "cancel":
			request.Verification = nil
			request.ChallengeID = ""
			request.PhoneNumber = ""
			request.SessionID = ""
			request.Fresh = true
			request.FactorID, request.MemberID, request.OrganizationID, request.BindingID = "", "", "", ""
		case "continue":
			if request.Verification == nil {
				message = "Verify your phone before continuing."
				break
			}
			if (!registered.registration.Preauthorized || slices.Contains(request.Input.Prompt, "consent")) && r.PostForm.Get("consent") != "yes" {
				message = "Approve the requested identity information before continuing."
				break
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
					message = "Select an available Member identity."
					break
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
		if err := service.storage.saveRequest(r.Context(), request); err != nil {
			http.Error(w, "Login transaction expired", http.StatusBadRequest)
			return
		}
	} else if request.Verification == nil {
		if service.loadSession(r, request) {
			if err := service.storage.saveRequest(r.Context(), request); err != nil {
				http.Error(w, "Login transaction expired", http.StatusBadRequest)
				return
			}
		}
	}
	if slices.Contains(request.Input.Prompt, "none") {
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
			request.MemberID, request.OrganizationID = members[0].ID, members[0].OrganizationID
		}
		if err := service.finish(w, r, request); err != nil {
			service.loginError(w, r, request, "login_required")
		}
		return
	}
	service.renderLogin(w, r, request, registered, message)
}
