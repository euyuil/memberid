package oidcprovider

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zhizhun-tech/memberid/internal/authevent"
	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/feishu"
	"github.com/zhizhun-tech/memberid/internal/identity"
	"golang.org/x/oauth2"
)

const accountLifetime = 5 * time.Minute
const accountPath = "/account/link/dingtalk"
const feishuAccountPath = "/account/link/feishu"
const feishuAccountCallbackPath = "/account/feishu/callback"

//go:embed account.html
var accountHTML string
var accountPage = template.Must(template.New("account").Parse(accountHTML))

type accountRequest struct {
	ID, SessionID, State string
	ExpiresAt            time.Time
	accountDetails
}
type accountDetails struct {
	InteractionID  string                        `json:"interactionId"`
	Kind           string                        `json:"kind"`
	PhoneNumber    string                        `json:"phoneNumber,omitempty"`
	ChallengeID    string                        `json:"challengeId,omitempty"`
	MemberID       string                        `json:"memberId"`
	OrganizationID string                        `json:"organizationId"`
	FactorID       string                        `json:"factorId"`
	BindingID      string                        `json:"bindingId"`
	ClientID       string                        `json:"clientId,omitempty"`
	ReturnURI      string                        `json:"returnUri,omitempty"`
	BrowserHash    string                        `json:"browserHash"`
	CSRF           string                        `json:"csrf"`
	Login          identity.DingTalkLoginContext `json:"login"`
	Feishu         *feishuAttempt                `json:"feishu,omitempty"`
}
type accountSession struct {
	id       string
	verified identity.Verification
}
type accountQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (service *Service) accountSession(r *http.Request, database accountQueryer, lock bool) (accountSession, error) {
	var session accountSession
	secret := service.cookieValue(r, "session")
	if len(secret) != 43 {
		return session, identity.ErrIneligible
	}
	query := "SELECT id,verification FROM authentication_sessions WHERE secret_hash=$1 AND revoked_at IS NULL AND expires_at>$2 AND absolute_expires_at>$2"
	if lock {
		query += " FOR UPDATE"
	}
	var data []byte
	if err := database.QueryRow(r.Context(), query, config.SecretHash(secret), service.now()).Scan(&session.id, &data); err != nil {
		return session, err
	}
	if json.Unmarshal(data, &session.verified) != nil {
		return session, identity.ErrIneligible
	}
	return session, nil
}
func (service *Service) freshAccountSession(session accountSession) bool {
	at := session.verified.AuthenticatedAt
	return !at.IsZero() && !at.After(service.now()) && at.Add(accountLifetime).After(service.now())
}
func (service *Service) accountClient(ctx context.Context, db databaseReader, details accountDetails) bool {
	if details.ClientID == "" {
		return details.ReturnURI == ""
	}
	client, err := service.storage.clientAt(ctx, db, details.ClientID)
	if err != nil || client.registration.SubjectKind != "member" || !slices.Contains(client.registration.AccountReturnURIs, details.ReturnURI) {
		return false
	}
	_, err = client.organizationActivation(ctx, db, details.OrganizationID)
	return err == nil
}
func (service *Service) accountMember(r *http.Request, session accountSession, memberID string) (identity.Member, string, error) {
	members, err := service.store.EligibleMembers(r.Context(), session.verified.Factor.ID)
	if err != nil {
		return identity.Member{}, "", err
	}
	for _, member := range members {
		if member.ID == memberID {
			binding, err := identity.MemberEvidence(r.Context(), service.store.Database(), session.verified.Factor.ID, member.ID, member.OrganizationID)
			if err != nil {
				return identity.Member{}, "", err
			}
			principal := identity.AccountPrincipal(session.id, member.ID, session.verified.Factor.ID, binding)
			if err := service.store.AuthorizeAccountView(r.Context(), principal, member.OrganizationID); err != nil {
				return identity.Member{}, "", err
			}
			return member, binding, nil
		}
	}
	return identity.Member{}, "", identity.ErrIneligible
}
func accountBrowser(r *http.Request) string {
	browser, _ := r.Context().Value(browserKey{}).(string)
	return browser
}
func accountFields(r *http.Request, names ...string) bool {
	for name := range r.Form {
		if !slices.Contains(names, name) {
			return false
		}
	}
	return true
}
func (service *Service) readAccount(r *http.Request, field, value string) (accountRequest, error) {
	var request accountRequest
	var data []byte
	// field is supplied only by the two fixed call sites, never by HTTP input.
	err := service.store.Database().QueryRow(r.Context(), "SELECT id,session_id,state,expires_at,data FROM account_link_requests WHERE "+field+"=$1 AND expires_at>$2", value, service.now()).Scan(&request.ID, &request.SessionID, &request.State, &request.ExpiresAt, &data)
	if err == nil {
		err = json.Unmarshal(data, &request.accountDetails)
	}
	if err == nil && ((request.Kind != "phone" && request.Kind != "dingtalk" && request.Kind != "feishu") || len(accountBrowser(r)) != 43 || !service.accountClient(r.Context(), service.store.Database(), request.accountDetails) || !sameSecret(request.BrowserHash, config.SecretHash(accountBrowser(r)))) {
		err = identity.ErrIneligible
	}
	return request, err
}
func accountAddress(request accountDetails) string {
	query := url.Values{"memberId": {request.MemberID}}
	if request.ClientID != "" {
		query.Set("client_id", request.ClientID)
		query.Set("returnUri", request.ReturnURI)
	}
	return "/account/link/" + request.Kind + "?" + query.Encode()
}

func (service *Service) accountExternal(w http.ResponseWriter, r *http.Request, kind string) {
	if !service.accountProviderEnabled(kind) {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", 405)
		return
	}
	session, err := service.accountSession(r, service.store.Database(), false)
	if err != nil {
		http.Error(w, "Sign in through a registered application, then reopen this MemberID account page.", 401)
		return
	}
	if r.Method == http.MethodPost {
		service.accountExternalPost(w, r, session, kind)
		return
	}
	request, member, ok := service.openAccount(w, r, session, kind)
	if ok {
		service.renderAccount(w, r, request, session, member, "")
	}
}

func (service *Service) openAccount(w http.ResponseWriter, r *http.Request, session accountSession, kind string) (accountRequest, identity.Member, bool) {
	if !accountFields(r, "memberId", "client_id", "returnUri") || !identity.ValidID(r.Form.Get("memberId"), identity.MemberKind) {
		http.Error(w, "Invalid account request", 400)
		return accountRequest{}, identity.Member{}, false
	}
	member, binding, err := service.accountMember(r, session, r.Form.Get("memberId"))
	if err != nil {
		http.Error(w, "This Member identity is not available to the current session.", 403)
		return accountRequest{}, identity.Member{}, false
	}
	details := accountDetails{InteractionID: newID(), Kind: kind, MemberID: member.ID, OrganizationID: member.OrganizationID, FactorID: session.verified.Factor.ID, BindingID: binding, ClientID: r.Form.Get("client_id"), ReturnURI: r.Form.Get("returnUri"), BrowserHash: config.SecretHash(accountBrowser(r))}
	if !service.accountClient(r.Context(), service.store.Database(), details) {
		http.Error(w, "Invalid account return destination or client", 400)
		return accountRequest{}, identity.Member{}, false
	}
	request := accountRequest{SessionID: session.id, accountDetails: details}
	// Reopening a pending flow preserves its cancel action and original destination.
	var existing string
	err = service.store.Database().QueryRow(r.Context(), `SELECT id FROM account_link_requests WHERE session_id=$1 AND expires_at>$2 AND state IN ('ready','pending','consumed')
  AND data->>'kind'=$7 AND data->>'memberId'=$3 AND data->>'browserHash'=$4 AND COALESCE(data->>'clientId','')=$5 AND COALESCE(data->>'returnUri','')=$6 ORDER BY expires_at DESC LIMIT 1`, session.id, service.now(), member.ID, details.BrowserHash, details.ClientID, details.ReturnURI, kind).Scan(&existing)
	if err == nil {
		request, err = service.readAccount(r, "id", existing)
	} else if errors.Is(err, pgx.ErrNoRows) {
		request.ID, request.State, request.ExpiresAt = newID(), "ready", service.now().Add(accountLifetime)
		request.CSRF = config.RandomSecret()
		var data []byte
		data, err = json.Marshal(request.accountDetails)
		if err == nil {
			_, err = service.store.Database().Exec(r.Context(), "INSERT INTO account_link_requests(id,session_id,data,state,expires_at) VALUES($1,$2,$3,'ready',$4)", request.ID, session.id, data, request.ExpiresAt)
		}
	}
	if err != nil {
		http.Error(w, "Account management temporarily unavailable", 503)
		return accountRequest{}, identity.Member{}, false
	}
	return request, member, true
}

func (service *Service) accountExternalPost(w http.ResponseWriter, r *http.Request, session accountSession, kind string) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" || r.Header.Get("Origin") != service.configuration.Issuer || !accountFields(r, "request", "csrf", "action", "provider") {
		http.Error(w, "Invalid account submission", 403)
		return
	}
	request, err := service.readAccount(r, "id", r.PostForm.Get("request"))
	if err != nil || request.Kind != kind || request.SessionID != session.id || !sameSecret(request.CSRF, r.PostForm.Get("csrf")) {
		http.Error(w, "Invalid or expired account request", 403)
		return
	}
	member, binding, err := service.accountMember(r, session, request.MemberID)
	if err != nil || binding != request.BindingID || session.verified.Factor.ID != request.FactorID {
		http.Error(w, "Member identity is no longer eligible", 403)
		return
	}
	switch r.PostForm.Get("action") {
	case "cancel":
		result, err := service.store.Database().Exec(r.Context(), "UPDATE account_link_requests SET state='canceled' WHERE id=$1 AND state IN ('ready','pending','consumed')", request.ID)
		if err != nil || result.RowsAffected() != 1 {
			http.Error(w, "Account request is no longer pending", 400)
			return
		}
		http.Redirect(w, r, accountAddress(request.accountDetails), http.StatusSeeOther)
	case "link":
		if request.State != "ready" || !service.freshAccountSession(session) {
			service.renderAccount(w, r, request, session, member, "Sign in again through your application before linking a new authentication method.")
			return
		}
		state := config.RandomSecret()
		var destination string
		if kind == "feishu" {
			app, login, err := service.feishu.LoginSource(r.Context(), member.OrganizationID, r.PostForm.Get("provider"))
			if err != nil {
				service.renderAccount(w, r, request, session, member, "Feishu is not available for this organization.")
				return
			}
			request.Feishu = &feishuAttempt{FeishuLoginContext: login, Verifier: oauth2.GenerateVerifier(), ExpiresAt: request.ExpiresAt}
			destination = feishu.AuthorizationURL(app.ClientID, service.configuration.Issuer+feishuAccountCallbackPath, state, request.Feishu.Verifier)
		} else {
			app, err := service.dingtalk.ApplicationSource(r.Context(), member.OrganizationID, r.PostForm.Get("provider"))
			if err != nil {
				service.renderAccount(w, r, request, session, member, "DingTalk is not available for this organization.")
				return
			}
			request.Login = app.LoginContext()
			query := url.Values{"client_id": {app.ClientID}, "redirect_uri": {service.configuration.Issuer + "/account/dingtalk/callback"}, "state": {state}, "response_type": {"code"}, "prompt": {"consent"}, "scope": {"openid corpid"}, "corpId": {app.CorpID}}
			destination = "https://login.dingtalk.com/oauth2/auth?" + query.Encode()
		}
		data, _ := json.Marshal(request.accountDetails)
		err = pgx.BeginFunc(r.Context(), service.store.Database(), func(tx pgx.Tx) error {
			current, err := service.accountSession(r, tx, true)
			if err != nil || current.id != request.SessionID || !service.freshAccountSession(current) {
				return identity.ErrIneligible
			}
			// Only the most recently started attempt may finish for this Member/session.
			if _, err := tx.Exec(r.Context(), "UPDATE account_link_requests SET state='canceled' WHERE session_id=$1 AND id<>$2 AND data->>'memberId'=$3 AND state IN ('ready','pending','consumed')", session.id, request.ID, member.ID); err != nil {
				return err
			}
			result, err := tx.Exec(r.Context(), "UPDATE account_link_requests SET state='pending',state_hash=$2,data=$3 WHERE id=$1 AND state='ready' AND expires_at>$4", request.ID, config.SecretHash(state), data, service.now())
			if err != nil {
				return err
			}
			if result.RowsAffected() != 1 {
				return identity.ErrConflict
			}
			return nil
		})
		if err != nil {
			http.Error(w, "Account request expired. Reopen the account page.", 400)
			return
		}
		http.Redirect(w, r, destination, http.StatusSeeOther)
	default:
		http.Error(w, "Invalid account action", 400)
	}
}

func (service *Service) accountExternalCallback(w http.ResponseWriter, r *http.Request, kind string) {
	if !service.accountProviderEnabled(kind) {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", 405)
		return
	}
	event := authevent.Event{Purpose: "accountLinking"}
	failure := errCallbackRejected
	defer func() { service.recordVerification(r, event, kind, failure) }()
	code, valid := dingTalkCallbackCode(r)
	if kind == "feishu" {
		code, valid = r.Form.Get("code"), accountFields(r, "state", "code", "error", "error_description")
	}
	if !valid || len(r.Form.Get("state")) != 43 {
		http.Error(w, "Invalid account callback", 400)
		return
	}
	request, err := service.readAccount(r, "state_hash", config.SecretHash(r.Form.Get("state")))
	session, sessionErr := service.accountSession(r, service.store.Database(), false)
	if err != nil || request.Kind != kind || sessionErr != nil || request.SessionID != session.id || request.State != "pending" || !service.freshAccountSession(session) {
		if err != nil {
			failure = err
		} else if sessionErr != nil {
			failure = sessionErr
		}
		http.Error(w, "Invalid or expired account callback", 400)
		return
	}
	member, binding, err := service.accountMember(r, session, request.MemberID)
	if err != nil || binding != request.BindingID || session.verified.Factor.ID != request.FactorID {
		if err != nil {
			failure = err
		}
		http.Error(w, "Member identity is no longer eligible", 403)
		return
	}
	event = accountEvent(request, session)
	event.ProviderID = request.Login.Namespace
	label := "DingTalk"
	if kind == "feishu" {
		if request.Feishu == nil || request.Feishu.OrganizationID != request.OrganizationID || request.Feishu.Verifier == "" {
			http.Error(w, "Invalid account callback", 400)
			return
		}
		event.ProviderID, label = request.Feishu.ProviderID, "Feishu"
	}
	event.FactorID, event.BindingID = "", ""
	result, err := service.store.Database().Exec(r.Context(), "UPDATE account_link_requests SET state='consumed',data=data #- '{feishu,verifier}' WHERE id=$1 AND state='pending' AND expires_at>$2", request.ID, service.now())
	if err != nil || result.RowsAffected() != 1 {
		if err != nil {
			failure = err
		}
		http.Error(w, "Invalid or expired account callback", 400)
		return
	}
	request.State = "consumed"
	if r.Form.Get("error") != "" || code == "" {
		if r.Form.Get("error") != "" {
			failure = callbackFailure(r.Form.Get("error"))
		}
		service.renderAccount(w, r, request, session, member, label+" verification did not complete. Cancel verification to try again.")
		return
	}
	var link func(context.Context, pgx.Tx, identity.Principal) (identity.MemberAdmission, error)
	if kind == "feishu" {
		var proof identity.FeishuProof
		proof, err = service.feishu.Verify(r.Context(), request.Feishu.FeishuLoginContext, service.configuration.Issuer+feishuAccountCallbackPath, code, request.Feishu.Verifier)
		link = func(ctx context.Context, tx pgx.Tx, principal identity.Principal) (identity.MemberAdmission, error) {
			return service.feishu.Link(ctx, tx, principal, proof, request.MemberID)
		}
	} else {
		var proof identity.DingTalkLoginProof
		proof, err = service.dingtalk.Verify(r.Context(), request.Login, code)
		link = func(ctx context.Context, tx pgx.Tx, principal identity.Principal) (identity.MemberAdmission, error) {
			return service.dingtalk.Link(ctx, tx, principal, proof, request.MemberID)
		}
	}
	if err != nil {
		failure = err
		service.renderAccount(w, r, request, session, member, "Unable to verify "+label+" membership. Cancel verification to try again.")
		return
	}
	var admitted identity.MemberAdmission
	err = pgx.BeginFunc(r.Context(), service.store.Database(), func(tx pgx.Tx) error {
		current, err := service.accountSession(r, tx, true)
		if err != nil {
			return accountVerificationError(err)
		}
		if current.id != request.SessionID || current.verified.Factor.ID != request.FactorID || !service.freshAccountSession(current) {
			return identity.ErrIneligible
		}
		var state string
		if err := tx.QueryRow(r.Context(), "SELECT state FROM account_link_requests WHERE id=$1 AND expires_at>$2 FOR UPDATE", request.ID, service.now()).Scan(&state); err != nil {
			return accountVerificationError(err)
		}
		if state != "consumed" {
			return identity.ErrConflict
		}
		if !service.accountClient(r.Context(), tx, request.accountDetails) {
			return identity.ErrIneligible
		}
		principal := identity.AccountPrincipal(current.id, request.MemberID, current.verified.Factor.ID, request.BindingID)
		admitted, err = link(r.Context(), tx, principal)
		if err != nil {
			return err
		}
		_, err = tx.Exec(r.Context(), "UPDATE account_link_requests SET state='completed' WHERE id=$1", request.ID)
		return err
	})
	if err != nil {
		failure = err
		message := "Unable to link this identity. It may already belong to another Member or the request is no longer eligible. Cancel verification to try again."
		if kind == "feishu" && errors.Is(err, identity.ErrConflict) {
			message = "Unable to link this identity: a binding conflict exists. The identity is already linked, or the application's binding slot is occupied or revoked. Contact your organization administrator."
		}
		service.renderAccount(w, r, request, session, member, message)
		return
	}
	failure = nil
	event.FactorID, event.BindingID = admitted.Factor.ID, admitted.BindingID
	request.State = "completed"
	service.renderAccount(w, r, request, session, member, label+" is linked to this Member. Your current session and existing grants keep their original authentication and expiry.")
}

func (service *Service) accountProviderEnabled(kind string) bool {
	return kind == "dingtalk" && service.dingtalk != nil || kind == "feishu" && service.feishu != nil
}

type accountPageData struct {
	ProviderLabel                                   string
	Request                                         accountRequest
	Member, Organization, Message, Nonce, ReopenURI string
	CanLink, CanCancel                              bool
	Providers                                       []identity.Provider
	OccupiedProviders                               map[string]bool
}

func (service *Service) renderAccount(w http.ResponseWriter, r *http.Request, request accountRequest, session accountSession, member identity.Member, message string) {
	bindings, err := service.store.Bindings(r.Context(), member.OrganizationID, member.ID)
	if err != nil {
		http.Error(w, "Account management temporarily unavailable", 503)
		return
	}
	occupied := false
	occupiedProviders := map[string]bool{}
	for _, binding := range bindings {
		if binding.FactorType == request.Kind {
			if request.Kind == "dingtalk" {
				occupied = true
			}
			if request.Kind == "feishu" {
				factor, err := service.store.Factor(r.Context(), binding.FactorID)
				if err != nil {
					http.Error(w, "Account management temporarily unavailable", 503)
					return
				}
				occupiedProviders[factor.Namespace] = true
			}
		}
	}
	label := "DingTalk"
	formAction := "https://login.dingtalk.com"
	if request.Kind == "feishu" {
		label = "Feishu"
		formAction = "https://accounts.feishu.cn"
	}
	fresh := service.freshAccountSession(session)
	if message == "" {
		switch {
		case occupied:
			message = "This Member already has a " + label + " binding. Self-service cannot replace or restore a binding. Contact your organization administrator if needed."
		case request.State != "ready":
			message = label + " verification is pending. Complete it with the provider or cancel verification before starting again."
		case !fresh:
			message = "Sign in again through your application, then reopen this page within five minutes to link " + label + "."
		}
	}
	organization, err := service.store.Organization(r.Context(), member.OrganizationID)
	if err != nil {
		http.Error(w, "Account management temporarily unavailable", 503)
		return
	}
	available := request.ExpiresAt.After(service.now()) && service.accountClient(r.Context(), service.store.Database(), request.accountDetails)
	if !service.accountClient(r.Context(), service.store.Database(), request.accountDetails) {
		request.ReturnURI = ""
		request.ClientID = ""
	}
	data := accountPageData{OccupiedProviders: occupiedProviders, ProviderLabel: label, Request: request, Member: member.DisplayName, Organization: organization.Name, Message: message, Nonce: config.RandomSecret(), ReopenURI: accountAddress(request.accountDetails), CanLink: available && request.State == "ready" && fresh && !occupied, CanCancel: available && (request.State == "pending" || request.State == "consumed")}
	providers, err := service.store.Providers(r.Context(), member.OrganizationID)
	if err != nil {
		http.Error(w, "Account management temporarily unavailable", 503)
		return
	}
	availableProvider := false
	for _, provider := range providers {
		if provider.Type == request.Kind && provider.Enabled && provider.AuthorizationStatus == "active" {
			data.Providers = append(data.Providers, provider)
			availableProvider = availableProvider || !occupiedProviders[provider.ID]
		}
	}
	data.CanLink = data.CanLink && availableProvider
	if !availableProvider && message == "" {
		data.Message = "No available application. Existing or revoked bindings require an administrator."
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+data.Nonce+"'; form-action 'self' "+formAction+"; base-uri 'none'; frame-ancestors 'none'")
	writeHTMLPage(w, accountPage, data)
}
