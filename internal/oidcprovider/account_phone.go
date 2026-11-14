package oidcprovider

import (
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"mime"
	"net/http"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
)

const phoneAccountPath = "/account/link/phone"

//go:embed account_phone.html
var phoneAccountHTML string
var phoneAccountPage = template.Must(template.New("phone-account").Parse(phoneAccountHTML))

func (service *Service) accountPhone(w http.ResponseWriter, r *http.Request) {
	if service.phone == nil {
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
		service.accountPhonePost(w, r, session)
		return
	}
	request, member, ok := service.openAccount(w, r, session, "phone")
	if ok {
		service.renderPhoneAccount(w, r, request, session, member, "")
	}
}

func (service *Service) accountPhonePost(w http.ResponseWriter, r *http.Request, session accountSession) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" || r.Header.Get("Origin") != service.configuration.Issuer || !accountFields(r, "request", "csrf", "action", "phone", "code") {
		http.Error(w, "Invalid account submission", 403)
		return
	}
	request, err := service.readAccount(r, "id", r.PostForm.Get("request"))
	if err != nil || request.Kind != "phone" || request.SessionID != session.id || !sameSecret(request.CSRF, r.PostForm.Get("csrf")) {
		http.Error(w, "Invalid or expired account request", 403)
		return
	}
	member, binding, err := service.accountMember(r, session, request.MemberID)
	if err != nil || binding != request.BindingID || session.verified.Factor.ID != request.FactorID {
		http.Error(w, "Member identity is no longer eligible", 403)
		return
	}
	if r.PostForm.Get("action") == "cancel" {
		result, err := service.store.Database().Exec(r.Context(), "UPDATE account_link_requests SET state='canceled' WHERE id=$1 AND state IN ('ready','pending','consumed')", request.ID)
		if err != nil || result.RowsAffected() != 1 {
			http.Error(w, "Account request is no longer pending", 400)
			return
		}
		http.Redirect(w, r, accountAddress(request.accountDetails), http.StatusSeeOther)
		return
	}
	if !service.freshAccountSession(session) {
		service.renderPhoneAccount(w, r, request, session, member, "Sign in again through your application before linking a new authentication method.")
		return
	}
	switch r.PostForm.Get("action") {
	case "send":
		if request.State != "ready" {
			http.Error(w, "Cancel the current verification before requesting another code.", 400)
			return
		}
		phone, err := identity.NormalizePhone(r.PostForm.Get("phone"))
		if err != nil {
			service.renderPhoneAccount(w, r, request, session, member, "Enter a valid supported phone number.")
			return
		}
		bindings, err := service.store.Bindings(r.Context(), member.OrganizationID, member.ID)
		if err != nil {
			http.Error(w, "Account management temporarily unavailable", 503)
			return
		}
		for _, existing := range bindings {
			if existing.FactorType == "phone" {
				service.renderPhoneAccount(w, r, request, session, member, "This Member already has a phone binding. Self-service cannot replace or restore a binding.")
				return
			}
		}
		request.PhoneNumber = phone
		pendingData, err := json.Marshal(request.accountDetails)
		if err != nil {
			http.Error(w, "Account management temporarily unavailable", 503)
			return
		}
		// Reserve before sending. Concurrent submissions and uncertain delivery
		// cannot silently send twice or replace the pending challenge.
		err = pgx.BeginFunc(r.Context(), service.store.Database(), func(tx pgx.Tx) error {
			current, err := service.accountSession(r, tx, true)
			if err != nil || current.id != request.SessionID || !service.freshAccountSession(current) {
				return identity.ErrIneligible
			}
			if _, err := tx.Exec(r.Context(), "UPDATE account_link_requests SET state='canceled' WHERE session_id=$1 AND id<>$2 AND data->>'memberId'=$3 AND state IN ('ready','pending','consumed')", session.id, request.ID, member.ID); err != nil {
				return err
			}
			result, err := tx.Exec(r.Context(), "UPDATE account_link_requests SET state='pending',data=$3 WHERE id=$1 AND state='ready' AND expires_at>$2", request.ID, service.now(), pendingData)
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
		request.State = "pending"
		challenge, err := service.phone.Start(r.Context(), request.ID, phone)
		if err != nil {
			message := "Unable to send a code. Cancel verification before trying again."
			if errors.Is(err, identity.ErrRateLimited) {
				message = "Please wait before requesting another code. Cancel verification to start again."
			}
			service.renderPhoneAccount(w, r, request, session, member, message)
			return
		}
		request.PhoneNumber, request.ChallengeID = phone, challenge.ID
		data, err := json.Marshal(request.accountDetails)
		if err != nil {
			http.Error(w, "Account management temporarily unavailable", 503)
			return
		}
		result, err := service.store.Database().Exec(r.Context(), "UPDATE account_link_requests SET data=$2 WHERE id=$1 AND state='pending' AND expires_at>$3", request.ID, data, service.now())
		if err != nil || result.RowsAffected() != 1 {
			http.Error(w, "Account request expired or was canceled. Reopen the account page.", 400)
			return
		}
		service.renderPhoneAccount(w, r, request, session, member, "Enter the verification code to link this phone to the selected Member. Cancel verification to edit the number.")
	case "verify":
		if request.State != "pending" || request.ChallengeID == "" {
			http.Error(w, "No pending phone verification", 400)
			return
		}
		_, err := service.phone.VerifyAndApply(r.Context(), request.ID, request.ChallengeID, r.PostForm.Get("code"), func(tx pgx.Tx, verified identity.Verification) error {
			current, err := service.accountSession(r, tx, true)
			if err != nil || current.id != request.SessionID || current.verified.Factor.ID != request.FactorID || !service.freshAccountSession(current) {
				return identity.ErrIneligible
			}
			var state, challenge string
			if err := tx.QueryRow(r.Context(), "SELECT state,data->>'challengeId' FROM account_link_requests WHERE id=$1 AND expires_at>$2 FOR UPDATE", request.ID, service.now()).Scan(&state, &challenge); err != nil || state != "pending" || challenge != request.ChallengeID || !service.accountClient(request.accountDetails) {
				return identity.ErrIneligible
			}
			principal := identity.AccountPrincipal(current.id, request.MemberID, current.verified.Factor.ID, request.BindingID)
			target := identity.PhoneLinkTarget{OrganizationID: request.OrganizationID, MemberID: request.MemberID, SourceFactorID: request.FactorID, SourceBindingID: request.BindingID}
			if err := identity.LinkPhone(r.Context(), tx, principal, verified, target); err != nil {
				return err
			}
			_, err = tx.Exec(r.Context(), "UPDATE account_link_requests SET state='completed' WHERE id=$1", request.ID)
			return err
		})
		if err != nil {
			message := "The code is invalid, expired, or unavailable. Cancel verification to request another code if needed."
			if !errors.Is(err, identity.ErrPhoneChallenge) {
				_, _ = service.store.Database().Exec(r.Context(), "UPDATE account_link_requests SET state='consumed' WHERE id=$1 AND state='pending'", request.ID)
				message = "Unable to link this phone. It may already belong to another Member or the request is no longer eligible. Cancel verification to try again."
			}
			if latest, readErr := service.readAccount(r, "id", request.ID); readErr == nil {
				request = latest
			}
			service.renderPhoneAccount(w, r, request, session, member, message)
			return
		}
		request.State = "completed"
		service.renderPhoneAccount(w, r, request, session, member, "Phone is linked to this Member. You can now use it to sign in to this organization.")
	default:
		http.Error(w, "Invalid account action", 400)
	}
}

type phoneAccountPageData struct {
	Request                                         accountRequest
	Member, Organization, Message, Nonce, ReopenURI string
	CanSend, CanVerify, CanCancel, NumberLocked     bool
}

func (service *Service) renderPhoneAccount(w http.ResponseWriter, r *http.Request, request accountRequest, session accountSession, member identity.Member, message string) {
	bindings, err := service.store.Bindings(r.Context(), member.OrganizationID, member.ID)
	if err != nil {
		http.Error(w, "Account management temporarily unavailable", 503)
		return
	}
	occupied := false
	for _, binding := range bindings {
		if binding.FactorType == "phone" {
			occupied = true
		}
	}
	fresh := service.freshAccountSession(session)
	if message == "" {
		switch {
		case occupied:
			message = "This Member already has a phone binding. Self-service cannot replace or restore a binding. Contact your organization administrator if needed."
		case request.State != "ready":
			message = "Phone verification is pending. Enter the code or cancel verification before starting again."
		case !fresh:
			message = "Sign in again through your application, then reopen this page within five minutes to link a phone."
		default:
			message = "Confirm the Member below, then verify the phone to link. Each organization keeps an independent Member identity."
		}
	}
	organization, err := service.store.Organization(r.Context(), member.OrganizationID)
	if err != nil {
		http.Error(w, "Account management temporarily unavailable", 503)
		return
	}
	available := request.ExpiresAt.After(service.now()) && service.accountClient(request.accountDetails)
	if !service.accountClient(request.accountDetails) {
		request.ClientID, request.ReturnURI = "", ""
	}
	data := phoneAccountPageData{Request: request, Member: member.DisplayName, Organization: organization.Name, Message: message, Nonce: config.RandomSecret(), ReopenURI: accountAddress(request.accountDetails), CanSend: available && fresh && !occupied && request.State == "ready", CanVerify: available && fresh && !occupied && request.State == "pending" && request.ChallengeID != "", CanCancel: available && (request.State == "pending" || request.State == "consumed"), NumberLocked: request.State != "ready" || occupied || !fresh}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+data.Nonce+"'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = phoneAccountPage.Execute(w, data)
}
