package oidcprovider

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zhizhun-tech/memberid/internal/authevent"
	"github.com/zhizhun-tech/memberid/internal/browserauth"
	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/identity"
	"github.com/zhizhun-tech/memberid/internal/samlprovider"
)

func (service *Service) samlSSO(w http.ResponseWriter, r *http.Request) {
	if service.saml == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", 405)
		return
	}
	entityID, err := samlprovider.Inspect(r)
	if err != nil {
		http.Error(w, "Invalid SAML request", 400)
		return
	}
	sp, err := service.store.SAMLServiceProviderByEntityID(r.Context(), entityID)
	if err != nil || !sp.Enabled || sp.Retired {
		http.Error(w, "SAML service provider unavailable", 400)
		return
	}
	if err := sp.Validate(service.configuration.AllowLoopbackHTTP); err != nil {
		http.Error(w, "SAML service provider unavailable", 503)
		return
	}
	txn, status, err := service.saml.Parse(r, sp, service.now())
	if err != nil {
		service.samlEvent(r, nil, "saml.request", "rejected", "invalidRequest")
		http.Error(w, "Invalid SAML request", 400)
		return
	}
	browser, _ := r.Context().Value(browserKey{}).(string)
	newBrowser := len(browser) != 43
	if newBrowser {
		browser = config.RandomSecret()
	}
	request := &authorizationRequest{grant: grant{ID: newID(), InteractionID: newID(), ClientID: sp.ID}, Interaction: browserauth.Interaction{Revision: 1, BrowserHash: config.SecretHash(browser), CSRF: config.RandomSecret(), ProviderOrganizationID: sp.OrganizationID}, SAML: txn}
	request.entryToken, err = service.sealSAMLLogin(request, request.Revision)
	if err != nil {
		http.Error(w, "SAML unavailable", http.StatusServiceUnavailable)
		return
	}
	result, err := service.store.Database().Exec(r.Context(), `INSERT INTO authentication_requests
		(id,protocol,client_id,saml_service_provider_id,saml_request_id,data,expires_at)
		VALUES($1,'saml','',$2,$3,'{}',$4) ON CONFLICT (saml_service_provider_id,saml_request_id) DO NOTHING`,
		request.ID, sp.ID, txn.RequestID, service.now().Add(10*time.Minute))
	if err != nil {
		service.samlEvent(r, request, "saml.request", "failed", "backendUnavailable")
		http.Error(w, "SAML unavailable", http.StatusServiceUnavailable)
		return
	}
	if result.RowsAffected() != 1 {
		service.samlEvent(r, request, "saml.request.reuse", "detected", "")
		http.Error(w, "SAML request already used", http.StatusBadRequest)
		return
	}
	// A losing first visit must not overwrite the winning browser binding.
	if newBrowser {
		service.cookie(w, "browser", browser, sessionIdleLifetime)
	}
	service.samlEvent(r, request, "saml.request", "succeeded", "")
	if status != "" {
		if err := service.finishSAML(w, r, request, status); err != nil {
			http.Error(w, "SAML request could not complete", 400)
		}
		return
	}
	http.Redirect(w, r, requestLoginURL(request), http.StatusSeeOther)
}

func (service *Service) finishSAML(w http.ResponseWriter, r *http.Request, request *authorizationRequest, status string) error {
	if service.saml == nil || request.SAML == nil {
		return identity.ErrIneligible
	}
	r = samlprovider.WithNonce(r)
	authenticated := status == ""
	var observation *identity.DingTalkDirectoryObservation
	var observationErr error
	if status == "" {
		observation, observationErr = service.storage.observeDirectory(r.Context(), &request.grant)
	}
	var body []byte
	var acs string
	replayed := false
	commitReady := false
	err := pgx.BeginFunc(r.Context(), service.store.Database(), func(tx pgx.Tx) error {
		// Session-before-request is also used by OIDC issuance and logout.
		now := service.now()
		auth := samlprovider.Authentication{}
		if status == "" {
			var verifiedData []byte
			var absoluteExpiry time.Time
			if err := tx.QueryRow(r.Context(), "SELECT verification,expires_at,absolute_expires_at FROM authentication_sessions WHERE id=$1 AND revoked_at IS NULL AND expires_at>$2 AND absolute_expires_at>$2 FOR UPDATE", request.SessionID, now).Scan(&verifiedData, &auth.ExpiresAt, &absoluteExpiry); err != nil {
				return accountVerificationError(err)
			}
			var verification identity.Verification
			if json.Unmarshal(verifiedData, &verification) != nil || verification.Factor.ID != request.FactorID || !verification.AuthenticatedAt.Equal(request.AuthTime) {
				return identity.ErrIneligible
			}
			auth.ExpiresAt = minimum(minimum(auth.ExpiresAt, absoluteExpiry), request.AbsoluteExpiry)
			auth.AuthenticatedAt, auth.SessionID = request.AuthTime, request.SessionID
		}
		var revision int64
		var consumed *time.Time
		var requestExpiry time.Time
		if err := tx.QueryRow(r.Context(), "SELECT revision,consumed_at,expires_at FROM authentication_requests WHERE id=$1 AND protocol='saml' AND expires_at>$2 FOR UPDATE", request.ID, now).Scan(&revision, &consumed, &requestExpiry); err != nil {
			return accountVerificationError(err)
		}
		if consumed != nil {
			replayed = true
			return identity.ErrConflict
		}
		if revision != request.Revision {
			return identity.ErrConflict
		}
		sp, err := identity.LockSAMLServiceProvider(r.Context(), tx, request.SAML.ServiceProviderID)
		if err != nil {
			return err
		}
		if !sp.Enabled || sp.Retired || sp.Revision != request.SAML.Revision {
			return identity.ErrIneligible
		}
		acs = sp.ACSURL
		if status == "" {
			if request.OrganizationID != sp.OrganizationID || request.MemberID == "" {
				return identity.ErrIneligible
			}
			if observationErr != nil {
				return observationErr
			}
			if observation != nil {
				if err := observation.Validate(r.Context(), tx); err != nil {
					return err
				}
			}
			binding, err := identity.LockSAMLMemberEvidence(r.Context(), tx, sp, request.MemberID, request.FactorID)
			if err != nil {
				return err
			}
			if request.BindingID != "" && binding != request.BindingID {
				return identity.ErrIneligible
			}
			request.BindingID = binding
			auth.NameID, err = identity.SAMLNameID(r.Context(), tx, sp, request.MemberID, request.SAML.AllowCreate)
			if errors.Is(err, identity.ErrNotFound) {
				status = "InvalidNameIDPolicy"
			} else if err != nil {
				return err
			}
			if err := tx.QueryRow(r.Context(), "SELECT display_name FROM members WHERE id=$1", request.MemberID).Scan(&auth.DisplayName); err != nil {
				return err
			}
			if slices.Contains(sp.Attributes, "Email") {
				auth.Email, err = identity.SAMLMemberEmail(r.Context(), tx, sp.OrganizationID, request.MemberID)
				if err != nil {
					return err
				}
			}
		}
		// External observations and row-lock waits must not freeze the validity
		// window. Recheck locked state against the signing time, including errors.
		now = service.now()
		if !requestExpiry.After(now) || authenticated && !auth.ExpiresAt.After(now) {
			return identity.ErrIneligible
		}
		body, err = service.saml.Response(r, request.SAML, sp, auth, status, now)
		if err != nil {
			return err
		}
		_, err = tx.Exec(r.Context(), "UPDATE authentication_requests SET consumed_at=$2,revision=revision+1,data=CASE WHEN data='{}'::jsonb THEN data ELSE jsonb_set(data,'{complete}','true'::jsonb) END WHERE id=$1", request.ID, now)
		commitReady = err == nil
		return err
	})
	if err != nil {
		if replayed {
			service.samlEvent(r, request, "saml.request.reuse", "detected", "")
		} else {
			event := samlEventContext(r, request)
			event.Type = "saml.assertion.issue"
			// Keep identity denials distinct from provider/backend failures. Use
			// the shared commit classifier without translating through OIDC errors.
			event = operationResult(event, err, commitReady)
			if errors.Is(err, identity.ErrConflict) {
				event.Outcome, event.ReasonCode = "rejected", "ineligible"
			} else if errors.Is(err, identity.ErrProviderUnavailable) {
				event.ReasonCode = "providerUnavailable"
			}
			service.events.Offer(event)
		}
		return err
	}
	request.Complete = true
	if status == "" {
		service.samlEvent(r, request, "saml.assertion.issue", "succeeded", "")
	} else {
		service.samlEvent(r, request, "saml.assertion.issue", "rejected", "invalidRequest")
	}
	samlprovider.Write(w, r, acs, body)
	return nil
}

func (service *Service) samlEvent(r *http.Request, request *authorizationRequest, kind, outcome, reason string) {
	event := samlEventContext(r, request)
	event.Type, event.Outcome, event.ReasonCode = kind, outcome, reason
	if kind == "saml.assertion.issue" && outcome == "succeeded" && event.MemberID != "" {
		event.Actor = authevent.Actor{Kind: "member", ID: event.MemberID}
	}
	service.events.Offer(event)
}

func samlEventContext(r *http.Request, request *authorizationRequest) authevent.Event {
	event := authevent.Event{Purpose: "login", RequestID: authevent.FromContext(r.Context()).RequestID}
	if request != nil {
		event.InteractionID = request.InteractionID
		event.ClientID = request.ClientID
		event.OrganizationID = request.OrganizationID
		if request.SAML != nil {
			event.OrganizationID = request.SAML.OrganizationID
		}
		event.MemberID = request.MemberID
		event.FactorID = request.FactorID
		event.BindingID = request.BindingID
		event.SessionID = request.SessionID
		event.Method = request.Method
		if request.Verification != nil && (request.FactorType == "dingtalk" || request.FactorType == "feishu") {
			event.ProviderID = request.Verification.Factor.Namespace
		}
	}
	return event
}
