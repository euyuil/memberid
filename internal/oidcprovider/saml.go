package oidcprovider

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/euyuil/memberid/internal/authevent"
	"github.com/euyuil/memberid/internal/browserauth"
	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/samlprovider"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	request := &authorizationRequest{grant: grant{ID: newID(), InteractionID: newID(), ClientID: sp.ID}, Interaction: browserauth.Interaction{Revision: 1, BrowserHash: config.SecretHash(browser), CSRF: config.RandomSecret()}, SAML: txn}
	data, err := json.Marshal(request)
	if err != nil {
		http.Error(w, "SAML unavailable", 503)
		return
	}
	_, err = service.store.Database().Exec(r.Context(), `INSERT INTO authentication_requests(id,protocol,client_id,saml_service_provider_id,saml_request_id,data,expires_at) VALUES($1,'saml',$2,$2,$3,$4,$5)`, request.ID, sp.ID, txn.RequestID, data, service.now().Add(10*time.Minute))
	if err != nil {
		var conflict *pgconn.PgError
		if errors.As(err, &conflict) && conflict.Code == "23505" {
			service.samlEvent(r, request, "saml.request.reuse", "detected", "")
		} else {
			service.samlEvent(r, request, "saml.request", "failed", "backendUnavailable")
		}
		http.Error(w, "SAML request unavailable or already used", 400)
		return
	}
	service.samlEvent(r, request, "saml.request", "succeeded", "")
	if status != "" {
		if err := service.finishSAML(w, r, request, status); err != nil {
			http.Error(w, "SAML request could not complete", 400)
		}
		return
	}
	http.Redirect(w, r, "/login?request="+url.QueryEscape(request.ID), http.StatusSeeOther)
}

func (service *Service) finishSAML(w http.ResponseWriter, r *http.Request, request *authorizationRequest, status string) error {
	if service.saml == nil || request.SAML == nil {
		return identity.ErrIneligible
	}
	r = samlprovider.WithNonce(r)
	now := service.now()
	var observation *identity.DingTalkDirectoryObservation
	var observationErr error
	if status == "" {
		observation, observationErr = service.storage.observeDirectory(r.Context(), &request.grant)
	}
	var body []byte
	var acs string
	replayed := false
	err := pgx.BeginFunc(r.Context(), service.store.Database(), func(tx pgx.Tx) error {
		// Session-before-request is also used by OIDC issuance and logout.
		auth := samlprovider.Authentication{}
		if status == "" {
			var verifiedData []byte
			if err := tx.QueryRow(r.Context(), "SELECT verification,expires_at FROM authentication_sessions WHERE id=$1 AND revoked_at IS NULL AND expires_at>$2 AND absolute_expires_at>$2 FOR UPDATE", request.SessionID, now).Scan(&verifiedData, &auth.ExpiresAt); err != nil {
				return identity.ErrIneligible
			}
			var verification identity.Verification
			if json.Unmarshal(verifiedData, &verification) != nil || verification.Factor.ID != request.FactorID || !verification.AuthenticatedAt.Equal(request.AuthTime) {
				return identity.ErrIneligible
			}
			auth.ExpiresAt = minimum(auth.ExpiresAt, request.AbsoluteExpiry)
			auth.AuthenticatedAt, auth.SessionID = request.AuthTime, request.SessionID
		}
		var revision int64
		var consumed *time.Time
		if err := tx.QueryRow(r.Context(), "SELECT revision,consumed_at FROM authentication_requests WHERE id=$1 AND protocol='saml' AND expires_at>$2 FOR UPDATE", request.ID, now).Scan(&revision, &consumed); err != nil {
			return identity.ErrIneligible
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
			if err := service.storage.validateDirectory(r.Context(), tx, observation, observationErr); err != nil {
				return err
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
		}
		body, err = service.saml.Response(r, request.SAML, sp, auth, status, now)
		if err != nil {
			return err
		}
		_, err = tx.Exec(r.Context(), "UPDATE authentication_requests SET consumed_at=$2,revision=revision+1,data=jsonb_set(data,'{complete}','true'::jsonb) WHERE id=$1", request.ID, now)
		return err
	})
	if err != nil {
		if replayed {
			service.samlEvent(r, request, "saml.request.reuse", "detected", "")
		} else {
			service.samlEvent(r, request, "saml.assertion.issue", "rejected", "ineligible")
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
	event := authevent.Event{Type: kind, Outcome: outcome, ReasonCode: reason, Purpose: "login", RequestID: authevent.FromContext(r.Context()).RequestID}
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
	}
	service.events.Offer(event)
}
