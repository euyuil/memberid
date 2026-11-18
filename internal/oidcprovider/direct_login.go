package oidcprovider

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/euyuil/memberid/internal/browserauth"
	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
)

func (service *Service) createDirectLogin(r *http.Request, organizationID string) (*authorizationRequest, error) {
	if organizationID != "" {
		organization, err := service.store.Organization(r.Context(), organizationID)
		if err != nil || organization.Status != "enabled" {
			return nil, identity.ErrIneligible
		}
	}
	browser, _ := r.Context().Value(browserKey{}).(string)
	request := &authorizationRequest{
		grant: grant{ID: newID(), InteractionID: newID()},
		Interaction: browserauth.Interaction{
			Revision: 1, BrowserHash: config.SecretHash(browser), CSRF: config.RandomSecret(), ProviderOrganizationID: organizationID,
		},
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	_, err = service.store.Database().Exec(r.Context(), "INSERT INTO authentication_requests(id,client_id,data,expires_at) VALUES($1,$2,$3,$4)", request.ID, request.ClientID, data, service.now().Add(10*time.Minute))
	return request, err
}

func (service *Service) finishDirectLogin(w http.ResponseWriter, r *http.Request, request *authorizationRequest) error {
	if request.MemberID == "" {
		return identity.ErrIneligible
	}
	request.Complete = true
	if err := service.storage.saveRequest(r.Context(), request); err != nil {
		return err
	}
	http.Redirect(w, r, "/account?memberId="+url.QueryEscape(request.MemberID), http.StatusSeeOther)
	return nil
}
