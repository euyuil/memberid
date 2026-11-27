package management

import (
	"net/http"

	"github.com/zhizhun-tech/memberid/internal/identity"
)

func (h *Handler) samlRoutes() {
	const collection = "/v1/organizations/{organizationId}/saml-service-providers"
	const item = collection + "/{serviceProviderId}"
	h.routes.HandleFunc("GET "+collection, func(w http.ResponseWriter, r *http.Request) {
		after, limit, ok := pageRequest(w, r)
		if !ok {
			return
		}
		value, err := h.store.OrganizationSAMLServiceProviders(r.Context(), r.PathValue("organizationId"), after, limit)
		respond(w, http.StatusOK, value, err)
	})
	h.routes.HandleFunc("GET "+item, func(w http.ResponseWriter, r *http.Request) {
		value, err := h.store.OrganizationSAMLServiceProvider(r.Context(), r.PathValue("organizationId"), r.PathValue("serviceProviderId"))
		respond(w, http.StatusOK, value, err)
	})
	configure := func(w http.ResponseWriter, r *http.Request) {
		input, ok := DecodeSAMLRegistration(w, r)
		if !ok {
			return
		}
		value, err := h.store.PutSAMLServiceProvider(r.Context(), identity.InstallationManagerPrincipal(), input.Registration(r.PathValue("organizationId")), false)
		status := http.StatusOK
		if r.Method == http.MethodPost {
			status = http.StatusCreated
		}
		respond(w, status, value, err)
	}
	h.routes.HandleFunc("POST "+collection, configure)
	h.routes.HandleFunc("PUT "+item, configure)
	h.routes.HandleFunc("POST "+item+"/retire", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Revision int64 `json:"revision"`
		}
		if !decode(w, r, &input) {
			return
		}
		value, err := h.store.RetireSAMLServiceProvider(r.Context(), identity.InstallationManagerPrincipal(), r.PathValue("organizationId"), r.PathValue("serviceProviderId"), input.Revision)
		respond(w, http.StatusOK, value, err)
	})
}

// DecodeSAMLRegistration shares the exact request shape between the private
// integration API and console. Callers provide their own authenticated principal.
func DecodeSAMLRegistration(w http.ResponseWriter, r *http.Request) (identity.SAMLServiceProviderInput, bool) {
	var input identity.SAMLServiceProviderInput
	if !decode(w, r, &input) {
		return input, false
	}
	if r.Method == http.MethodPost && input.Revision != 0 || r.Method == http.MethodPut && (input.ID != r.PathValue("serviceProviderId") || input.Revision <= 0) {
		problem(w, http.StatusBadRequest, "invalid_request")
		return input, false
	}
	return input, true
}

// DecodePageRequest provides the same bounded, duplicate-free cursor contract
// to console directories that share a private management collection.
func DecodePageRequest(w http.ResponseWriter, r *http.Request) (string, int, bool) {
	return pageRequest(w, r)
}
