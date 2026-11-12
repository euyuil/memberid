// Package management exposes installation-wide operator access on a separate listener.
package management

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/euyuil/memberid/internal/identity"
)

type Handler struct {
	store    *identity.Store
	verifier []byte
	routes   *http.ServeMux
}

func New(store *identity.Store, secretSHA256 string, applications *identity.DingTalkApplications) (*Handler, error) {
	verifier, err := hex.DecodeString(secretSHA256)
	if err != nil || len(verifier) != sha256.Size || store == nil {
		return nil, errors.New("management requires a store and a credential verifier")
	}
	h := &Handler{store: store, verifier: verifier, routes: http.NewServeMux()}
	h.routes.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		respond(w, http.StatusOK, map[string]string{"status": "ok"}, nil)
	})
	h.routes.HandleFunc("POST /v1/organizations", h.createOrganization)
	h.routes.HandleFunc("POST /v1/organization-enrollments", h.enrollOrganization)
	h.routes.HandleFunc("GET /v1/organizations/{organizationId}/enrollment", func(w http.ResponseWriter, r *http.Request) {
		value, err := h.store.Enrollment(r.Context(), r.PathValue("organizationId"))
		respond(w, http.StatusOK, value, err)
	})
	h.routes.HandleFunc("GET /v1/organizations", h.organizations)
	h.routes.HandleFunc("GET /v1/organizations/{organizationId}", func(w http.ResponseWriter, r *http.Request) {
		value, err := h.store.Organization(r.Context(), r.PathValue("organizationId"))
		respond(w, http.StatusOK, value, err)
	})
	h.routes.HandleFunc("PATCH /v1/organizations/{organizationId}", h.updateOrganization)
	h.routes.HandleFunc("POST /v1/organizations/{organizationId}/members", h.createMember)
	h.routes.HandleFunc("GET /v1/organizations/{organizationId}/members", h.members)
	h.routes.HandleFunc("GET /v1/organizations/{organizationId}/members/{memberId}", func(w http.ResponseWriter, r *http.Request) {
		value, err := h.store.Member(r.Context(), r.PathValue("organizationId"), r.PathValue("memberId"))
		respond(w, http.StatusOK, value, err)
	})
	h.routes.HandleFunc("PATCH /v1/organizations/{organizationId}/members/{memberId}", h.updateMember)
	h.routes.HandleFunc("GET /v1/organizations/{organizationId}/members/{memberId}/bindings", func(w http.ResponseWriter, r *http.Request) {
		value, err := h.store.Bindings(r.Context(), r.PathValue("organizationId"), r.PathValue("memberId"))
		respond(w, http.StatusOK, map[string]any{"items": value}, err)
	})
	h.routes.HandleFunc("POST /v1/organizations/{organizationId}/members/{memberId}/bindings", h.bind)
	h.routes.HandleFunc("DELETE /v1/organizations/{organizationId}/members/{memberId}/bindings/{factorId}", func(w http.ResponseWriter, r *http.Request) {
		err := h.store.RevokeBinding(r.Context(), r.PathValue("organizationId"), r.PathValue("memberId"), r.PathValue("factorId"))
		respond(w, http.StatusNoContent, nil, err)
	})
	h.routes.HandleFunc("GET /v1/factors/{factorId}", func(w http.ResponseWriter, r *http.Request) {
		value, err := h.store.Factor(r.Context(), r.PathValue("factorId"))
		respond(w, http.StatusOK, value, err)
	})
	h.routes.HandleFunc("POST /v1/eligibility", h.eligibility)
	if applications != nil {
		h.dingTalkRoutes(applications)
	}
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	credentials := strings.Fields(r.Header.Get("Authorization"))
	if len(r.Header.Values("Authorization")) != 1 || len(credentials) != 2 || !strings.EqualFold(credentials[0], "Bearer") || !h.authenticate(credentials[1]) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="MemberID management"`)
		problem(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.Header.Get("Origin") != "" {
		problem(w, http.StatusForbidden, "browser_access_denied")
		return
	}
	if r.Method == http.MethodHead {
		problem(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		if r.Method != http.MethodGet || (r.URL.Path != "/v1/organizations" && !strings.HasSuffix(r.URL.Path, "/members")) {
			problem(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	response := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	h.routes.ServeHTTP(response, r)
	if r.Method != http.MethodGet {
		slog.Info("Management request", "principal", "installation-manager", "method", r.Method, "route", r.Pattern, "status", response.status)
	}
}

func (h *Handler) authenticate(secret string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != 32 {
		return false
	}
	digest := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(h.verifier, digest[:]) == 1
}

func respond(w http.ResponseWriter, status int, value any, err error) {
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrInvalid):
			problem(w, http.StatusBadRequest, "invalid_request")
		case errors.Is(err, identity.ErrNotFound):
			problem(w, http.StatusNotFound, "not_found")
		case errors.Is(err, identity.ErrMemberIDConflict):
			problem(w, http.StatusUnprocessableEntity, "member_id_conflict")
		case errors.Is(err, identity.ErrConflict):
			problem(w, http.StatusConflict, "conflict")
		case errors.Is(err, identity.ErrProviderUnavailable):
			problem(w, http.StatusServiceUnavailable, "provider_unavailable")
		case errors.Is(err, identity.ErrIneligible):
			problem(w, http.StatusForbidden, "ineligible")
		default:
			problem(w, http.StatusInternalServerError, "internal_error")
		}
		return
	}
	w.WriteHeader(status)
	if status != http.StatusNoContent {
		_ = json.NewEncoder(w).Encode(value)
	}
}

func problem(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

// Management requests are flat JSON objects with exact, unique field names.
func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		problem(w, http.StatusUnsupportedMediaType, "json_required")
		return false
	}
	decoder := json.NewDecoder(r.Body)
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		problem(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	fields := map[string]bool{}
	kind := reflect.TypeOf(target).Elem()
	for index := 0; index < kind.NumField(); index++ {
		fields[kind.Field(index).Tag.Get("json")] = true
	}
	values := map[string]json.RawMessage{}
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		var value json.RawMessage
		if err != nil || !ok || !fields[key] || values[key] != nil || decoder.Decode(&value) != nil || string(value) == "null" {
			problem(w, http.StatusBadRequest, "invalid_request")
			return false
		}
		values[key] = value
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || decoder.Decode(new(any)) != io.EOF {
		problem(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	data, err := json.Marshal(values)
	if err != nil || json.Unmarshal(data, target) != nil {
		problem(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func pageRequest(w http.ResponseWriter, r *http.Request) (string, int, bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_request")
		return "", 0, false
	}
	for key, values := range query {
		if (key != "after" && key != "limit") || len(values) != 1 || values[0] == "" {
			problem(w, http.StatusBadRequest, "invalid_request")
			return "", 0, false
		}
	}
	limit := 50
	if raw := query.Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			problem(w, http.StatusBadRequest, "invalid_request")
			return "", 0, false
		}
	}
	return query.Get("after"), limit, true
}

func (h *Handler) createOrganization(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if !decode(w, r, &input) {
		return
	}
	value, err := h.store.CreateOrganization(r.Context(), input.ID, input.Name)
	respond(w, http.StatusCreated, value, err)
}
func (h *Handler) updateOrganization(w http.ResponseWriter, r *http.Request) {
	var input identity.OrganizationChange
	if !decode(w, r, &input) {
		return
	}
	value, err := h.store.UpdateOrganization(r.Context(), r.PathValue("organizationId"), input)
	respond(w, http.StatusOK, value, err)
}
func (h *Handler) organizations(w http.ResponseWriter, r *http.Request) {
	after, limit, ok := pageRequest(w, r)
	if !ok {
		return
	}
	value, err := h.store.Organizations(r.Context(), after, limit)
	respond(w, http.StatusOK, value, err)
}
func (h *Handler) createMember(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
	}
	if !decode(w, r, &input) {
		return
	}
	value, err := h.store.CreateMember(r.Context(), r.PathValue("organizationId"), input.ID, input.DisplayName)
	respond(w, http.StatusCreated, value, err)
}
func (h *Handler) updateMember(w http.ResponseWriter, r *http.Request) {
	var input identity.MemberChange
	if !decode(w, r, &input) {
		return
	}
	value, err := h.store.UpdateMember(r.Context(), r.PathValue("organizationId"), r.PathValue("memberId"), input)
	respond(w, http.StatusOK, value, err)
}
func (h *Handler) members(w http.ResponseWriter, r *http.Request) {
	after, limit, ok := pageRequest(w, r)
	if !ok {
		return
	}
	value, err := h.store.Members(r.Context(), r.PathValue("organizationId"), after, limit)
	respond(w, http.StatusOK, value, err)
}
func (h *Handler) bind(w http.ResponseWriter, r *http.Request) {
	var input struct {
		FactorID string `json:"authenticationFactorId"`
	}
	if !decode(w, r, &input) {
		return
	}
	value, err := h.store.BindFactor(r.Context(), r.PathValue("organizationId"), r.PathValue("memberId"), input.FactorID)
	respond(w, http.StatusOK, value, err)
}
func (h *Handler) eligibility(w http.ResponseWriter, r *http.Request) {
	var input struct {
		OrganizationID string `json:"organizationId"`
		MemberID       string `json:"memberId"`
		FactorID       string `json:"authenticationFactorId"`
		FactorType     string `json:"authenticationFactorType"`
	}
	if !decode(w, r, &input) {
		return
	}
	value, err := h.store.Eligibility(r.Context(), input.OrganizationID, input.MemberID, input.FactorID, input.FactorType)
	respond(w, http.StatusOK, value, err)
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (h *Handler) enrollOrganization(w http.ResponseWriter, r *http.Request) {
	var input identity.OrganizationEnrollment
	if !decode(w, r, &input) {
		return
	}
	value, err := h.store.EnrollOrganization(r.Context(), input)
	respond(w, http.StatusOK, value, err)
}
