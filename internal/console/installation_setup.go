package console

import (
	"crypto/subtle"
	_ "embed"
	"errors"
	"html/template"
	"mime"
	"net/http"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
)

//go:embed installation_setup.html
var setupHTML string

//go:embed installation_setup.js
var setupJS string

var setupPage = template.Must(template.New("installation setup").Parse(setupHTML))

type setupPageData struct {
	OrganizationID, Username string
	Password, Confirmation   string
	Error                    string
	Completed                bool
}

func setupScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = w.Write([]byte(setupJS))
}

func (s *Service) redirectToSetup(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/" || r.URL.Query().Has("error") {
		return false
	}
	available, err := s.setupStore.SetupAvailable(r.Context())
	if err != nil {
		http.Error(w, "Installation status is unavailable", http.StatusServiceUnavailable)
		return true
	}
	if available {
		if _, err := s.session(r); err == nil {
			return false
		}
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
	}
	return available
}

func (s *Service) installationSetup(w http.ResponseWriter, r *http.Request) {
	// Same-origin form submissions must retain their Origin for setup validation.
	w.Header().Set("Referrer-Policy", "same-origin")
	available, err := s.setupStore.SetupAvailable(r.Context())
	if err != nil {
		http.Error(w, "Installation status is unavailable", http.StatusServiceUnavailable)
		return
	}
	if !available {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	data := setupPageData{OrganizationID: identity.SystemOrganizationID, Username: identity.RootUsername}
	if r.Method == http.MethodPost {
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/x-www-form-urlencoded" || r.Header.Get("Origin") != s.origin || r.ParseForm() != nil || r.URL.RawQuery != "" {
			http.Error(w, "Invalid setup submission", http.StatusForbidden)
			return
		}
		for _, values := range r.PostForm {
			if len(values) != 1 {
				http.Error(w, "Repeated setup parameter", http.StatusBadRequest)
				return
			}
		}
		switch r.PostForm.Get("action") {
		case "generate":
			data.Confirmation = config.RandomSecret()
			data.Password, err = s.setupStore.PrepareSetupPassword(r.Context(), r.PostForm.Get("code"), data.Confirmation)
			if err == nil {
				s.cookie(w, "setup", data.Confirmation, 900)
			}
		case "complete":
			confirmation := r.PostForm.Get("confirmation")
			if r.PostForm.Get("saved") != "yes" || len(confirmation) != 43 ||
				subtle.ConstantTimeCompare([]byte(confirmation), []byte(s.cookieValue(r, "setup"))) != 1 {
				err = identity.ErrSetupCredential
			} else {
				err = s.setupStore.CompleteSetup(r.Context(), confirmation)
			}
			if err == nil {
				s.cookie(w, "setup", "", -1)
				// The setup form is same-origin. A link on the resulting document
				// starts the separate navigation to the OIDC issuer.
				data.Completed = true
			}
		default:
			http.Error(w, "Invalid setup action", http.StatusBadRequest)
			return
		}
		if errors.Is(err, identity.ErrSetupCredential) {
			data.Error = "设置码或确认已失效。请在部署终端生成新的设置码。"
		} else if err != nil {
			http.Error(w, "Setup is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = setupPage.Execute(w, data)
}
