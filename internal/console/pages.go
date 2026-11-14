package console

import (
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var pagePath = regexp.MustCompile(`^/(organizations(/[A-Za-z0-9_-]+(/(members(/[A-Za-z0-9_-]+)?|providers|events))?)?|members|providers|events)?$`)

// Only page routes receive the application entry point. API, authentication,
// missing assets, and unknown paths retain their own HTTP responses.
func registerPages(routes *http.ServeMux, static fs.FS) {
	routes.Handle("GET /assets/", http.FileServer(http.FS(static)))
	routes.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawPath != "" || !pagePath.MatchString(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		index, err := fs.ReadFile(static, "index.html")
		if err != nil {
			http.Error(w, "console assets unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(index)
		}
	})
}

// A return target is a local, canonical console page, never an arbitrary URL
// or a protocol/API endpoint. It is stored with the single-use login state.
func validReturnTo(value string) bool {
	if len(value) > 4096 || strings.ContainsAny(value, "\\#\r\n\t") || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.RawPath != "" || !pagePath.MatchString(u.Path) {
		return false
	}
	_, err = url.ParseQuery(u.RawQuery)
	return err == nil
}

func loginFailure(w http.ResponseWriter, r *http.Request, returnTo, code string) {
	u, _ := url.Parse(returnTo)
	query := u.Query()
	query.Set("error", code)
	u.RawQuery = query.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}
