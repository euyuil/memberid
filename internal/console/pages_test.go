package console

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
)

func TestConsolePageRequests(t *testing.T) {
	routes := http.NewServeMux()
	for _, path := range []string{"/api/session", "/auth/login", "/auth/callback"} {
		routes.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
	}
	registerPages(routes, fstest.MapFS{
		"index.html":    {Data: []byte("<html>Console</html>")},
		"assets/app.js": {Data: []byte("console.log('asset')")},
	})
	for _, path := range []string{
		"/", "/organizations", "/members?q=Alice&status=active", "/providers", "/events?before=42",
		"/organizations/org_example", "/organizations/org_example/members?after=mbr_cursor",
		"/organizations/org_example/members/mbr_example", "/organizations/org_example/providers",
		"/organizations/org_system/events?memberId=mbr_example",
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(method+" "+path, func(t *testing.T) {
				response := httptest.NewRecorder()
				routes.ServeHTTP(response, httptest.NewRequest(method, path, nil))
				if response.Code != 200 || response.Header().Get("Content-Type") != "text/html; charset=utf-8" {
					t.Fatalf("page response: %d %v", response.Code, response.Header())
				}
				want := "<html>Console</html>"
				if method == http.MethodHead {
					want = ""
				}
				if response.Body.String() != want {
					t.Fatal("unexpected page body", response.Body.String())
				}
			})
		}
	}
	for path, status := range map[string]int{
		"/missing": 404, "/members/id": 404, "/organizations/org_example/providers/id": 404,
		"/organizations/org_example/events/id": 404, "/organizations/org_example/members/id/extra": 404,
		"/organizations/%2Fexample": 404, "/api/missing": 404, "/auth/missing": 404,
		"/assets/missing.js": 404, "/index.html": 404, "/.gitkeep": 404,
		"/api/session": 401, "/auth/login": 401, "/auth/callback": 401, "/assets/app.js": 200,
	} {
		response := httptest.NewRecorder()
		routes.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != status || strings.Contains(response.Body.String(), "<html>Console</html>") {
			t.Errorf("%s: status %d, body %q", path, response.Code, response.Body.String())
		}
	}
	response := httptest.NewRecorder()
	routes.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/members", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatal("page accepted POST", response.Code)
	}
}

func TestLoginReturnTargets(t *testing.T) {
	for _, value := range []string{"/", "/members?q=%E5%A7%93%E5%90%8D+%26+Alice&after=mbr_cursor", "/organizations/org_example/members/mbr_example", "/organizations/org_example/events?memberId=mbr_example&before=42"} {
		if !validReturnTo(value) {
			t.Errorf("rejected local page: %q", value)
		}
	}
	for _, value := range []string{
		"", "https://example.invalid/members", "//example.invalid/members", `\\example.invalid`, `/\example.invalid`,
		"/%2f%2fexample.invalid", "/%5cexample.invalid", "/%6dembers", "/members/../auth/login", "/members/",
		"/auth/login", "/auth/callback", "/api/members", "/assets/app.js", "/unknown",
		"/members#fragment", "/members#", "/members?q=%ZZ", "/members?q=a;b", "/members?\r\nLocation: https://example.invalid",
		"/members?q=" + strings.Repeat("a", 4096),
	} {
		if validReturnTo(value) {
			t.Errorf("accepted invalid return target: %q", value)
		}
	}
}

func TestLoginFailurePreservesPageAndFilters(t *testing.T) {
	response := httptest.NewRecorder()
	loginFailure(response, httptest.NewRequest(http.MethodGet, "/auth/callback", nil), "/members?q=Alice%26Bob&after=mbr_cursor", "login_failed")
	target, err := url.Parse(response.Header().Get("Location"))
	if err != nil || response.Code != 303 || target.Path != "/members" || target.Query().Get("q") != "Alice&Bob" || target.Query().Get("after") != "mbr_cursor" || target.Query().Get("error") != "login_failed" {
		t.Fatal("failure lost return target", response.Header())
	}
}
