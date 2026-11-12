package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthAndUnknownRoutes(t *testing.T) {
	httpServer := httptest.NewServer(New().Handler)
	defer httpServer.Close()
	for _, test := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodHead, "/healthz", http.StatusOK},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{http.MethodGet, "/.well-known/openid-configuration", http.StatusNotFound},
		{http.MethodGet, "/unknown", http.StatusNotFound},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			request, err := http.NewRequest(test.method, httpServer.URL+test.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := httpServer.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != test.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.status)
			}
			if test.method == http.MethodGet && test.path == "/healthz" {
				if string(body) != "{\"status\":\"ok\"}\n" || response.Header.Get("Cache-Control") != "no-store" {
					t.Fatalf("unexpected health response: %s", body)
				}
			}
		})
	}
}
