package management

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStrictJSON(t *testing.T) {
	for _, input := range []string{`{"name":"a","name":"b"}`, `{"Name":"a"}`, `{"name":null}`, `{"unknown":"a"}`, `{"name":false}`, `[]`, `{} {}`, `{"name":"` + strings.Repeat("a", 33<<10) + `"}`} {
		t.Run(input[:min(len(input), 30)], func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(input))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			request.Body = http.MaxBytesReader(response, request.Body, 32<<10)
			var value struct {
				Name string `json:"name"`
			}
			if decode(response, request, &value) || response.Code != http.StatusBadRequest {
				t.Fatalf("accepted invalid JSON: status %d", response.Code)
			}
		})
	}
	request := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(`{"manualBlocked":false}`))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	var value struct {
		ManualBlocked *bool `json:"manualBlocked"`
	}
	if !decode(httptest.NewRecorder(), request, &value) || value.ManualBlocked == nil || *value.ManualBlocked {
		t.Fatal("explicit false was not retained")
	}
}
