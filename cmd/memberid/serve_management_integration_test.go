//go:build integration

package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/testdb"
)

type listeningOutput chan string

func (output listeningOutput) Write(data []byte) (int, error) {
	output <- string(data)
	return len(data), nil
}

func TestManagementStartsWithoutProvidersOrClients(t *testing.T) {
	databaseURL := testdb.Create(t)
	if err := identity.Initialize(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEMBERID_DATABASE_URL", databaseURL)
	t.Setenv("MEMBERID_PHONE_ENABLED", "false")
	directory := filepath.Join(t.TempDir(), "installation")
	if err := config.Initialize(directory, "https://login.example.invalid", false); err != nil {
		t.Fatal(err)
	}
	credential, err := os.ReadFile(filepath.Join(directory, "management-secret"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	output := make(listeningOutput, 1)
	finished := make(chan error, 1)
	go func() {
		finished <- run(ctx, []string{"serve-management", "--directory", directory, "--listen", "127.0.0.1:0"}, output, io.Discard)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(15 * time.Second):
			t.Error("management did not stop")
		}
	})
	var base string
	select {
	case line := <-output:
		base = "http://" + strings.TrimSpace(strings.TrimPrefix(line, "MemberID listening on "))
	case <-time.After(10 * time.Second):
		t.Fatal("management did not start")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, path := range []string{"/healthz", "/v1/organizations", "/.well-known/openid-configuration"} {
		request, _ := http.NewRequest("GET", base+path, nil)
		request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(credential)))
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		expected := 200
		if strings.HasPrefix(path, "/.well-known/") {
			expected = 404
		}
		if response.StatusCode != expected {
			t.Fatalf("%s: status %d", path, response.StatusCode)
		}
	}
}
