//go:build integration

package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	base, _ := startManagementProcess(t, directory)
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

func startManagementProcess(t *testing.T, directory string) (string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	output := make(listeningOutput, 1)
	finished := make(chan error, 1)
	go func() {
		finished <- run(ctx, []string{"serve-management", "--directory", directory, "--listen", "127.0.0.1:0"}, output, io.Discard)
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
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
	}
	t.Cleanup(stop)
	var base string
	select {
	case line := <-output:
		base = "http://" + strings.TrimSpace(strings.TrimPrefix(line, "MemberID listening on "))
	case <-time.After(10 * time.Second):
		t.Fatal("management did not start")
	}
	return base, stop
}

func TestManagementCredentialRotationRequiresRestart(t *testing.T) {
	databaseURL := testdb.Create(t)
	if err := identity.Initialize(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEMBERID_DATABASE_URL", databaseURL)
	directory := filepath.Join(t.TempDir(), "installation")
	if err := config.Initialize(directory, "https://login.example.invalid", false); err != nil {
		t.Fatal(err)
	}
	oldCredential, err := os.ReadFile(filepath.Join(directory, "management-secret"))
	if err != nil {
		t.Fatal(err)
	}
	base, stop := startManagementProcess(t, directory)
	assertStatus := func(address string, credential []byte, expected int) {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), "GET", address+"/healthz", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(credential)))
		client := &http.Client{Timeout: 5 * time.Second}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != expected {
			t.Fatalf("management authentication returned %d, expected %d", response.StatusCode, expected)
		}
	}
	assertStatus(base, oldCredential, 200)
	outputFile := filepath.Join(directory, "next-credential")
	var output bytes.Buffer
	if err := run(t.Context(), []string{"config", "rotate-management-secret", "--directory", directory, "--output-file", outputFile}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	newCredential, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(base, oldCredential, 200)
	assertStatus(base, newCredential, 401)
	stop()
	restarted, _ := startManagementProcess(t, directory)
	assertStatus(restarted, oldCredential, 401)
	assertStatus(restarted, newCredential, 200)
}
