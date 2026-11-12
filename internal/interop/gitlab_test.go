//go:build interop

package interop

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

const gitlabImage = "gitlab/gitlab-ce:19.5.5-ce.0@sha256:5f97f753bb3b990271c26670aa3f49fe5adf9c752ea783bf4b2c86d76b27ba4d"
const postgresImage = "postgres:18.6@sha256:bd5dfa494a5a259704365813dbfa5fa6b3e69be7348d43b547f540c730478583"
const issuer = "https://127.0.0.1:18080"
const gitlabOrigin = "http://127.0.0.1:18111"

// This opt-in check runs the distributed executable and an unmodified GitLab.
// Only the external SMS transport is simulated, in a separate test process.
func TestGitLab(t *testing.T) {
	packageDirectory := os.Getenv("MEMBERID_INTEROP_PACKAGE")
	if packageDirectory == "" {
		t.Skip("set MEMBERID_INTEROP_PACKAGE to an absolute Linux distribution directory")
	}
	if !filepath.IsAbs(packageDirectory) {
		t.Fatal("MEMBERID_INTEROP_PACKAGE must be absolute")
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		data, err := os.ReadFile(filepath.Join(root, "go.mod"))
		if err == nil && strings.HasPrefix(string(data), "module github.com/euyuil/memberid\n") {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("run the interoperability check inside the MemberID checkout")
		}
		root = parent
	}
	build, err := os.ReadFile(filepath.Join(packageDirectory, "BUILDINFO"))
	if err != nil || !strings.Contains(string(build), "goos=linux\n") || !strings.Contains(string(build), "goarch=amd64\n") || !strings.Contains(string(build), "cgo=0\n") {
		t.Fatal("a complete Linux amd64 distribution is required")
	}
	binary, err := os.ReadFile(filepath.Join(packageDirectory, "memberid"))
	if err != nil {
		t.Fatal("packaged executable unavailable")
	}
	digest := sha256.Sum256(binary)
	checksums, err := os.ReadFile(filepath.Join(packageDirectory, "SHA256SUMS"))
	if err != nil || !strings.Contains(string(checksums), hex.EncodeToString(digest[:])+"  ./memberid\n") {
		t.Fatal("packaged executable checksum mismatch")
	}
	owner := randomHex()
	local := filepath.Join(root, ".local")
	if err := os.MkdirAll(local, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(local, "gitlab-interop-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "owner"), []byte(owner), 0600); err != nil {
		t.Fatal(err)
	}
	f := &gitlabFixture{t: t, directory: directory, owner: owner, image: "memberid-interop:" + owner, database: "memberid-interop-db-" + owner, volume: "memberid-interop-config-" + owner}
	t.Cleanup(func() { f.cleanup(local) })
	fixtureBinary := os.Getenv("MEMBERID_INTEROP_FIXTURE")
	if fixtureBinary == "" {
		fixtureBinary = filepath.Join(directory, "fixture-linux")
		command := exec.CommandContext(t.Context(), "go", "test", "-c", "-tags=interop", "-trimpath", "-buildvcs=false", "-o", fixtureBinary, "./internal/interop")
		command.Dir = root
		command.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
		if output, err := command.CombinedOutput(); err != nil {
			_ = os.WriteFile(filepath.Join(directory, "build-error.log"), output, 0600)
			t.Fatal("fixture compilation failed; inspect the local build-error.log")
		}
	}
	if !filepath.IsAbs(fixtureBinary) {
		t.Fatal("fixture executable path must be absolute")
	}
	createFixtureCertificate(t, directory, "sms")
	createFixtureCertificate(t, directory, "issuer")
	f.docker("build", "--tag", f.image, packageDirectory)
	f.imageID = strings.TrimSpace(f.docker("image", "inspect", "--format", "{{.Id}}", f.image))
	f.docker("volume", "create", "--label", f.label(), f.volume)
	f.volumeCreated = true
	fixtureMount := "type=bind,source=" + fixtureBinary + ",target=/fixture,readonly"
	configurationMount := "type=volume,source=" + f.volume + ",target=/configuration"
	f.docker("run", "--rm", "--network", "none", "--user", "0:0", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--label", f.label(), "--entrypoint", "/fixture", "--mount", fixtureMount, "--mount", configurationMount, "--env", "MEMBERID_INTEROP_HELPER=prepare", f.image, "-test.run=^TestFixture$")
	f.start(f.database, "--tmpfs", "/var/lib/postgresql", "--publish", "127.0.0.1:18080:18080", "--publish", "127.0.0.1:18111:18111", "--env", "POSTGRES_HOST_AUTH_METHOD=trust", postgresImage)
	f.wait("PostgreSQL", time.Minute, func() bool {
		_, err := f.tryDocker("exec", f.database, "pg_isready", "--username", "postgres", "--quiet")
		return err == nil
	})
	configuration := []string{"--mount", configurationMount}
	f.operator(nil, "database", "init")
	f.operator(configuration, "config", "init", "--directory", "/configuration/installation", "--issuer", issuer, "--allow-loopback-http")
	client := object(t, f.operator(configuration, "client", "add", "--directory", "/configuration/installation", "--id", "gitlab", "--redirect", gitlabOrigin+"/users/auth/openid_connect/callback"))
	organization := object(t, f.operator(nil, "organization", "create", "--name", "Example organization"))
	member := object(t, f.operator(nil, "member", "create", "--organization", organization["id"].(string), "--name", "Example member"))
	f.organizationID, f.memberID = organization["id"].(string), member["id"].(string)
	fixtureUser := "0:0"
	if runtime.GOOS != "windows" {
		fixtureUser = fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	}
	f.start("memberid-interop-sms-"+owner, "--network", "container:"+f.database, "--read-only", "--cap-drop", "ALL", "--user", fixtureUser, "--entrypoint", "/fixture", "--mount", fixtureMount, "--mount", "type=bind,source="+directory+",target=/fixture-data", "--env", "MEMBERID_INTEROP_HELPER=sms", f.image, "-test.run=^TestFixture$", "-test.timeout=45m")
	f.wait("SMS fixture", time.Minute, func() bool { _, err := os.Stat(filepath.Join(directory, "sms-ready")); return err == nil })
	f.start("memberid-interop-login-"+owner, "--network", "container:"+f.database, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", configurationMount+",readonly", "--mount", "type=bind,source="+filepath.Join(directory, "sms.pem")+",target=/etc/memberid-ca.pem,readonly", "--env", "MEMBERID_DATABASE_URL="+f.databaseURL(), "--env", "MEMBERID_PHONE_ENABLED=true", "--env", "MEMBERID_SMS_ACCESS_KEY_ID=synthetic-access", "--env", "MEMBERID_SMS_ACCESS_KEY_SECRET="+randomHex(), "--env", "MEMBERID_SMS_SIGN_NAME=synthetic-sign", "--env", "MEMBERID_SMS_TEMPLATE_CODE=synthetic-template", "--env", "HTTPS_PROXY=http://127.0.0.1:18081", "--env", "SSL_CERT_FILE=/etc/memberid-ca.pem", f.image, "serve", "--directory", "/configuration/installation", "--listen", "0.0.0.0:18082")
	f.start("memberid-interop-edge-"+owner, "--network", "container:"+f.database, "--read-only", "--cap-drop", "ALL", "--user", fixtureUser, "--entrypoint", "/fixture", "--mount", fixtureMount, "--mount", "type=bind,source="+directory+",target=/fixture-data,readonly", "--env", "MEMBERID_INTEROP_HELPER=edge", f.image, "-test.run=^TestFixture$", "-test.timeout=45m")
	f.waitHTTP(issuer+"/.well-known/openid-configuration", "memberid-interop-edge-"+owner)
	provider := []any{map[string]any{"name": "openid_connect", "label": "MemberID", "args": map[string]any{"name": "openid_connect", "scope": []string{"openid", "profile"}, "response_type": "code", "issuer": issuer, "discovery": true, "client_auth_method": "basic", "uid_field": "sub", "pkce": true, "client_options": map[string]any{"identifier": "gitlab", "secret": client["client_secret"], "redirect_uri": gitlabOrigin + "/users/auth/openid_connect/callback"}}}}
	if err := writeFixtureJSON(filepath.Join(directory, "provider.json"), provider); err != nil {
		t.Fatal(err)
	}
	configurationText := `external_url 'http://127.0.0.1:18111'
postgresql['port'] = 5433
prometheus_monitoring['enable'] = false
puma['worker_processes'] = 0
sidekiq['concurrency'] = 5
gitlab_rails['gitlab_signup_enabled'] = false
gitlab_rails['omniauth_enabled'] = true
gitlab_rails['omniauth_allow_single_sign_on'] = ['openid_connect']
gitlab_rails['omniauth_providers'] = JSON.parse(File.read('/interop/provider.json'))
`
	if err := os.WriteFile(filepath.Join(directory, "gitlab.rb"), []byte(configurationText), 0600); err != nil {
		t.Fatal(err)
	}
	gitlab := "memberid-interop-gitlab-" + owner
	f.create(gitlab, "--network", "container:"+f.database, "--memory", "6g", "--cpus", "3", "--shm-size", "256m", "--mount", "type=bind,source="+directory+",target=/interop,readonly", "--env", `GITLAB_OMNIBUS_CONFIG=from_file '/interop/gitlab.rb'`, "--env", "GITLAB_ROOT_PASSWORD="+randomHex(), gitlabImage)
	trustDirectory := filepath.Join(directory, "trusted-certs")
	if err := os.Mkdir(trustDirectory, 0755); err != nil {
		t.Fatal(err)
	}
	certificate, err := os.ReadFile(filepath.Join(directory, "issuer.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trustDirectory, "memberid-fixture.crt"), certificate, 0644); err != nil {
		t.Fatal(err)
	}
	// GitLab moves imported certificates during reconfiguration; give its own
	// writable configuration volume a copy, not a read-only bind mount.
	f.docker("cp", trustDirectory, gitlab+":/etc/gitlab/")
	f.docker("start", gitlab)
	// The monitoring endpoint has an IP allowlist; the sign-in page is also
	// reachable from the host browser through the loopback port mapping.
	f.waitHTTP(gitlabOrigin+"/users/sign_in", gitlab)
	seed := `result = Users::CreateService.new(User.find_by_username('root'), { username: 'memberid-test', name: 'MemberID Test', email: 'memberid-test@example.invalid', password: SecureRandom.hex(24), skip_confirmation: true, organization_id: Organizations::Organization.default_organization.id }).execute
raise result.message unless result.success?
user = result.payload[:user]
Identity.create!(user: user, provider: 'openid_connect', extern_uid: JSON.parse(File.read('/interop/member.json')).fetch('memberId'))
puts 'Synthetic GitLab account linked'
`
	if err := writeFixtureJSON(filepath.Join(directory, "member.json"), map[string]string{"memberId": f.memberID}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(directory, "member.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "seed.rb"), []byte(seed), 0644); err != nil {
		t.Fatal(err)
	}
	f.docker("exec", gitlab, "gitlab-rails", "runner", "/interop/seed.rb")
	f.login()
	t.Log("Unmodified GitLab CE 19.5.5 established its linked account session through the packaged MemberID provider.")
	if os.Getenv("MEMBERID_INTEROP_HOLD") == "true" {
		if err := writeFixtureJSON(filepath.Join(directory, "manual-ready.json"), map[string]string{"issuer": issuer, "gitlab": gitlabOrigin, "phone": "19900000001"}); err != nil {
			t.Fatal(err)
		}
		t.Log("Manual browser check ready in .local/" + filepath.Base(directory) + "; create manual.done after inspection.")
		f.wait("manual browser inspection", 20*time.Minute, func() bool { _, err := os.Stat(filepath.Join(directory, "manual.done")); return err == nil })
	}
}

type gitlabFixture struct {
	t                                                  *testing.T
	directory, owner, image, imageID, database, volume string
	organizationID, memberID                           string
	containers                                         []string
	volumeCreated                                      bool
}

func randomHex() string {
	value := make([]byte, 16)
	_, _ = rand.Read(value)
	return hex.EncodeToString(value)
}
func (f *gitlabFixture) label() string { return "memberid.interop=" + f.owner }
func (f *gitlabFixture) databaseURL() string {
	return "postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable"
}
func (f *gitlabFixture) tryDocker(args ...string) (string, error) {
	command := exec.CommandContext(f.t.Context(), "docker", args...)
	output, err := command.CombinedOutput()
	return string(output), err
}
func (f *gitlabFixture) docker(args ...string) string {
	f.t.Helper()
	output, err := f.tryDocker(args...)
	if err != nil {
		_ = os.WriteFile(filepath.Join(f.directory, "docker-error.log"), []byte(output), 0600)
		f.t.Fatalf("Docker %s failed; inspect the owned local docker-error.log", args[0])
	}
	return output
}
func (f *gitlabFixture) start(name string, args ...string) {
	f.create(name, args...)
	f.docker("start", name)
}
func (f *gitlabFixture) create(name string, args ...string) {
	f.containers = append(f.containers, name)
	f.docker(append([]string{"create", "--name", name, "--label", f.label()}, args...)...)
}
func (f *gitlabFixture) operator(options []string, args ...string) string {
	command := []string{"run", "--rm", "--label", f.label(), "--network", "container:" + f.database, "--env", "MEMBERID_DATABASE_URL=" + f.databaseURL()}
	command = append(command, options...)
	command = append(command, f.image)
	return f.docker(append(command, args...)...)
}
func object(t *testing.T, text string) map[string]any {
	t.Helper()
	var result map[string]any
	if json.Unmarshal([]byte(text), &result) != nil {
		t.Fatal("expected JSON from fixture operator command")
	}
	return result
}
func (f *gitlabFixture) wait(name string, timeout time.Duration, ready func() bool) {
	f.t.Helper()
	deadline, nextMessage := time.Now().Add(timeout), time.Now()
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		if time.Now().After(nextMessage) {
			f.t.Log("Waiting for " + name)
			nextMessage = time.Now().Add(30 * time.Second)
		}
		select {
		case <-f.t.Context().Done():
			f.t.Fatal("fixture wait canceled")
		case <-time.After(time.Second):
		}
	}
	f.t.Fatal(name + " timed out")
}
func (f *gitlabFixture) transport() *http.Transport {
	f.t.Helper()
	pem, err := os.ReadFile(filepath.Join(f.directory, "issuer.pem"))
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(pem) {
		f.t.Fatal("fixture issuer CA unavailable")
	}
	return &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
}
func (f *gitlabFixture) waitHTTP(address, container string) {
	client := &http.Client{Timeout: 5 * time.Second, Transport: f.transport()}
	f.wait("HTTP readiness", 15*time.Minute, func() bool {
		if strings.TrimSpace(f.docker("inspect", "--format", "{{.State.Running}}", container)) != "true" {
			output, _ := f.tryDocker("logs", "--tail", "100", container)
			_ = os.WriteFile(filepath.Join(f.directory, "startup-error.log"), []byte(output), 0600)
			f.t.Fatal("fixture container stopped before readiness; inspect local startup-error.log")
		}
		response, err := client.Get(address)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == 200
	})
}
func (f *gitlabFixture) cleanup(local string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := func(args ...string) string {
		output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil && !f.t.Failed() {
			f.t.Errorf("owned fixture cleanup command failed: %s", args[0])
		}
		return strings.TrimSpace(string(output))
	}
	for _, name := range slices.Backward(f.containers) {
		if command("inspect", "--format", `{{ index .Config.Labels "memberid.interop" }}`, name) == f.owner {
			command("rm", "--force", "--volumes", name)
		} else if !f.t.Failed() {
			f.t.Error("container cleanup ownership check failed")
		}
	}
	if f.volumeCreated {
		if command("volume", "inspect", "--format", `{{ index .Labels "memberid.interop" }}`, f.volume) == f.owner {
			command("volume", "rm", f.volume)
		} else if !f.t.Failed() {
			f.t.Error("volume cleanup ownership check failed")
		}
	}
	if f.imageID != "" {
		if command("image", "inspect", "--format", "{{.Id}}", f.image) == f.imageID {
			command("image", "rm", f.image)
		} else if !f.t.Failed() {
			f.t.Error("image cleanup ownership check failed")
		}
	}
	if f.t.Failed() {
		f.t.Log("Local fixture diagnostics retained in .local/" + filepath.Base(f.directory))
		return
	}
	absolute, err := filepath.EvalSymlinks(f.directory)
	local, localErr := filepath.EvalSymlinks(local)
	relative, relativeErr := filepath.Rel(local, absolute)
	marker, markerErr := os.ReadFile(filepath.Join(absolute, "owner"))
	if err == nil && localErr == nil && relativeErr == nil && relative != "." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, "..") && strings.HasPrefix(filepath.Base(absolute), "gitlab-interop-") && markerErr == nil && string(marker) == f.owner {
		if err := os.RemoveAll(absolute); err != nil {
			f.t.Error("owned fixture directory cleanup failed")
		}
	} else {
		f.t.Error("fixture cleanup ownership check failed")
	}
}
