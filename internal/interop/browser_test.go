//go:build interop

package interop

import (
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type browserReply struct {
	status                  int
	location, address, body string
}

func (f *gitlabFixture) login() {
	jar, err := cookiejar.New(nil)
	if err != nil {
		f.t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Transport: f.transport(), Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(address string, form url.Values) browserReply {
		f.t.Helper()
		parsed, err := url.Parse(address)
		if err != nil || parsed.Scheme+"://"+parsed.Host != issuer && parsed.Scheme+"://"+parsed.Host != gitlabOrigin {
			f.t.Fatal("browser fixture refused an unexpected destination")
		}
		method := http.MethodGet
		var input io.Reader
		if form != nil {
			method, input = http.MethodPost, strings.NewReader(form.Encode())
		}
		r, err := http.NewRequestWithContext(f.t.Context(), method, address, input)
		if err != nil {
			f.t.Fatal("browser fixture request creation failed")
		}
		if form != nil {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
			r.Header.Set("Referer", parsed.Scheme+"://"+parsed.Host+"/")
		}
		response, err := client.Do(r)
		if err != nil {
			f.t.Fatal("browser fixture request failed at " + parsed.Path)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		if err != nil {
			f.t.Fatal("browser fixture could not read " + parsed.Path)
		}
		if err := os.WriteFile(filepath.Join(f.directory, "browser-last.html"), data, 0600); err != nil {
			f.t.Fatal("browser fixture diagnostics could not be retained")
		}
		f.t.Logf("%s %s: %d", method, parsed.Path, response.StatusCode)
		return browserReply{response.StatusCode, response.Header.Get("Location"), address, string(data)}
	}
	if result := request(gitlabOrigin+"/api/v4/user", nil); result.status != 401 {
		f.t.Fatal("GitLab unexpectedly authenticated an empty browser")
	}
	page := request(gitlabOrigin+"/users/sign_in", nil)
	if page.status != 200 || !strings.Contains(page.body, "MemberID") {
		f.t.Fatal("GitLab MemberID login button unavailable")
	}
	csrf := matchField(f.t, page.body, `<meta name="csrf-token" content="([^"]+)"`)
	response := request(gitlabOrigin+"/users/auth/openid_connect", url.Values{"authenticity_token": {csrf}})
	verified, callback, pkce := false, false, false
	for range 24 {
		if response.status == 302 || response.status == 303 {
			current, _ := url.Parse(response.address)
			next, err := current.Parse(response.location)
			if err != nil {
				f.t.Fatal("invalid browser redirect")
			}
			if next.Scheme+"://"+next.Host == issuer && next.Path == "/oauth/authorize" {
				query := next.Query()
				if query.Get("client_id") != "gitlab" || query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" || len(query.Get("code_challenge")) != 43 || query.Get("state") == "" || query.Get("nonce") == "" {
					f.t.Fatal("GitLab did not request the standard bound PKCE code flow")
				}
				pkce = true
			}
			if next.Scheme+"://"+next.Host == gitlabOrigin && next.Path == "/users/auth/openid_connect/callback" {
				callback = true
			}
			response = request(next.String(), nil)
			continue
		}
		if strings.HasPrefix(response.address, issuer+"/login") {
			if response.status != 200 {
				f.t.Fatal("MemberID login page failed")
			}
			form := url.Values{"request": {hiddenField(f.t, response.body, "request")}, "csrf": {hiddenField(f.t, response.body, "csrf")}}
			if !verified {
				form.Set("action", "send")
				form.Set("phone", "19900000001")
				response = request(issuer+"/login", form)
				if response.status != 200 || !strings.Contains(response.body, "Verification code requested") {
					f.t.Fatal("packaged SMS request did not complete")
				}
				var code string
				f.wait("synthetic SMS", 15*time.Second, func() bool {
					data, err := os.ReadFile(filepath.Join(f.directory, "sms.json"))
					if err != nil {
						return false
					}
					value := object(f.t, string(data))
					code, _ = value["code"].(string)
					return len(code) == 6
				})
				form = url.Values{"request": {hiddenField(f.t, response.body, "request")}, "csrf": {hiddenField(f.t, response.body, "csrf")}, "action": {"verify"}, "code": {code}}
				response = request(issuer+"/login", form)
				if response.status != 200 || !strings.Contains(response.body, "No eligible Member identity is available") {
					f.t.Fatal("verified phone did not reach explicit Member enrollment")
				}
				factor := object(f.t, f.operator(nil, "factor", "inspect", "--phone", "19900000001"))
				f.operator(nil, "member", "bind-factor", "--organization", f.organizationID, "--member", f.memberID, "--factor", factor["id"].(string))
				verified = true
				response = request(issuer+"/login?request="+url.QueryEscape(form.Get("request")), nil)
				continue
			}
			form.Set("action", "continue")
			form.Set("member", f.memberID)
			form.Set("consent", "yes")
			response = request(issuer+"/login", form)
			continue
		}
		break
	}
	if !verified || !pkce || !callback {
		f.t.Fatal("GitLab code flow did not complete all expected stages")
	}
	current := request(gitlabOrigin+"/api/v4/user", nil)
	if current.status != 200 {
		f.t.Fatal("GitLab did not establish its own authenticated session")
	}
	user := object(f.t, current.body)
	if user["username"] != "memberid-test" {
		f.t.Fatal("GitLab authenticated the wrong account")
	}
}
func hiddenField(t *testing.T, page, name string) string {
	t.Helper()
	return matchField(t, page, `name="`+regexp.QuoteMeta(name)+`" value="([^"]+)"`)
}
func matchField(t *testing.T, page, expression string) string {
	t.Helper()
	values := regexp.MustCompile(expression).FindStringSubmatch(page)
	if len(values) != 2 {
		t.Fatal("expected browser form field unavailable")
	}
	return html.UnescapeString(values[1])
}
