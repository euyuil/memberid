//go:build integration

package oidcprovider

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestFeishuTopLevelBrowser(t *testing.T) {
	browser := os.Getenv("MEMBERID_TEST_BROWSER")
	if browser == "" {
		t.Skip("set MEMBERID_TEST_BROWSER to a Chromium executable")
	}
	for _, flow := range []string{"link", "signin"} {
		t.Run(flow, func(t *testing.T) {
			f, provider, _, _ := feishuAccountFixture(t)
			issuer, _ := url.Parse(f.server.URL)
			entry := f.server.URL + feishuAccountPath + "?memberId=" + f.member.ID
			verifier := ""
			if flow == "signin" {
				f.browser = browserClient()
				start, pkce := f.authorization("example-web", "openid", nil)
				f.status(start, 302)
				entry, verifier = start.header.Get("Location"), pkce
			}
			input, err := json.Marshal(map[string]any{"browser": browser, "profile": t.TempDir(), "issuer": f.server.URL, "entry": entry, "cookies": f.browser.Jar.Cookies(issuer), "flow": flow, "callback": callback})
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), "node", "testdata/feishu-browser.mjs")
			cmd.Stdin = bytes.NewReader(input)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			code, err := cmd.Output()
			if err != nil {
				t.Fatalf("browser failed: %v: %s", err, stderr.String())
			}
			if provider.calls.Load() != 1 {
				t.Fatal("unexpected upstream token exchanges")
			}
			if flow == "signin" {
				tokens := f.exchange("example-web", strings.TrimSpace(string(code)), verifier)
				f.status(tokens, 200)
				if f.signedClaims(jsonObject(t, tokens)["id_token"].(string))["sub"] == "" {
					t.Fatal("missing signed Member subject")
				}
			}
		})
	}
}
