//go:build integration

package oidcprovider

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/identity"
)

// TestConsoleBrowserFixture is an opt-in, disposable manual inspection fixture.
// It uses the same HTTP provider and synthetic SMS sender as the integration tests.
// No test sender, code disclosure, or fixture route is compiled into MemberID.
func TestConsoleBrowserFixture(t *testing.T) {
	file := os.Getenv("MEMBERID_CONSOLE_BROWSER_FILE")
	if file == "" {
		t.Skip("set MEMBERID_CONSOLE_BROWSER_FILE to a private new status-file path")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("status file must not exist")
	}
	f := newFixture(t)
	m, err := f.store.CreateMember(t.Context(), identity.SystemOrganizationID, "", "演示平台管理员")
	if err != nil {
		t.Fatal(err)
	}
	factor, err := f.store.EnsureFactor(t.Context(), "phone", "phone:e164", "+8619900000001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.BindFactor(t.Context(), m.OrganizationID, m.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	for _, member := range []identity.Member{m, f.member} {
		if err = f.store.SetAdministrator(t.Context(), identity.ManagementActor{}, member.OrganizationID, member.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	server := consoleFixture(t, f)
	t.Cleanup(func() { _ = os.Remove(file); _ = os.Remove(file + ".stop") })
	t.Log("Disposable console available; inspect the private status file. Create its .stop sibling to finish.")
	deadline := time.NewTimer(20 * time.Minute)
	defer deadline.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		value, _ := json.Marshal(map[string]string{"url": server.URL, "phone": "19900000001", "code": f.sender.latest()})
		if err := os.WriteFile(file, value, 0600); err != nil {
			t.Fatal(err)
		}
		select {
		case <-deadline.C:
			t.Fatal("browser inspection timed out")
		case <-t.Context().Done():
			return
		case <-tick.C:
			if _, err := os.Stat(file + ".stop"); err == nil {
				return
			}
		}
	}
}
