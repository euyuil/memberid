package authorization

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestActionPatternsAndRead(t *testing.T) {
	for _, test := range []struct {
		pattern string
		allow   []string
		deny    []string
	}{
		{"update", []string{"update"}, []string{"status.update", "Update"}},
		{"status.update", []string{"status.update"}, []string{"update", "settings.update"}},
		{"*.update", []string{"status.update", "settings.update"}, []string{"update", "security.credentials.update"}},
		{"**.update", []string{"update", "status.update", "security.credentials.update"}, []string{"create", "get"}},
		{"*", []string{"create", "get", "update", "delete"}, []string{"status.update"}},
		{"**", []string{"get", "status.update", "security.credentials.update"}, nil},
		{"read", []string{"list", "get"}, []string{"settings.get", "update"}},
		{"settings.read", []string{"settings.list", "settings.get"}, []string{"get", "list", "settings.update"}},
		{"*.read", []string{"settings.list", "status.get"}, []string{"list", "security.credentials.get"}},
		{"**.read", []string{"get", "settings.list", "security.credentials.get"}, []string{"update", "status.update"}},
	} {
		t.Run(test.pattern, func(t *testing.T) {
			permissions := []Permission{{Scope: Scope{Pattern: "organizations/org_example"}, Actions: []string{test.pattern}}}
			for _, action := range test.allow {
				if err := Check(permissions, Requirement{"organizations/org_example", action}); err != nil {
					t.Errorf("allow %s: %v", action, err)
				}
			}
			for _, action := range test.deny {
				if err := Check(permissions, Requirement{"organizations/org_example", action}); !errors.Is(err, ErrDenied) {
					t.Errorf("deny %s: %v", action, err)
				}
			}
		})
	}
}

func TestScopePatternsAndCollectionBoundaries(t *testing.T) {
	for _, test := range []struct {
		pattern string
		allow   []string
		deny    []string
	}{
		{"organizations/*", []string{"organizations/org_a"}, []string{"organizations", "organizations/org_a/members"}},
		{"organizations/**", []string{"organizations", "organizations/org_a", "organizations/org_a/members/member_a"}, []string{"memberDirectory"}},
		{"organizations/*/roleAssignments/*", []string{"organizations/org_a/roleAssignments/assignment_a"}, []string{"organizations/org_a/roleAssignments", "organizations/org_a/roleAssignments/assignment_a/details"}},
		{"organizations/org_a/**/roleAssignments", []string{"organizations/org_a/roleAssignments", "organizations/org_a/members/member_a/roleAssignments"}, []string{"organizations/org_b/roleAssignments", "organizations/org_a/roleAssignments/assignment_a"}},
		{"*", []string{"organizations"}, []string{"organizations/org_a"}},
		{"**", []string{"organizations", "organizations/org_a", "memberDirectory"}, nil},
	} {
		t.Run(test.pattern, func(t *testing.T) {
			permissions := []Permission{{Scope: Scope{Pattern: test.pattern}, Actions: []string{"read"}}}
			for _, target := range test.allow {
				if err := Check(permissions, Requirement{target, "get"}); err != nil {
					t.Errorf("allow %s: %v", target, err)
				}
			}
			for _, target := range test.deny {
				if err := Check(permissions, Requirement{target, "get"}); !errors.Is(err, ErrDenied) {
					t.Errorf("deny %s: %v", target, err)
				}
			}
		})
	}
	collection := []Permission{{Scope: Scope{"organizations/org_a/members"}, Actions: []string{"create", "read"}}}
	if err := Check(collection, Requirement{"organizations/org_a/members", "list"}); err != nil {
		t.Fatal(err)
	}
	if err := Check(collection, Requirement{"organizations/org_a/members/member_a", "get"}); !errors.Is(err, ErrDenied) {
		t.Fatal("collection read granted instance retrieval", err)
	}
}

func TestAllRequirementsAndPermissionPairing(t *testing.T) {
	permissions := []Permission{
		{Scope: Scope{"organizations/org_a"}, Actions: []string{"update", "list"}},
		{Scope: Scope{"organizations/org_b"}, Actions: []string{"status.update", "get"}},
	}
	if err := Check(permissions, Requirement{"organizations/org_a", "status.update"}); !errors.Is(err, ErrDenied) {
		t.Fatal("borrowed action from another scope", err)
	}
	if err := Check(permissions, Requirement{"organizations/org_a", "get"}); !errors.Is(err, ErrDenied) {
		t.Fatal("combined list/get across scopes", err)
	}
	if err := Check(permissions, Requirement{"organizations/org_a", "update"}, Requirement{"organizations/org_a", "status.update"}); !errors.Is(err, ErrDenied) {
		t.Fatal("partially allowed combined request", err)
	}
	permissions = append(permissions, Permission{Scope: Scope{"organizations/org_a"}, Actions: []string{"status.update"}})
	if err := Check(permissions, Requirement{"organizations/org_a", "update"}, Requirement{"organizations/org_a", "status.update"}); err != nil {
		t.Fatal("separate applicable permissions must satisfy both pairs", err)
	}
}

func TestInvalidDescriptionsNeverGrantAccess(t *testing.T) {
	for _, pattern := range []string{"", "/organizations", "organizations/", "organizations//members", "org_*", "**/**", "organizations/**/members/**", "org?", "[org]", "(org)", "org|members", "org\\members", "org\x00", " org"} {
		if err := Check([]Permission{{Scope: Scope{pattern}, Actions: []string{"**"}}}, Requirement{"organizations", "list"}); !errors.Is(err, ErrInvalid) {
			t.Errorf("scope %q: %v", pattern, err)
		}
	}
	for _, action := range []string{"", ".update", "status.", "status..update", "status/update", "re*", "status*", "**.**", "get|update", "get\n"} {
		if err := Check([]Permission{{Scope: Scope{"**"}, Actions: []string{action}}}, Requirement{"organizations", "list"}); !errors.Is(err, ErrInvalid) {
			t.Errorf("action %q: %v", action, err)
		}
	}
	for _, encoded := range []string{`{}`, `{"scope":null,"actions":["**"]}`, `{"scope":{"pattern":"**"},"actions":[]}`} {
		var permission Permission
		if err := json.Unmarshal([]byte(encoded), &permission); err != nil {
			t.Fatal(err)
		}
		if err := Check([]Permission{permission}, Requirement{"organizations", "list"}); !errors.Is(err, ErrInvalid) {
			t.Errorf("incomplete permission %s: %v", encoded, err)
		}
	}
	full := []Permission{{Scope: Scope{"**"}, Actions: []string{"**"}}}
	for _, requirement := range []Requirement{{"", "get"}, {"organizations/*", "get"}, {"organizations", "*"}, {"organizations", "read"}, {"organizations", "status..update"}} {
		if err := Check(full, requirement); !errors.Is(err, ErrInvalid) {
			t.Errorf("invalid requirement %+v: %v", requirement, err)
		}
	}
	if err := Check(full); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty operation granted access", err)
	}
	if err := Check(nil, Requirement{"organizations", "list"}); !errors.Is(err, ErrDenied) {
		t.Fatal("empty authority granted access", err)
	}
}
