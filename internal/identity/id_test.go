package identity

import (
	"strings"
	"testing"
)

func TestIdentifiers(t *testing.T) {
	seen := map[string]bool{}
	for _, kind := range []Kind{OrganizationKind, MemberKind, FactorKind} {
		for range 100 {
			id, err := NewID(kind)
			if err != nil || !ValidID(id, kind) || seen[id] {
				t.Fatalf("invalid or duplicate generated identifier: %q, %v", id, err)
			}
			seen[id] = true
			if ValidID(id, Kind("unknown")) {
				t.Fatal("accepted unknown identifier kind")
			}
			for _, bad := range []string{strings.ToUpper(id), id + "0", string(kind) + "_" + strings.Repeat("z", idWidth), string(kind) + "_" + strings.Repeat("0", idWidth)} {
				if ValidID(bad, kind) {
					t.Fatalf("accepted invalid identifier %q", bad)
				}
			}
		}
	}
	if _, err := NewID(Kind("unknown")); err != ErrInvalid {
		t.Fatal("accepted unknown generator kind")
	}
}

func TestNames(t *testing.T) {
	for _, test := range []struct {
		value string
		valid bool
	}{
		{"Example team", true}, {"示例组织", true}, {"", false}, {"  ", false}, {"line\nbreak", false}, {string([]byte{0xff}), false}, {strings.Repeat("a", 129), false},
	} {
		if validText(test.value, 128) != test.valid {
			t.Errorf("unexpected validity for %q", test.value)
		}
	}
}
