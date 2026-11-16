package identity

import (
	"strings"
	"testing"
)

func TestLegacyNameIDInput(t *testing.T) {
	for _, value := range []string{"old-account-42", "旧系统账号", "literal<&>value", strings.Repeat("x", 256)} {
		if !validLegacyNameID(value) {
			t.Fatalf("rejected supported value %q", value)
		}
	}
	for _, value := range []string{"", " ", " leading", "trailing ", "a\nb", "a\x00b", "\xff", "\ufffe", "\uffff", strings.Repeat("x", 257)} {
		if validLegacyNameID(value) {
			t.Fatalf("accepted invalid value %q", value)
		}
	}
}
