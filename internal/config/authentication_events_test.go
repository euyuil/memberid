package config

import (
	"testing"
	"time"
)

func TestAuthenticationEventRetention(t *testing.T) {
	if (Installation{}).AuthenticationEventRetention() != 90*24*time.Hour {
		t.Fatal("default retention")
	}
	if (Installation{AuthenticationEventRetentionDays: 7}).AuthenticationEventRetention() != 7*24*time.Hour {
		t.Fatal("configured retention")
	}
	installation := Installation{Issuer: "https://login.example.invalid", SigningKeyFile: "signing-key.pem", PublicKeysFile: "public-keys.json", SecretsFile: "secrets.json", ClientsFile: "clients.json"}
	if err := installation.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, days := range []int{-1, 36501} {
		installation.AuthenticationEventRetentionDays = days
		if installation.Validate() == nil {
			t.Fatal("invalid retention accepted")
		}
	}
}
