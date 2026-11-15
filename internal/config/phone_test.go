package config

import (
	"testing"

	"github.com/euyuil/memberid/internal/identity"
)

func TestPhoneSendConfiguration(t *testing.T) {
	base := Installation{Issuer: "https://auth.example.invalid", SigningKeyFile: "key.pem", PublicKeysFile: "public.pem", SecretsFile: "secrets.json", ClientsFile: "clients.json"}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	defaults, err := base.PhoneSendLimitsPerHour.WithDefaults()
	if err != nil || defaults != (identity.PhoneSendLimits{Transaction: 6, Browser: 12, Source: 60, Client: 300, Installation: 1000}) {
		t.Fatal("invalid default budgets", defaults, err)
	}
	base.PhoneSendLimitsPerHour.Browser = 2
	limits, err := base.PhoneSendLimitsPerHour.WithDefaults()
	if err != nil || limits.Browser != 2 || limits.Source != defaults.Source {
		t.Fatal("partial overrides lost defaults")
	}
	for _, field := range []*int{&base.PhoneSendLimitsPerHour.Transaction, &base.PhoneSendLimitsPerHour.Browser, &base.PhoneSendLimitsPerHour.Source, &base.PhoneSendLimitsPerHour.Client, &base.PhoneSendLimitsPerHour.Installation} {
		*field = -1
		if base.Validate() == nil {
			t.Fatal("accepted negative budget")
		}
		*field = 0
	}
	for _, cidr := range []string{"invalid", "192.0.2.1", "0.0.0.0/0", "::/0", "::ffff:192.0.2.0/120"} {
		base.PhoneTrustedProxyCIDRs = []string{cidr}
		if base.Validate() == nil {
			t.Fatal("accepted unsafe proxy range", cidr)
		}
	}
	base.PhoneTrustedProxyCIDRs = []string{"10.0.0.0/24", "2001:db8::/64"}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
}
