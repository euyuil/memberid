package oidcprovider

import (
	"net/http/httptest"
	"testing"
)

func TestPhoneSourceAddress(t *testing.T) {
	for _, test := range []struct {
		name, peer, forwarded, want string
		trusted                     []string
	}{
		{"direct", "192.0.2.1:1234", "", "192.0.2.1", nil},
		{"untrusted spoof", "192.0.2.1:1234", "198.51.100.1", "192.0.2.1", []string{"10.0.0.0/24"}},
		{"trusted proxy", "10.0.0.1:1234", "192.0.2.1", "192.0.2.1", []string{"10.0.0.0/24"}},
		{"client prefix", "10.0.0.1:1234", "198.51.100.1, 192.0.2.1", "192.0.2.1", []string{"10.0.0.0/24"}},
		{"multiple proxies", "10.0.0.1:1234", "198.51.100.1, 192.0.2.1, 10.0.0.2", "192.0.2.1", []string{"10.0.0.0/24"}},
		{"missing header", "10.0.0.1:1234", "", "10.0.0.1", []string{"10.0.0.0/24"}},
		{"IPv6", "[2001:db8::1]:1234", "", "2001:db8::1", nil},
		{"mapped proxy", "[::ffff:10.0.0.1]:1234", "::ffff:192.0.2.1", "192.0.2.1", []string{"10.0.0.0/24"}},
		{"IPv6 proxy", "[2001:db8::1]:1234", "192.0.2.1", "192.0.2.1", []string{"2001:db8::/64"}},
		{"malformed header", "10.0.0.1:1234", "not-an-address", "", []string{"10.0.0.0/24"}},
		{"empty hop", "10.0.0.1:1234", "192.0.2.1, ", "", []string{"10.0.0.0/24"}},
		{"scoped address", "10.0.0.1:1234", "fe80::1%eth0", "", []string{"10.0.0.0/24"}},
		{"invalid peer", "unknown", "192.0.2.1", "", []string{"10.0.0.0/24"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/login", nil)
			r.RemoteAddr = test.peer
			r.Header.Set("X-Forwarded-For", test.forwarded)
			address, err := phoneSourceAddress(r, test.trusted)
			if test.want == "" {
				if err == nil {
					t.Fatal("accepted malformed address")
				}
			} else if err != nil || address.String() != test.want {
				t.Fatal("incorrect source", address, err)
			}
		})
	}
}
