package oidcprovider

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/euyuil/memberid/internal/identity"
)

func (service *Service) startPhone(r *http.Request, binding, phone, clientID string) (identity.PhoneChallenge, error) {
	address, err := phoneSourceAddress(r, service.configuration.PhoneTrustedProxyCIDRs)
	if err != nil {
		return identity.PhoneChallenge{}, err
	}
	return service.phone.Start(r.Context(), binding, phone, identity.PhoneSendSource{
		BrowserID: accountBrowser(r), ClientID: clientID, Address: address,
	})
}

// Trust forwarded addresses only through explicitly configured proxy hops.
// Stop at the first untrusted hop so a client-supplied prefix cannot choose its quota.
func phoneSourceAddress(r *http.Request, trustedCIDRs []string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, identity.ErrInvalid
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, identity.ErrInvalid
	}
	trusted := func(address netip.Addr) bool {
		for _, value := range trustedCIDRs {
			prefix, err := netip.ParsePrefix(value)
			if err == nil && prefix.Contains(address.Unmap()) {
				return true
			}
		}
		return false
	}
	forwarded := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	if forwarded == "" || !trusted(address) {
		return address.Unmap(), nil
	}
	if len(forwarded) > 4096 {
		return netip.Addr{}, identity.ErrInvalid
	}
	hops := strings.Split(forwarded, ",")
	for i := len(hops) - 1; i >= 0 && trusted(address); i-- {
		address, err = netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil || address.Zone() != "" {
			return netip.Addr{}, identity.ErrInvalid
		}
	}
	return address.Unmap(), nil
}
