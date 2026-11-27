package oidcprovider

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/zhizhun-tech/memberid/internal/authevent"
	"github.com/zhizhun-tech/memberid/internal/identity"
)

func (service *Service) startPhone(r *http.Request, binding, phone, clientID string, event authevent.Event) (identity.PhoneChallenge, error) {
	address, err := phoneSourceAddress(r, service.configuration.PhoneTrustedProxyCIDRs)
	if err != nil {
		service.rejectPhoneSend(r, event)
		return identity.PhoneChallenge{}, err
	}
	return service.phone.Start(authevent.WithContext(r.Context(), event), binding, phone, identity.PhoneSendSource{
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

func (service *Service) rejectPhoneSend(r *http.Request, event authevent.Event) {
	event.RequestID = authevent.FromContext(r.Context()).RequestID
	event.Type, event.Method, event.Outcome, event.ReasonCode = "sms.send", "sms", "rejected", "invalidRequest"
	service.events.Offer(event)
}

func (service *Service) loginEvent(ctx context.Context, request *authorizationRequest) authevent.Event {
	// Only an operator-registered organization restriction owns this shared phone
	// workflow. A phone number or an arbitrary organization hint establishes none.
	event := authevent.Event{InteractionID: request.InteractionID, ClientID: request.ClientID, ClientName: request.ClientName, Purpose: "login"}
	if request.SAML != nil {
		event.OrganizationID = request.ProviderOrganizationID
		return event
	}
	if registered, err := service.storage.client(ctx, request.ClientID); err == nil {
		event.OrganizationID = registered.registration.OrganizationID
		if event.ClientName == "" {
			event.ClientName = registered.displayName
		}
	}
	return event
}
func accountEvent(request accountRequest, session accountSession) authevent.Event {
	return authevent.Event{InteractionID: request.InteractionID, OrganizationID: request.OrganizationID, MemberID: request.MemberID, ClientID: request.ClientID, FactorID: session.verified.Factor.ID, SessionID: session.id, BindingID: request.BindingID, Actor: authevent.Actor{Kind: "member", ID: request.MemberID}, Purpose: "accountLinking"}
}
