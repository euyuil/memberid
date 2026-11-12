# Member account linking

MemberID hosts a self-service page for linking a freshly verified DingTalk identity to an existing Member. It uses MemberID's own browser session and current binding eligibility. It needs no application-specific roles, management API credential, or special identity-evidence scope. This is account functionality, not an alternative login, token, or refresh protocol.

## Open the page

Enable the optional DingTalk login adapter, configure the organization's application, and register `<issuer>/account/dingtalk/callback` as an exact DingTalk callback in addition to the ordinary login callback. The application needs the same corporation and directory permissions as [DingTalk login](dingtalk.md).

After authenticating through a registered OIDC application, navigate to:

```text
<issuer>/account/link/dingtalk?memberId=<member-id>
```

The selected Member must already be eligible through the browser session's verified factor. MemberID checks the explicit binding and displays the organization's name and identifier and the Member's name and identifier before starting verification. A caller-supplied Member identifier never establishes ownership. No session or an ineligible Member produces a generic error without exposing another Member's details.

To return to a relying party, register a separate exact account destination with `memberid client add --account-return <url>` (or the corresponding client configuration), then supply both `client_id` and `returnUri`. URL-encode their values:

```text
<issuer>/account/link/dingtalk?memberId=<member-id>&client_id=<client-id>&returnUri=<encoded-account-url>
```

The client must use the Member subject profile and allow that organization. Only `accountReturnUris` authorizes the destination: OIDC callbacks, logout destinations, prefixes, and arbitrary URLs are not accepted. Supplying only a return URL is invalid. Both parameters may be omitted for a MemberID-only page with no external return link. The page does not redirect automatically after linking; the user can inspect the result and follow the registered return link. It transports no access token, provider token, authentication proof, or new login session to that destination.

## Verification and lifetime

Linking requires a MemberID session authenticated within the preceding five minutes, both when starting and when committing the binding. An older session can view the page but must authenticate again through a registered application before linking. An RP can request fresh authentication through standard OIDC `prompt=login` or `max_age`; a Refresh Token does not reset `auth_time` or satisfy this requirement. The five-minute rule is MemberID account policy, not an OIDC requirement.

The page keeps the organization, Member, link button, cancel button, and feedback area in stable positions. A fresh form is bound to the browser, session, selected Member, original binding, client, and return destination. Same-origin form submissions require its CSRF value. The upstream attempt uses random, hashed state and expires with the form after five minutes. Reopening the same pending flow preserves its cancellation action. Starting a newer flow for the same session and Member cancels older forms and attempts.

The callback requires the same browser and current MemberID session. State is consumed atomically before contacting DingTalk; replay, concurrent callbacks, wrong browsers, canceled attempts, expired forms, and failed responses cannot reuse it. A failed verification can be canceled and restarted. The provider must freshly establish the configured corporation and consistent internal-employee identifiers. The result uses the same organization, application, directory-event, and authorization revision checks as login admission.

After provider I/O, one transaction rechecks the session, request, current factor and binding, organization, Member eligibility, and current client return policy before applying the link. Session revocation, source-factor disablement, binding revocation, departure, manual block, cancellation, or a changed provider configuration prevents an in-flight link from committing. Partial failure leaves no new factor, binding, or admitted identity.

## Identity and session effects

The Member's identifier and locally managed display name remain unchanged. The same provider person may link to separate Members in different organizations; those bindings use independent provider namespaces. Matching contacts or names never merge identities. A provider identity already bound to another Member in the organization is a conflict. Self-service cannot replace an occupied factor slot, restore a revoked binding, remove a factor, or transfer one between Members. Operators handle those administrative decisions through the separate management interface.

Successful linking adds verified DingTalk evidence to the selected Member. It does not change the source session, create an OIDC grant, reset authentication time, extend deadlines, or replace the current browser cookie. Existing grants retain their original factor provenance and limits; subsequent eligibility checks observe the new binding and directory evidence. A later standard DingTalk login resolves to the same Member subject in that organization. The result page offers the registered return link, or tells the user they can close the page when no client destination was supplied.

The fresh-install schema is version 12. Existing databases are rejected without automatic migration or reset. Account requests become eligible for cleanup after five minutes. The running authentication process removes them during normal expiry cleanup; removing an expired session also removes its account requests. No upstream authorization code or provider token is stored in these requests.

## Validation boundary

Automated HTTP and disposable-PostgreSQL tests cover real forms and callbacks, CSRF, browser and session binding, exact return validation, fresh authentication, cancellation, concurrent replay, failed upstream verification, eligibility changes during provider I/O, binding conflicts, distinct organizations, stable OIDC subjects, and original session/grant preservation. Browser layout inspection uses synthetic rendered states. These checks simulate DingTalk and do not establish real upstream authorization or live GitLab acceptance.
