# Native SAML identity provider

MemberID implements a restricted, SP-initiated SAML 2.0 Web Browser SSO profile in the normal `memberid serve` executable. SAML is disabled by default. It shares the existing phone, password, DingTalk, Feishu, Member selection, consent, and browser session flows with OIDC. It does not create an internal OIDC client or exchange an intermediate login proof.

## Enable signing and register an SP

Use a fresh schema version 24 database. Existing demo databases are rejected; no upgrade migration or data reset is performed. Follow [operator setup](operations.md) to create the installation, organization, Member, and authentication source.

Provision a dedicated RSA private key of at least 2048 bits and its matching X.509 signing certificate in the protected installation directory. The certificate must be currently valid and permit digital signatures if it declares key usage. Use separate key material from TLS and OIDC. MemberID rejects an OIDC key found in its retained public key set. The SAML certificate is an explicitly distributed signing trust anchor; a publicly trusted TLS certificate is not required.

Add to `memberid.json`:

```json
"saml": {
  "enabled": true,
  "signingKeyFile": "saml-key.pem",
  "certificateFile": "saml-certificate.pem"
}
```

Paths must be local to the installation directory. Private-file protections match the existing signing-key loader. Missing, mismatched, expired, or not-yet-valid material prevents startup. Live metadata and issuance also check certificate usability. Configuration is loaded at startup; restart after changes. [SAML signing operations](saml-signing.md) provide expiry inspection, public certificate export, guarded manual activation, rollback, and a consistent backup/restore procedure. Certificate issuance, automatic renewal, and overlapping IdP-key publication are not implemented; SP trust updates and process restarts remain explicit operator responsibilities.

Register one organization-scoped SP using a JSON file:

```json
{
  "id": "example-sp",
  "displayName": "Example application",
  "entityId": "https://sp.example.test/metadata",
  "organizationId": "org_REPLACE_WITH_CREATED_ORGANIZATION",
  "acsUrl": "https://sp.example.test/saml/acs",
  "enabled": true,
  "allowUnsignedRequests": false,
  "signingCertificates": ["REPLACE_WITH_PEM_ENCODED_SP_SIGNING_CERTIFICATE"],
  "preauthorized": false,
  "attributes": [],
  "revision": 0
}
```

```sh
memberid saml sp apply --directory ./installation --file ./sp.json
memberid saml sp list --directory ./installation
memberid saml sp inspect --directory ./installation --id example-sp
memberid saml signing inspect --directory ./installation
memberid saml sp disable --directory ./installation --id example-sp --revision 1
```

Commands use `MEMBERID_DATABASE_URL` and the local operator authority. Registrations can also be managed through the [administration console](console.md#saml-applications) and [private management API](management-api.md#saml-service-provider-registration). Platform administrators can manage any organization; organization administrators can manage only their own organization's registrations. Ordinary Members and account self-service sessions have no registration authority. The private API's installation credential has installation-wide authority and is never sent to the browser.

All writes are audited and require the inspected current revision; zero creates a registration. Organization, registration ID, and entity ID are immutable. Display names are optional, nonblank text of at most 128 Unicode code points; an omitted name is displayed as the registration ID. `saml sp retire` permanently disables the registration; its entity ID and subject mappings remain reserved and cannot be reassigned. Update the inspected JSON and apply it for other policy changes. Use disable for a reversible interruption. A stale revision or retired registration returns a conflict; reload and inspect before making a new intentional change. After an uncertain response, inspect the current registration rather than automatically retrying a write.

Each registration has exactly one HTTPS POST ACS. No metadata fetching, wildcards, dynamic ACS selection, or indexed ACS is supported. The operator CLI's explicit loopback-development configuration permits `http://127.0.0.1` only; both HTTP management interfaces require HTTPS recipients. Redirect requests must be signed using RSA-SHA256 against one of up to four pinned SP certificates. SP certificates establish key trust rather than Web PKI trust; their dates are not used for request admission. `allowUnsignedRequests: true` is an explicit per-SP exception. A present but invalid signature is always rejected, including under that exception. Enveloped XML signatures are outside this Redirect-only input profile.

An enabled SAML installation can start without OIDC clients if it has at least one active SP. It still uses the standard installation secrets and OIDC key files. Disabled SAML exposes neither endpoint. Unknown or disabled SPs cannot start authentication.

## Protocol contract

| Surface | Implemented behavior |
| --- | --- |
| Entity ID and metadata | `{issuer}/saml/metadata`; GET/HEAD; independent signing certificate and persistent NameID format |
| SSO input | GET `{issuer}/saml/sso`; HTTP-Redirect AuthnRequest |
| SSO output | HTTP-POST Response and Assertion, both RSA-SHA256 signed; nonce-protected automatic form submission with a manual continue button |
| Request binding | Exact issuer, IdP destination, SP/ACS, signature policy, browser, CSRF, and callback continuation |
| Time limits | Request at most five minutes old or one minute in the future; interaction expires after ten minutes; assertion valid for at most two minutes, capped by the original session expiry |
| Replay | Durable `(SP, request ID)` reservation; issuance and transaction consumption commit atomically; only one concurrent completion emits a response |
| Subject | Random, persistent, pairwise `(SP, Member)` NameID; stable across authentication methods, restarts, and profile changes; never derived from phone, email, display name, or provider subject |
| Claims | Explicitly registered `DisplayName` and administrator-managed `Email`; missing email is omitted. No mailbox-verification claim, phone, organization roles, or business permissions. See [managed email](member-email.md). |
| Authentication context | `urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified`; original authentication time and session limit retained |

The query is limited to 32 KiB, inflated XML to 256 KiB, nesting to 32 levels, XML elements to 2,048, request IDs to 256 bytes, and RelayState to 80 decoded bytes. A nonempty request ID is required. RelayState is returned as opaque text, never used as a redirect target. DTDs, directives, duplicate parameters/elements, ambiguous XML, unsupported extensions, and unsupported algorithms are rejected. No external XML resources are resolved.

Consent is required unless the operator preauthorizes the SP. `IsPassive` succeeds only with a usable shared session, one eligible Member in the registered organization, and preauthorization; otherwise it returns `NoPassive` without an interactive page. `ForceAuthn=true` returns `RequestUnsupported`, because upstream provider login cannot currently prove fresh credentials. Requested authentication context returns `NoAuthnContext`. Unsupported NameID policy, including a first-time mapping with `AllowCreate=false`, returns `InvalidNameIDPolicy`. Unknown SPs, unsafe destinations, invalid signatures, malformed/expired requests, and replay are local HTTP errors. Trusted supported error delivery is a signed SAML status response without an assertion.

Immediately before issuance, a database transaction rechecks the session, request revision, SP revision, organization, Member, factor, binding, and provider eligibility. SP changes during login invalidate the continuation. External directory checks occur before the final transaction and their revision-bound observations are revalidated inside it. After acquiring the locks, issuance samples the current time again and rejects an expired interaction, idle session, or absolute session. Time spent waiting on a provider or database lock cannot extend those deadlines. No response is emitted before commit. Logout/revocation prevents future issuance but does not revoke an already issued assertion or end a downstream SP session. SAML Single Logout is not implemented.

The assertion's `Conditions.NotBefore` permits one minute of clock skew; its `NotOnOrAfter` and bearer `SubjectConfirmationData.NotOnOrAfter` share the same two-minute/session cap. The response `Destination` and confirmation `Recipient` are the registered ACS, both `InResponseTo` values identify the reserved request, and the audience is the registered SP entity ID. Consumers must validate these constraints and maintain their own request/assertion replay protection. Atomic IdP transaction consumption does not stop someone reposting an already emitted assertion at the SP.

## Shared authentication and eligibility

Phone verification, passwords, DingTalk, and Feishu use the same verified-factor and explicit-binding rules as OIDC. Explicitly binding these factors to one Member preserves that Member's persistent NameID for a given SP. Matching contact details or provider profile fields does not create a binding. SAML request IDs and replay state remain separate from OIDC codes and grants.

A usable shared browser session can move between SAML and OIDC without another credential check. Its original authentication time is retained in SAML `AuthnInstant` and OIDC `auth_time`; token refresh and subsequent assertion issuance do not establish fresh authentication or extend the absolute session limit. Session reuse emits no new `authentication.verify` success. `ForceAuthn` remains explicitly unsupported.

Organization disablement, Member blocking or confirmed departure, factor disablement, and binding revocation prevent new assertions. A disabled or revoked DingTalk/Feishu source cannot establish or reuse authentication, but an independent valid source bound to the same eligible Member remains usable. A confirmed Member departure affects that Member across sources. A DingTalk directory outage is not a confirmed departure: DingTalk authentication fails, while the existing linked-phone fallback policy is retained. See [DingTalk authentication](dingtalk.md) for that policy's limits.

Upstream callbacks recheck current organization, Member, binding, factor, and provider configuration after external I/O, before committing authentication evidence. Changing provider credentials during login invalidates that callback. Assertion issuance rechecks current eligibility and SP registration in its own transaction, including revision-bound directory observations. These controls stop new issuance; they do not terminate sessions that an SP has already established. The SP owns its application-session lifetime and revocation policy.

## Initial profile acceptance

The initial profile in [issue #99](https://github.com/euyuil/memberid/issues/99) is supported by the following implementation and acceptance evidence. The [independent consumer guide](saml-interop.md#observed-acceptance-and-limits) records the tested package versions, executable hashes, environment, and observed results.

| Acceptance criterion | Evidence |
| --- | --- |
| Metadata and complete SP-initiated login through the ordinary package | [Packaged HTTPS acceptance](../internal/interop/saml/acceptance.test.mjs) starts the normal executable, reads metadata, sends a signed Redirect request, posts the response to the independent SP, and confirms its authenticated application session. Linux build CI runs this fixture after packaging. |
| Issuer, subject, authentication statement, correlation, and validity | [Protocol tests](../internal/samlprovider/provider_test.go) verify response/assertion signatures and contents; [shared identity tests](../internal/oidcprovider/saml_eligibility_integration_test.go) check stable NameID and original authentication time. The independent consumer rejects correctly signed responses with invalid issuer, audience, recipient, destination, correlation, or validity constraints. |
| Explicit failure without unsafe redirects or successful assertions | [HTTP admission and transaction tests](../internal/oidcprovider/saml_integration_test.go) cover invalid destinations, unknown SPs, expiry, browser binding, unsupported requests, replay, and concurrent completion. Protocol tests require error responses to contain no assertion. Packaged acceptance returns URL-shaped RelayState unchanged while posting only to the registered ACS. |
| Configuration, bindings, sessions, and limitations documented | This guide defines the protocol contract; [registration management](management-api.md#saml-service-provider-registration) and [signing operations](saml-signing.md) document administrative authority and lifecycle procedures. |
| Focused success/error tests with explicit validation limits | Protocol/configuration tests, disposable PostgreSQL integration tests with the race detector, and independent packaged consumer acceptance cover the initial profile. The consumer guide distinguishes automated HTTP acceptance from browser inspection, real-provider validation, GitLab SAML compatibility, and certification. |

The [dependency inventory](third-party-components.md#saml-idp-and-xml-signatures) records the pinned upstream SAML implementation, XML dependencies, reviewed licenses, retained notices, and advisory reachability limits. [Startup tests](../cmd/memberid/saml_integration_test.go) and HTTP admission tests cover configuration gating. Shared SAML/OIDC tests retain separate protocol transactions and the existing OIDC identity/session contract.

Legacy identifier administration and additional NameID formats ([#103](https://github.com/euyuil/memberid/issues/103)) and production database upgrades ([#106](https://github.com/euyuil/memberid/issues/106)) remain separate work. Persistent pairwise NameID allocation is part of this initial profile. [Administrator-managed email](member-email.md) is an optional extension with its own authority and release rules.

## Boundaries and validation

This profile does not implement IdP-initiated SSO, Artifact/SOAP bindings, encrypted assertions, SLO, SCIM, mailbox verification, legacy subject mapping, or automatic signing-key rotation. These remain separate work. Shared authentication tables are protocol-neutral; OIDC grants, codes, and token endpoints remain OIDC-only.

Run `go test ./internal/samlprovider ./internal/config` for parsing, signing, metadata, and key configuration. Run the [disposable PostgreSQL tests](../CONTRIBUTING.md#postgresql-integration-tests) for registry authority, revisions, persistent NameID allocation, HTTP login through each synthetic provider, concurrent completion, policy invalidation, shared OIDC SSO, and protocol separation. Real DingTalk/Feishu/SMS calls are not made by these tests. Actual GitLab SAML compatibility and complete SAML conformance are not established by a simulated SP or by the existing GitLab OIDC acceptance check.

The [independent SAML consumer acceptance](saml-interop.md) runs a packaged MemberID executable against Node-SAML 5.2.0 over real HTTPS, establishes an SP application session, and checks response constraints and SP-side replay rejection. It also verifies correctly signed negative fixtures so a broken signature cannot mask a missing constraint check. Blocking a Member during a pending login must prevent the next assertion while leaving the already established SP session intact. The Linux build CI job runs this acceptance after packaging. Database regressions cover wrong-browser submission, cross-organization selection, session/request expiry during directory I/O and row-lock waits, concurrent completion, and SP policy changes. Additional tests bind all four authentication methods to one Member, check NameID and original authentication time across SAML/OIDC/refresh, invalidate identity and source state before issuance and during upstream I/O, and verify independent-source behavior. `ForceAuthn` tests retain an existing SSO session and require an assertion-free `RequestUnsupported` response.

Authentication events include `saml.request`, `saml.request.reuse`, and `saml.assertion.issue`, with the existing bounded asynchronous persistence/retention model. They contain internal correlation identifiers, established authentication method/provider context, and safe result codes, never request XML, assertions, RelayState, or private keys. Issuance distinguishes eligibility denials from provider/backend failures and unconfirmed commits; success follows the committed transaction. Audit delivery failure cannot change the authentication result. See [authentication events](authentication-events.md) for recording boundaries. Registration changes use the transactional management audit, including the authenticated actor, organization and application display-name snapshots, and previous/resulting public trust configuration. A failed audit write rolls back the registration change. Certificate input accepts public certificates only; private keys are never registration data.
