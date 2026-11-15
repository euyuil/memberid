# Native SAML identity provider

MemberID implements a restricted, SP-initiated SAML 2.0 Web Browser SSO profile in the normal `memberid serve` executable. SAML is disabled by default. It shares the existing phone, DingTalk, Feishu, Member selection, consent, and browser session flows with OIDC. It does not create an internal OIDC client or exchange an intermediate login proof.

## Enable signing and register an SP

Use a fresh schema version 20 database. Existing demo databases are rejected; no upgrade migration or data reset is performed. Follow [operator setup](operations.md) to create the installation, organization, Member, and authentication source.

Provision a dedicated RSA private key of at least 2048 bits and its matching X.509 signing certificate in the protected installation directory. The certificate must be currently valid and permit digital signatures if it declares key usage. Use separate key material from TLS and OIDC. MemberID rejects an OIDC key found in its retained public key set. The SAML certificate is an explicitly distributed signing trust anchor; a publicly trusted TLS certificate is not required.

Add to `memberid.json`:

```json
"saml": {
  "enabled": true,
  "signingKeyFile": "saml-key.pem",
  "certificateFile": "saml-certificate.pem"
}
```

Paths must be local to the installation directory. Private-file protections match the existing signing-key loader. Missing, mismatched, expired, or not-yet-valid material prevents startup. Live metadata and issuance also check certificate usability. Configuration is loaded at startup; restart after changes. There is no automated certificate issuance, renewal, rollover, or overlapping IdP-key publication yet. Expiry monitoring and coordinated replacement are operator responsibilities.

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
| Claims | No email, phone, organization roles, or business permissions; optional explicitly registered `DisplayName` only |
| Authentication context | `urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified`; original authentication time and session limit retained |

The query is limited to 32 KiB, inflated XML to 256 KiB, nesting to 32 levels, and RelayState to 80 decoded bytes. RelayState is returned as opaque text, never used as a redirect target. DTDs, directives, duplicate parameters/elements, ambiguous XML, unsupported extensions, and unsupported algorithms are rejected. No external XML resources are resolved.

Consent is required unless the operator preauthorizes the SP. `IsPassive` succeeds only with a usable shared session, one eligible Member in the registered organization, and preauthorization; otherwise it returns `NoPassive` without an interactive page. `ForceAuthn=true` returns `RequestUnsupported`, because upstream provider login cannot currently prove fresh credentials. Requested authentication context returns `NoAuthnContext`. Unsupported NameID policy, including a first-time mapping with `AllowCreate=false`, returns `InvalidNameIDPolicy`. Unknown SPs, unsafe destinations, invalid signatures, malformed/expired requests, and replay are local HTTP errors. Trusted supported error delivery is a signed SAML status response without an assertion.

Immediately before issuance, a database transaction rechecks the session, request revision, SP revision, organization, Member, factor, binding, and provider eligibility. SP changes during login invalidate the continuation. External directory checks occur before the final transaction and their revision-bound observations are revalidated inside it. No response is emitted before commit. Logout/revocation prevents future issuance but does not revoke an already issued assertion or end a downstream SP session. SAML Single Logout is not implemented.

## Boundaries and validation

This profile does not implement IdP-initiated SSO, Artifact/SOAP bindings, encrypted assertions, SLO, SCIM, trusted email release, legacy subject mapping, or managed signing-key rotation. These remain separate work. Shared authentication tables are protocol-neutral; OIDC grants, codes, and token endpoints remain OIDC-only.

Run `go test ./internal/samlprovider ./internal/config` for parsing, signing, metadata, and key configuration. Run the [disposable PostgreSQL tests](../CONTRIBUTING.md#postgresql-integration-tests) for registry authority, revisions, persistent NameID allocation, HTTP login through each synthetic provider, concurrent completion, policy invalidation, shared OIDC SSO, and protocol separation. Real DingTalk/Feishu/SMS calls are not made by these tests. Actual GitLab SAML compatibility and complete SAML conformance are not established by a simulated SP or by the existing GitLab OIDC acceptance check.

Authentication events include `saml.request`, `saml.request.reuse`, and `saml.assertion.issue`, with the existing bounded asynchronous persistence/retention model. They contain internal correlation identifiers and safe result codes, never request XML, assertions, RelayState, or private keys. Registration changes use the transactional management audit, including the authenticated actor, organization and application display-name snapshots, and previous/resulting public trust configuration. A failed audit write rolls back the registration change. Certificate input accepts public certificates only; private keys are never registration data.
