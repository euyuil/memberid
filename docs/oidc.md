# OpenID Connect web-client profile

MemberID implements confidential web-client login using the maintained `github.com/zitadel/oidc/v3` provider. Register each application separately, use an exact redirect URI, and keep its secret on the application's backend. Browser-only public clients are not enabled in this profile.

## Endpoints and capabilities

Discover configuration at `ISSUER/.well-known/openid-configuration`.

| Purpose | Path |
| --- | --- |
| Authorization | `/oauth/authorize` |
| Token exchange | `/oauth/token` |
| Public signing keys | `/.well-known/jwks.json` |
| UserInfo | `/oauth/userinfo` |
| Token introspection | `/oauth/introspect` |
| Token revocation | `/oauth/revoke` |
| RP-initiated logout | `/oauth/logout` |

Authorization uses `response_type=code`, mandatory PKCE `S256`, and the `openid` scope. Token exchange, introspection, and revocation use `client_secret_basic`. ID Tokens and JWT access tokens use RS256 and a public-key-derived `kid`. Discovery advertises only the enabled profile, including the registered custom evidence scopes.

Rotating Refresh Tokens are the next implementation step. `offline_access` and refresh grants are currently rejected, even if a client registration already contains the future `refresh` policy. There is no private renewal endpoint. Implicit flow, password grants, client credentials, token exchange, dynamic registration, request objects, device flow, and iframe session checks are not enabled.

## Login and independent subjects

The browser follows the application's authorization redirect to MemberID. MemberID binds the login transaction to an HttpOnly browser cookie and verifies login form submissions with an exact Origin and transaction-specific CSRF value. Phone verification then establishes a server-side SSO session. The user selects an explicitly bound, currently eligible Member in the organization's context. A client may be restricted to one organization.

The stable account key is `(iss, sub)`, where ordinary clients receive the independent Member identifier as `sub`. Two Members using the same verified phone remain two subjects. Display names and contact attributes must not be used for account matching. Missing verified email is omitted, not manufactured from a phone number or Member identifier.

Clients receive only requested supported identity information. `profile` supplies the Member display name and a stable Member-based `preferred_username` through UserInfo; `phone` supplies the verified phone number and verification flag. The `email` scope is accepted for standard client compatibility, but no email claims are issued until a verified email source exists. Applications that require email-based provisioning must use an explicit account-linking or provisioning process.

Interactive consent is required unless the operator explicitly marks the registered policy `preauthorized`. `prompt=consent` still requires confirmation. `prompt=login` and `max_age` require appropriate fresh authentication. `prompt=none` returns a standard interaction error when authentication, consent, or an unambiguous eligible Member is unavailable. An existing session does not silently select one of several organization identities.

A separately registered `subjectKind=factor` client may receive a verified phone-factor subject before membership exists. This policy requires an operator-selected evidence scope and fixed audience. It does not create a Member or grant access to an organization. Ordinary clients cannot request this subject mode themselves.

## Token validation and eligibility

Relying parties must verify the exact issuer, RS256 signature against the issuer's JWKS, client audience, expiry, applicable nonce, and `azp` when present. The provider library includes both the resource audience and client ID in the ID Token audience and identifies the client in `azp`; OIDC permits multiple audiences. Do not assume `aud` is a scalar or accept a token intended only for another client. Follow [OIDC Core's ID Token validation rules](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).

ID Tokens authenticate the user to a client. They do not work as UserInfo or application API bearer credentials. Access-token consumers must separately require the expected issuer, resource audience, valid lifetime and signature, `tokenUse=access`, and their own permissions. Token type and permissions cannot be inferred merely from a valid signature or matching subject.

For a registered evidence scope, the access token includes `authentication` facts (`factorId`, `factorType`, `method`, `authenticatedAt`, `expiresAt`), plus `organizationId`, `memberId`, and `bindingId` when a Member is selected. This is an optional identity-claim extension to the standard access token, not another credential or authorization protocol. No business roles, administrative privileges, or resource grants are issued by MemberID.

Current organization, Member, factor, and binding eligibility is checked during code issuance/redemption and online UserInfo/introspection. An authorization code is bound to its client, redirect URI, PKCE verifier, and browser transaction. It expires after at most one minute and may be redeemed once. A detected valid code replay revokes the resulting grant, including concurrent duplicate redemption. A failed client or PKCE check does not consume another client's legitimate code.

## Lifetimes, revocation, and logout

Authorization transactions expire after ten minutes. Access tokens last at most ten minutes and never outlive the source session deadline. ID Tokens last five minutes. SSO sessions currently last seven days, bounded by 365 days from the original authentication; ordinary page requests do not extend them. These are MemberID policies, not durations mandated by OIDC. The forthcoming refresh implementation must preserve the original authentication time and absolute deadline.

Session credentials and authorization-code values are retained only as hashes. Authorization, session, grant, and token records persist in PostgreSQL, and expired records are cleaned periodically. A server restart does not require a new login when its configuration, keys, database, and browser cookies are retained. Protect the database, private keys, provider credentials, client secrets, and backups.

Revocation affects the authenticated client's grant. Introspection is restricted to that client. RP-initiated logout requires a valid `id_token_hint`, validates any registered post-logout destination, revokes the associated MemberID SSO session and grants, and clears the browser session cookie. It does not erase another application's local session. Back-channel logout is not implemented. Already issued JWTs accepted only through offline signature validation remain usable until expiry; use online introspection where immediate revocation is required.

Production cookies use `Secure`, `HttpOnly`, `SameSite=Lax`, and the `__Host-` prefix. Production requires an HTTPS issuer. The explicit `127.0.0.1` development exception uses non-Secure local cookies. Serve authentication through a trusted TLS endpoint, preserve the configured issuer origin, and avoid logging authorization headers, token responses, cookies, codes, or login form bodies.

## Running the provider

Follow [operator setup](operations.md) to initialize a new dedicated database and installation directory, register a client, and configure the optional [phone adapter](phone-authentication.md). Then run:

```sh
memberid serve --directory .local/memberid --listen 127.0.0.1:8080
```

The current interactive implementation requires the phone adapter; another independent authentication adapter is still being implemented. Omitting `--directory` starts health-only mode. Configuration and client-policy changes take effect after a restart. This initial schema is version 3; startup refuses older schemas, and no existing database is reset or migrated automatically.

For the first Member, create its organization and Member through the operator CLI, then let the person verify their phone in an application login. Verification creates only the factor. An authorized operator can inspect that existing factor and explicitly bind it:

```sh
memberid factor inspect --phone PHONE_NUMBER
memberid member bind-factor --organization ORGANIZATION_ID --member MEMBER_ID --factor FACTOR_ID
```

Confirm the intended organization and person through the administrator's enrollment process before binding. Start a new authorization request after enrollment; the retained SSO session can satisfy authentication. The lookup command never creates unverified factor evidence, and binding by an arbitrary phone number is not supported.

## Validation status

Automated HTTP tests use the actual provider, RSA tokens, browser cookie jars, and disposable PostgreSQL databases. They exercise login, discovery, client/PKCE/redirect checks, CSRF and browser binding, consent, distinct organization subjects, factor-only subjects, concurrent code replay, current eligibility, introspection, revocation, logout, authentication age, and persisted SSO/JWKS behavior across a signing-key rollover restart. SMS delivery is simulated in these tests. Real GitLab interoperability and deployed provider acceptance remain separate pending checks; this is not a claim of OpenID certification.