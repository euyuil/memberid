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

Authorization uses `response_type=code`, mandatory PKCE `S256`, and the `openid` scope. Token exchange, introspection, and revocation require a form-encoded POST body and `client_secret_basic`. Query-string credentials, body client secrets, and combined client-authentication methods are rejected. ID Tokens and JWT access tokens use RS256 and a public-key-derived `kid`. Discovery advertises only the enabled profile, including the registered custom evidence scopes.

Clients explicitly registered with `refresh=true` can request `offline_access` and use rotating Refresh Tokens at the standard token endpoint. Other clients cannot obtain or use refresh grants. Discovery advertises refresh only when at least one registered client enables it. There is no private renewal endpoint. Implicit flow, password grants, client credentials, token exchange, dynamic registration, request objects, device flow, and iframe session checks are not enabled.

## Login and independent subjects

The browser follows the application's authorization redirect to MemberID. MemberID binds the login transaction to an HttpOnly browser cookie and verifies login form submissions with an exact Origin and transaction-specific CSRF value. Phone verification or an enabled DingTalk login then establishes a server-side SSO session. The user selects an explicitly bound, currently eligible Member in the organization's context. A client may be restricted to one organization.

The stable account key is `(iss, sub)`, where ordinary clients receive the independent Member identifier as `sub`. Two Members using the same verified phone remain two subjects. Display names and contact attributes must not be used for account matching. Missing verified email is omitted, not manufactured from a phone number or Member identifier.

Clients receive only requested supported identity information. `profile` supplies the Member display name and a stable Member-based `preferred_username` through UserInfo; `phone` supplies the verified phone number and verification flag for phone authentication; DingTalk login does not manufacture phone claims. The `email` scope is accepted for standard client compatibility, but no email claims are issued until a verified email source exists. Applications that require email-based provisioning must use an explicit account-linking or provisioning process.

Interactive consent is required unless the operator explicitly marks the registered policy `preauthorized`. `prompt=consent` still requires confirmation. `prompt=login` and `max_age` require appropriate fresh authentication. `prompt=none` returns a standard interaction error when authentication, consent, or an unambiguous eligible Member is unavailable. An existing session does not silently select one of several organization identities.

A separately registered `subjectKind=factor` client may receive a verified phone-factor subject before membership exists. This policy requires an operator-selected evidence scope and fixed audience. It does not create a Member or grant access to an organization. Ordinary clients cannot request this subject mode themselves.

## Token validation and eligibility

Relying parties must verify the exact issuer, RS256 signature against the issuer's JWKS, client audience, expiry, applicable nonce, and `azp` when present. The provider library includes both the resource audience and client ID in the ID Token audience and identifies the client in `azp`; OIDC permits multiple audiences. Do not assume `aud` is a scalar or accept a token intended only for another client. Follow [OIDC Core's ID Token validation rules](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).

ID Tokens authenticate the user to a client. They do not work as UserInfo or application API bearer credentials. Access-token consumers must separately require the expected issuer, resource audience, valid lifetime and signature, `tokenUse=access`, and their own permissions. Token type and permissions cannot be inferred merely from a valid signature or matching subject.

For a registered evidence scope, the access token includes `authentication` facts (`factorId`, `factorType`, `method`, `authenticatedAt`, `expiresAt`), plus `organizationId`, `memberId`, and `bindingId` when a Member is selected. This is an optional identity-claim extension to the standard access token, not another credential or authorization protocol. No business roles, administrative privileges, or resource grants are issued by MemberID.

Current organization, Member, factor, and binding eligibility is checked during code issuance/redemption, refresh, and online UserInfo/introspection. For admitted DingTalk-linked Members, code redemption and refresh also perform [current directory verification](dingtalk.md#current-directory-verification-at-token-issuance), with distinct policies for unknown provider outages and definitive contradictions. An authorization code is bound to its client, redirect URI, PKCE verifier, and browser transaction. It expires after at most one minute and may be redeemed once. A detected valid code replay revokes the resulting grant, including concurrent duplicate redemption. A failed client or PKCE check does not consume another client's legitimate code.

## Lifetimes, revocation, and logout

Authorization transactions expire after ten minutes. Access tokens last at most ten minutes and never outlive the original authentication deadline. ID Tokens last five minutes. Browser SSO lasts seven days. A client grant expires after seven days without a successful refresh and cannot extend past 365 days from the original authentication. Ordinary page requests and token introspection do not extend either deadline. These are MemberID policies, not durations mandated by OIDC.

Session credentials, authorization-code values, and random Refresh Token credentials are retained only as hashes. Authorization, session, grant, and token records persist in PostgreSQL, and expired records are cleaned periodically. A server restart does not require a new login when its configuration, keys, database, and browser cookies are retained. Protect the database, private keys, provider credentials, client secrets, and backups.

Revocation affects the authenticated client's grant. The endpoint requires a nonempty `token`, ignores `token_type_hint` when finding supported token types, and treats unknown or differently owned credentials as successful no-ops. A bare token identifier is not a revocable credential. The provider uses the maintained library's authenticated AES-256-GCM implementation without its legacy unauthenticated opaque-token decoder. See [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1).

Access-token introspection is restricted to that client; Refresh Token introspection is not provided. Refresh Token revocation invalidates its entire grant, including its access tokens at online verifiers. RP-initiated logout requires a valid `id_token_hint`, validates any registered post-logout destination, revokes the associated MemberID SSO session and grants, and clears the browser session cookie. It does not erase another application's local session. Back-channel logout is not implemented. Already issued JWTs accepted only through offline signature validation remain usable until expiry; use online introspection where immediate revocation is required.

Production cookies use `Secure`, `HttpOnly`, `SameSite=Lax`, and the `__Host-` prefix. Production requires an HTTPS issuer. The explicit `127.0.0.1` development exception uses non-Secure local cookies. Serve authentication through a trusted TLS endpoint, preserve the configured issuer origin, and avoid logging authorization headers, token responses, cookies, codes, or login form bodies.

## Standard refresh

Request `offline_access` during authorization only for a client whose operator registration enables refresh. MemberID obtains explicit consent during that login unless a preauthorized policy supplies the operator's prior consent decision. Once the grant exists, refresh does not require another confirmation, browser navigation, iframe, SSO cookie, or shared origin:

```sh
curl --request POST "$ISSUER/oauth/token" \
  --user "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode grant_type=refresh_token \
  --data-urlencode "refresh_token=$REFRESH_TOKEN"
```

The application backend must protect both credentials and redact command/request logs. Each successful response replaces the previous Refresh Token. Persist the returned token securely before another refresh. Serialize refresh for the same grant across browser tabs and application replicas. Retrying an already consumed token, including after a lost successful response, revokes the family and requires a new authorization flow. There is no replay grace window or private recovery token.

A refresh may retain or narrow its scope; it cannot add a scope or regain a removed one through a later rotation. The original subject, authentication time, client binding, and absolute deadline remain fixed. MemberID rechecks current identity eligibility and registered client policy before issuing tokens. Rotation and replay revocation are database transactions, so multiple MemberID replicas share the same result.

Browser SSO and client grants have separate idle behavior. An actively renewed grant remains usable after the browser's MemberID cookie expires, and cleanup retains the associated session record while unexpired grant records still reference it. This does not extend browser SSO or reset fresh authentication. The server requires fresh authorization when five minutes or less remain before the absolute deadline. Access-token and grant expirations are capped at that deadline; each application remains responsible for its own local-session lifetime.

An application can refresh automatically when foreground activity needs an almost-expired Access Token. Avoid refreshing from background polling. MemberID cannot determine whether an arbitrary RP's refresh originated from human foreground activity; that scheduling policy belongs to the client. On `invalid_grant`, discard local token state and start a new standard authorization flow instead of repeatedly retrying a consumed or expired token. Follow [OAuth security guidance on refresh protection](https://www.rfc-editor.org/rfc/rfc9700.html#name-refresh-token-protection).

## Running the provider

Follow [operator setup](operations.md) to initialize a new dedicated database and installation directory, register a client, and configure at least one optional [phone](phone-authentication.md) or [DingTalk](dingtalk.md) adapter. Then run:

```sh
memberid serve --directory .local/memberid --listen 127.0.0.1:8080
```

Phone and DingTalk can be enabled independently. DingTalk-only login requires no SMS credentials. Omitting `--directory` starts health-only mode. File configuration and client-policy changes take effect after a restart; organization DingTalk credentials are loaded with explicit revision checks. This initial schema is version 11; startup refuses older schemas, and no existing database is reset or migrated automatically.

For the first Member, create its organization and Member through the operator CLI, then let the person verify their phone in an application login. Verification creates only the factor. An authorized operator can inspect that existing factor and explicitly bind it:

```sh
memberid factor inspect --phone PHONE_NUMBER
memberid member bind-factor --organization ORGANIZATION_ID --member MEMBER_ID --factor FACTOR_ID
```

Confirm the intended organization and person through the administrator's enrollment process before binding. Start a new authorization request after enrollment; the retained SSO session can satisfy authentication. The lookup command never creates unverified factor evidence, and binding by an arbitrary phone number is not supported.

## Validation status

Automated HTTP tests use the actual provider, RSA tokens, browser cookie jars, and disposable PostgreSQL databases. They exercise login, discovery, client/PKCE/redirect checks, CSRF and browser binding, consent, distinct organization subjects, factor-only subjects, concurrent code replay, current eligibility, introspection, revocation, logout, authentication age, persisted SSO/JWKS behavior across a signing-key rollover restart, refresh rotation and scope narrowing, concurrent family replay, independent provider instances, and transactional rollback on issuance failure. SMS delivery and upstream DingTalk responses are simulated in these tests. A browser rendering check of the actual login template at 320-pixel width confirmed stable control positions across initial, pending, verified, and failed states, with no horizontal overflow; this is synthetic UI validation, not live provider acceptance. The [packaged GitLab fixture](gitlab.md) has established an actual GitLab account session through its unmodified OIDC client; independent interactive browser acceptance and live upstream-provider acceptance remain pending. This is not a claim of OpenID certification.

The login page permits form navigation to its own origin, the current registered OIDC callback origin, and the fixed DingTalk login origin when that method is enabled. Redirect-URI validation remains exact at protocol boundaries. Script execution and framing remain disabled.
