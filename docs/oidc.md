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

Authorization responses support `query` (the default) and `fragment`, as advertised in Discovery. `form_post` and other response modes are not enabled and receive `invalid_request` before login. Clients must select one of the advertised modes; successful responses and interaction errors use that selected mode.

Clients explicitly registered with `refresh=true` can request `offline_access` and use rotating Refresh Tokens at the standard token endpoint. Other clients cannot obtain or use refresh grants. Discovery advertises refresh only when at least one registered client enables it. There is no private renewal endpoint. Implicit flow, password grants, client credentials, token exchange, dynamic registration, request objects, device flow, and iframe session checks are not enabled.

Malformed requests at the token, introspection, and revocation endpoints return HTTP 400 with the OAuth `invalid_request` JSON error, including repeated parameters, invalid form encoding, and requests exceeding the configured size limit. These responses retain the endpoint's no-store cache policy.

Client authentication failures at the token, introspection, and revocation endpoints return HTTP 401 with `WWW-Authenticate: Basic realm="MemberID"`. Token and revocation responses include the OAuth `invalid_client` JSON error. Successful requests and other protocol errors do not carry that authentication challenge.

Authorization requests using `request_uri` receive `request_uri_not_supported`, matching Discovery's `request_uri_parameter_supported=false`. The error is returned only to a callback registered for the identified client; unknown clients and unregistered callbacks receive a local error. An empty `request_uri` is treated as absent.

## Login and independent subjects

The browser follows the application's authorization redirect to MemberID. MemberID binds the login transaction to an HttpOnly browser cookie and verifies login form submissions with an exact Origin and transaction-specific CSRF value. A Member client without a registered organization first asks for an Organization ID at `/login?request=…`. A valid selection redirects to `/login/{organizationID}?request=…`; clients with a registered organization use that organization path directly. The transaction binds this selection on the server. Canceling verification retains the selected organization. To choose another organization, start a new direct login or have the application initiate a new authorization transaction.

An operator-assigned `/login/{slug}` is a bookmarkable GET alias. It resolves the enabled organization and redirects to the same issuer’s permanent `/login/{organizationID}` path, forwarding only the `request` parameter. The ID path checks the browser transaction and the client’s registered organization before presenting authentication methods. See [slug assignment](operations.md#provision-identities).

Organization login URLs return HTTP 404 for unknown or disabled organizations. If the organization lookup fails because of a database error, the login URL and organization selection form return HTTP 503.

Password, phone, DingTalk, or Feishu verification then establishes a server-side SSO session. A password identifies one bound Member in the selected or client-restricted organization. Other methods may require the user to select from multiple eligible Members, but only within the selected organization.

Opening `/login` or `/login/{organizationID}` without an application transaction starts a direct Member account login. Its completion opens `/account?memberId=…` for the authenticated Member and does not create an OIDC grant or enter the management console. These URLs can be bookmarked for interactive use. Direct continuation reuses SSO only while the session satisfies the [Member account freshness policy](account-linking.md); an older session requires fresh authentication instead of offering a continuation that the account page would reject. Applications must still use the standard authorization endpoint rather than treating the organization login page as an API.

Opening or refreshing a direct login page and selecting an organization are read-only. Selection redirects to the stable organization URL. With a fresh SSO session, a Member can continue to the account page repeatedly. Each continuation checks the current session and eligibility in the selected organization, and the account page checks access on every visit.

Submitting a password, requesting an SMS code, or starting DingTalk or Feishu authentication creates a ten-minute direct login transaction bound to the organization and browser. Each entry form is valid for ten minutes and can start one transaction. Separate organization pages can be open in parallel. Canceling a pending verification keeps its transaction in the same organization. Each provider process admits up to 12 authentication starts per browser cookie and 600 across all browsers per fixed one-minute window. At either limit a start returns HTTP 429 with `Retry-After: 60`. Entry pages, SSO continuation and existing transactions remain available. The counters reset on process restart. Expiry cleanup removes completed and abandoned transactions.

The stable account key is `(iss, sub)`, where ordinary clients receive the independent Member identifier as `sub`. Two Members using the same verified phone remain two subjects. Display names and contact attributes must not be used for account matching. Missing verified email is omitted, not manufactured from a phone number or Member identifier.

Use a distinct issuer for a separate installation with a fresh database. The reserved installation administrator ID `mbr_root` is scoped to its issuer in client account associations.

Clients receive only requested supported identity information. `profile` supplies the Member display name and a stable Member-based `preferred_username` through UserInfo; `phone` supplies the verified phone number and verification flag for phone authentication; external-provider login does not assert upstream contact values as verified phone claims. The `email` scope is accepted for standard client compatibility, but neither `email` nor `email_verified` is issued. [Administrator-managed SAML email](member-email.md) does not change this contract or establish mailbox ownership; OIDC release requires a separate explicit policy. Applications that require email-based provisioning must use an explicit account-linking or provisioning process.

After verification, interactive sign-in preselects the Member when exactly one identity is eligible. Interactive consent is required unless the operator explicitly marks the registered policy `preauthorized`. `prompt=consent` still requires confirmation. `prompt=login` and `max_age` require appropriate fresh authentication. `prompt=none` returns a standard interaction error when authentication, consent, or an unambiguous eligible Member is unavailable. An existing session does not silently select one of several organization identities.

When an authorization request supplies `id_token_hint`, the provider library validates it and MemberID retains its subject for that transaction. Completing authentication as a different Member or factor returns `login_required` to the registered callback instead of issuing a code for the other identity. This also applies to silent authorization.

For ordinary Member clients, a `login_hint` containing a complete valid Member ID
narrows selection to that Member among the current authentication factor's
eligible bindings and registered client organization policy. It supplies no
authentication or membership evidence and cannot override `id_token_hint`.
Unrecognized hint formats are ignored. With `prompt=none`, an unavailable hinted
Member returns `interaction_required`; missing or expired authentication returns
`login_required`. A preauthorized client can reuse valid SSO to select that one
Member without another SMS challenge. The [console identity switch](console.md#switch-the-signed-in-member)
uses this standard authorization flow and separately checks management access.

A separately registered `subjectKind=factor` client may receive a verified phone-factor subject before membership exists. This policy requires an operator-selected evidence scope and fixed audience. It does not create a Member or grant access to an organization. Ordinary clients cannot request this subject mode themselves.

## Token validation and eligibility

Relying parties must verify the exact issuer, RS256 signature against the issuer's JWKS, client audience, expiry, applicable nonce, and `azp` when present. The provider library includes both the resource audience and client ID in the ID Token audience and identifies the client in `azp`; OIDC permits multiple audiences. Do not assume `aud` is a scalar or accept a token intended only for another client. Follow [OIDC Core's ID Token validation rules](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).

ID Tokens authenticate the user to a client. They do not work as UserInfo or application API bearer credentials. Access-token consumers must separately require the expected issuer, resource audience, valid lifetime and signature, `tokenUse=access`, and their own permissions. Token type and permissions cannot be inferred merely from a valid signature or matching subject.

For a registered evidence scope, the access token includes `authentication` facts (`factorId`, `factorType`, `method`, `authenticatedAt`, `expiresAt`), plus `organizationId`, `memberId`, and `bindingId` when a Member is selected. This is an optional identity-claim extension to the standard access token, not another credential or authorization protocol. No business roles, administrative privileges, or resource grants are issued by MemberID.

The [token and server-side authorization design](authorization-boundaries.md)
records the agreed management boundary: tokens carry their documented identity
and OAuth claims, while MemberID evaluates its current management authority on
the server. Consuming applications own their business authorization. That design
does not change this token profile or make OIDC tokens valid credentials for the
existing management interfaces.

Current organization, Member, factor, and binding eligibility is checked during code issuance/redemption, refresh, and online UserInfo/introspection. For admitted DingTalk-linked Members using phone or DingTalk authentication, code redemption and refresh also perform [current directory verification](dingtalk.md#current-directory-verification-at-token-issuance), with distinct policies for unknown provider outages and definitive contradictions. An authorization code is bound to its client, redirect URI, PKCE verifier, and browser transaction. It expires after at most one minute and may be redeemed once. A detected valid code replay revokes the resulting grant, including concurrent duplicate redemption. A failed client or PKCE check does not consume another client's legitimate code.

## Lifetimes, revocation, and logout

Authorization transactions expire after ten minutes. Access tokens last at most ten minutes and never outlive the original authentication deadline. ID Tokens last five minutes. Browser SSO lasts seven days. A client grant expires after seven days without a successful refresh and cannot extend past 365 days from the original authentication. Ordinary page requests and token introspection do not extend either deadline. These are MemberID policies, not durations mandated by OIDC.

Session credentials, authorization-code values, and random Refresh Token credentials are retained only as hashes. Authorization, session, grant, and token records persist in PostgreSQL, and expired records are cleaned periodically. A server restart does not require a new login when its configuration, keys, database, and browser cookies are retained. Protect the database, private keys, provider credentials, client secrets, and backups.

Revocation affects the authenticated client's grant. The endpoint requires a nonempty `token`, ignores `token_type_hint` when finding supported token types, and treats unknown or differently owned credentials as successful no-ops. A bare token identifier is not a revocable credential. The provider uses the maintained library's authenticated AES-256-GCM implementation without its legacy unauthenticated opaque-token decoder. See [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1).

Access-token introspection is restricted to that client; Refresh Token introspection is not provided. Refresh Token revocation invalidates its entire grant, including its access tokens at online verifiers. RP-initiated logout accepts GET and form-encoded POST requests. A valid `id_token_hint` identifying the current browser session permits direct logout. Without that hint, or when it identifies a different session, MemberID asks whether to end the current browser session; cancellation preserves it. A `client_id` can identify the registration for an exact `post_logout_redirect_uri` when no hint is supplied. Invalid hints and unregistered destinations are rejected. POST requests first redirect to a local GET so SameSite cookies can identify the session after a cross-site RP submission.

Logout confirmation is protected by an expiring, encrypted request bound to the browser and current session, plus an exact Origin check. A confirmation opened before a new login cannot log out that new session. Successful logout revokes the selected current session and its grants and clears its cookie; it never revokes another browser's session merely because a hint refers to it. Repeating logout without an active session is harmless. Logout does not erase another application's local session. Back-channel logout is not implemented. Already issued JWTs accepted only through offline signature validation remain usable until expiry; use online introspection where immediate revocation is required.

Production cookies use `Secure`, `HttpOnly`, `SameSite=Lax`, and the `__Host-` prefix. Production requires an HTTPS issuer. The explicit `127.0.0.1` development exception uses non-Secure local cookies. Serve authentication through a trusted TLS endpoint, preserve the configured issuer origin, and avoid logging authorization headers, token responses, cookies, codes, or login form bodies.

Authentication pages use `Referrer-Policy: same-origin`: same-origin form submissions retain their `Origin`, while cross-origin navigations send no `Referer`. Keep this policy at reverse proxies. `no-referrer` causes browsers to send `Origin: null` on ordinary form POSTs and breaks the strict origin check; see the [Fetch origin-header algorithm](https://fetch.spec.whatwg.org/#append-a-request-origin-header). Login submissions still require the exact issuer origin, a valid transaction cookie, and the transaction's CSRF value. Missing, opaque (`null`), and foreign origins are rejected.

Initial grant establishment and confirmed code/Refresh Token reuse produce
[best-effort authentication events](authentication-events.md). A replay observation
and its actual grant revocation are separate events; audit failure never replaces
or gates the protocol transaction. Issuance success means committed grant/token
records, not confirmation that the client received the response. Explicit client
revocation, browser logout, and operator grant revocation use the same independent
event writer. A shared-session logout records platform session context and each
actually revoked organization grant; an idempotent no-op adds no state-change event.

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

Follow [operator setup](operations.md) to initialize a new dedicated database and installation directory, register a client, and configure at least one of the optional [phone](phone-authentication.md), [DingTalk](dingtalk.md), and [Feishu](feishu.md) adapters. Then run:

```sh
memberid serve --directory .local/memberid --listen 127.0.0.1:8080
```

Member clients can authenticate with an [organization-scoped password](administration.md#organization-scoped-passwords) and receive `amr=["pwd"]`. The username belongs to the password credential; subject and profile claims retain their existing Member semantics. The password form is part of the browser authorization flow. Token requests continue to use the documented Authorization Code and Refresh Token grants.

Phone, DingTalk, and Feishu can be enabled independently of password login. Omitting `--directory` starts health-only mode. Local signing and installation configuration is loaded at startup. Client policy and organization provider credentials use the current database registrations. The current schema is version 30. Startup refuses older schemas and preserves existing database contents.

For the first Member, create its organization and Member through the operator CLI, then let the person verify their phone in an application login. Verification creates only the factor. An authorized operator can inspect that existing factor and explicitly bind it:

```sh
memberid factor inspect --phone PHONE_NUMBER
memberid member bind-factor --organization ORGANIZATION_ID --member MEMBER_ID --factor FACTOR_ID
```

Confirm the intended organization and person through the administrator's enrollment process before binding. Start a new authorization request after enrollment; the retained SSO session can satisfy authentication. The lookup command never creates unverified factor evidence, and binding by an arbitrary phone number is not supported.

## Validation status

Automated HTTP tests use the actual provider, RSA tokens, browser cookie jars, and disposable PostgreSQL databases. They exercise login, discovery, client/PKCE/redirect checks, CSRF and browser binding, consent, distinct organization subjects, factor-only subjects, concurrent code replay, current eligibility, introspection, revocation, logout, authentication age, persisted SSO/JWKS behavior across a signing-key rollover restart, refresh rotation and scope narrowing, concurrent family replay, independent provider instances, and transactional rollback on issuance failure. SMS delivery and upstream DingTalk and Feishu responses are simulated. A browser rendering check of the actual login template at 320-pixel width confirmed stable control positions across initial, pending, verified, and failed states, with no horizontal overflow; this is synthetic UI validation, not live provider acceptance. The [packaged GitLab fixture](gitlab.md) has established an actual GitLab account session through its unmodified OIDC client; independent interactive browser acceptance and live upstream-provider acceptance remain pending. This is not a claim of OpenID certification.

The login page permits form navigation to its own origin, the current registered OIDC callback origin, and the fixed DingTalk and Feishu login origins for the enabled methods. Redirect-URI validation remains exact at protocol boundaries. Script execution and framing remain disabled.
