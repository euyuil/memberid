# DingTalk authentication

An enabled MemberID organization may configure multiple DingTalk applications without SMS, Members, or OIDC clients. Use the [organization identity provider directory](console.md#organization-identity-providers) to add another application or edit an existing one. Interactive DingTalk login and verified Member admission are implemented. Explicit application-authorization synchronization, current employee-directory checks at token issuance, and periodic directory reconciliation are available. Outbound provider streams now persist membership event receipts and apply confirmed departures before acknowledging delivery.

## Configure and inspect

Create an organization using the [operator commands](operations.md). Obtain a DingTalk corporation identifier, application client identifier, and client secret from the organization's authorized application administrator. The application must be authorized for that corporation. Review the intended corporation and permissions before saving the configuration.

Place the client secret in a protected local file outside version control. One final LF or CRLF is accepted; other leading/trailing whitespace and control characters are rejected. Do not put the secret on the command line, in query strings, or in retained logs.

```sh
memberid dingtalk configure --directory .local/memberid \
  --organization '<organization-id>' --corp '<dingtalk-corp-id>' \
  --client '<dingtalk-client-id>' --secret-file '<protected-secret-file>' \
  --expected-revision 0
memberid dingtalk inspect --directory .local/memberid \
  --organization '<organization-id>'
```

Use `--provider <namespace>` with `inspect`, `configure`, `sync`, or `reconcile` to address an existing application when multiple are configured. The namespace is the provider ID in console data. The CLI requires `MEMBERID_DATABASE_URL` and the installation's protected configuration. It uses the same domain operation as the management API. Inspection returns organization ID, an opaque provider namespace, corporation ID, client ID, revision, and creation/update timestamps. It never returns the client secret, ciphertext, or provider access token.

The management operations are:

- `GET /v1/organizations/{organizationId}/dingtalk-application`: inspect existing metadata, or 404 if unconfigured.
- `PUT /v1/organizations/{organizationId}/dingtalk-application`: submit `corpId`, `clientId`, `clientSecret`, and `expectedRevision` in a JSON body. Successful creation, rotation, and unchanged-secret updates return 200 with metadata.

These organization-only operations return 409 when multiple DingTalk applications are configured. Both require the installation management credential on the private management listener. They are absent from the public OIDC listener. See the [management boundary](management-api.md) and [OpenAPI contract](management.openapi.json).

## Stable binding and rotation

Initial configuration requires `expectedRevision: 0`; its accepted revision is 1. MemberID generates and retains an independent provider namespace for each application. A DingTalk application client ID can be registered once per installation. Different application registrations can refer to the same corporation while retaining separate MemberID identities and namespaces.

The corporation and client identifiers cannot be replaced in place. Changing either returns 409 and does not reassign existing identity evidence. Applications can be disabled in the console while retaining their configuration and existing bindings.

To rotate a secret, inspect the current revision, submit the same corporation and client IDs with the new secret, and set `expectedRevision` to that revision. A successful secret change advances the configuration revision. Authorization observations use a separate `authorizationRevision`. An unchanged secret is verified again. If authorization is already active, metadata remains unchanged; if it was revoked, a successful check restores authorization and advances only the authorization revision and its timestamps. Old revisions return 409. After an uncertain response, inspect current metadata before retrying; do not blindly overwrite a newer revision. Pending login attempts bind to configuration, authorization-observation, and organization-lifecycle revisions. Disabling and re-enabling an organization cannot restore a pending attempt from its earlier lifecycle. Rotating the secret invalidates those attempts; it does not change Member identifiers or reset existing grant authentication times.

Provider validation occurs before the write transaction. MemberID rechecks the organization status and expected revision while holding the organization row lock. Disabling an organization or accepting a competing update during external I/O prevents the stale operation from applying. Invalid credentials, denied authorization, timeouts, and unknown provider failures return 503 `provider_unavailable` without changing an existing configuration or Member eligibility. This configuration operation does not infer departure or revoke existing identities from a failed candidate credential.

## Credential protection and provider protocol

MemberID stores the client secret using Go's AES-256-GCM implementation with a random nonce. Authenticated associated data binds the ciphertext to the MemberID organization, provider namespace, DingTalk corporation, client, and configuration revision. Substituting another organization's ciphertext or replaying ciphertext from an older revision fails decryption. The installation `providerKey` remains in its protected secrets file, separate from PostgreSQL. Back up that key securely with the installation; replacing it does not rotate or recover existing encrypted credentials. Automated encryption-key rotation is not implemented.

Application authorization is verified using DingTalk's [documented application token endpoint](https://open-dingtalk.github.io/developerpedia/docs/develop/permission/single_to_multi/new_get_app_token/) at `https://api.dingtalk.com/v1.0/oauth2/{corpId}/token`, with the standard provider field names `client_id`, `client_secret`, and `grant_type=client_credentials`. The transport uses the fixed HTTPS provider origin, a ten-second timeout, bounded responses, no redirects, and no automatic retries. It requests a fresh token for each configuration check and discards that token. Provider response messages and credential-bearing transport errors are not exposed.

Management request logs record only the installation principal, method, route template, and response status. Protect any reverse proxy and external tracing configuration as well; MemberID cannot prevent independently configured infrastructure from capturing request bodies. These operations do not create a durable human audit history or accept a caller-supplied human identity as proof of authorization.

## Validation

Tests simulate DingTalk responses and use disposable PostgreSQL databases. They cover request encoding, error redaction, redirect rejection, response limits, encrypted storage and restart, wrong keys, ciphertext substitution, stable bindings, failed-candidate preservation, conflicting initial configuration and rotations, disabled organizations during provider I/O, and the CLI/HTTP contracts. HTTP and database tests also cover DingTalk-only OIDC login, distinct organization subjects, standard refresh, callback browser binding and replay, and cancellation or configuration changes during provider verification. These checks simulate the upstream provider; they do not establish live DingTalk credentials or actual provider consent.

The fresh-install schema is version 15. Startup refuses older schemas without resetting or migrating their data.

The reserved `org_system` organization accepts only explicitly provisioned Members. Unlike ordinary organizations, it does not automatically admit every verified employee. Use the [system Member bootstrap](administration.md#bootstrap-and-recovery) operator approval before the intended person's fresh DingTalk login; administrator assignment remains a separate step.

## Enable interactive login

Set `MEMBERID_DINGTALK_ENABLED=true` for the public authentication process. `MEMBERID_PHONE_ENABLED` is independent; a DingTalk-only installation needs no SMS credentials. Register at least one confidential Member client and configure a usable organization application before sending users to login. Management may configure applications while the server is running. Provider enablement and file-backed OIDC client changes require a restart.

Register `<issuer>/login/dingtalk/callback` as the exact upstream redirect URL in the DingTalk application's settings. The issuer is the same configured HTTPS origin used for OIDC. The explicit loopback development exception uses `http://127.0.0.1` and still needs a provider-accepted callback registration. MemberID requests `openid corpid` as described in DingTalk's [browser authorization flow](https://open-dingtalk.github.io/developerpedia/docs/develop/permission/token/browser/get_user_app_token_browser/). The application also needs the user-profile and employee-directory permissions used to resolve `unionId`, find the corresponding employee, and read that employee's details.

An organization-restricted OIDC client supplies the MemberID organization context. An unrestricted client asks the user for that organization's MemberID identifier; this does not expose a public organization directory. The sign-in button navigates to the fixed DingTalk authorization origin. After successful verification, the user selects the independent Member and follows the same OIDC consent policy as phone login. The factor-only registration profile continues to require phone authentication and does not accept a DingTalk session.

MemberID stores only a hash of the random upstream state, binds it to the browser and OIDC authorization request, and expires the attempt after five minutes. State is consumed before the code exchange. A replay, wrong browser, expired attempt, changed application revision, canceled request, disabled organization, blocked Member, or revoked binding cannot complete login. Lost or failed upstream responses require canceling that verification and starting a fresh authorization. No upstream access or refresh token is returned to the browser or relying party.

For self-service linking, also register `<issuer>/account/dingtalk/callback` as an exact upstream callback. The [account linking page](account-linking.md) verifies a new DingTalk identity for an existing eligible Member without provisioning another Member.

## Member admission and identity evidence

A successful code exchange must report the configured corporation. MemberID resolves the verified `unionId`, obtains a fresh application token for that corporation, requires an internal employee (`contact_type=0`), and verifies consistent `userid` and `unionid` in the employee detail response. Missing visibility, unknown contact types, provider errors, and conflicting identifiers fail closed; they do not prove departure. See the provider's [subject mapping](https://developer.alibaba.com/docs/api.htm?apiId=52234) and [employee detail](https://jaq-doc.alibaba.com/docs/api.htm?apiId=52243) contracts.

The first verified admission creates a new independent Member and binding, unless an authorized operator already explicitly bound that factor to a Member in the same organization's provider namespace. Matching contacts, names, or identities in another organization never link Members. Repeated verification preserves the Member identifier. A verified change to an employee ID can retain the same `unionId` identity, but collisions with another identity are rejected. Provider profile updates do not overwrite an existing locally managed display name.

Fresh verified membership may clear an external-departure block, but never a manual block or revoked binding. Member admission, local SSO session creation, and the OIDC login-request update commit in one transaction. An invalidated request leaves none of those partial results. Optional department evidence is retained in MemberID, with unavailable data distinguished from a verified empty list; it is not added to authentication tokens or converted into business permissions. Upstream contact fields are not treated as verified phone or email factors.

The issued OIDC profile, token lifetimes, refresh rotation, and logout behavior are the same as for phone authentication. `amr` and authentication evidence use the provider method `dingtalk`. Refresh preserves the original authentication time; it does not exchange another DingTalk authorization code.

Current eligibility checks use stored organization, Member, factor, binding, provider-namespace, and application-authorization facts. Confirmed application revocation makes that DingTalk source ineligible. Phone authentication and phone-based grants remain available subject to the organization and Member eligibility rules. Disabling the login adapter stops new DingTalk authentication and SSO reuse, but does not itself revoke existing client grants. Authorization synchronization checks the application, not every employee. Stream leave events establish stored departure as described below. Unknown directory failures cannot establish employee departure; operators must block departed Members or revoke their bindings/grants when access must end.

## Synchronize application authorization

Run an explicit fresh check against the stored application credentials:

```sh
memberid dingtalk sync --directory .local/memberid --organization "$ORGANIZATION_ID"
```

The command returns metadata with `authorizationStatus` (`active` or `revoked`), `authorizationRevision`, and `authorizationVerifiedAt`. A confirmed revoked result is a successful synchronization operation with `authorizationStatus: revoked`; scripts must inspect that field. `inspect` and the management GET endpoint return the same metadata without contacting DingTalk. The synchronization command requires operator access to the protected installation and database. There is no public or browser-triggered synchronization endpoint.

A fresh application token establishes active authorization. Only the application-token endpoint's documented HTTP 400 `unauthorized.client` establishes revocation. Invalid candidate credentials, `invalid.client`, timeouts, outages, unknown errors, and missing directory visibility do not establish revocation or departure. Unknown failures leave the prior observation unchanged and return an error. Interactive login and current directory verification also record the same definitive denial for the current stored credentials. See the provider's [application-token error contract](https://open-dingtalk.github.io/developerpedia/docs/develop/permission/single_to_multi/new_get_app_token/).

Each accepted synchronization advances the observation revision, even when the status is unchanged. A newer observation, credential change, or organization lifecycle change prevents an older in-flight result from applying. A conflict requires a fresh provider check; MemberID does not blindly retry a stale write. Pending DingTalk callbacks and admission proofs are invalidated by a new observation. New requests use the current revision.

A fresh successful application-authorization check, whether explicit or in the background, or accepted credential configuration can restore application authorization. That check alone does not clear manual Member blocks, external-departure evidence, revoked bindings, or revoked grants. Known revocation is checked during identity selection, token issuance, refresh, UserInfo, introspection, and management eligibility queries. Previously issued JWTs can still be accepted by offline verifiers until their short expiry. Synchronization is not a logout or an authentication-time reset; existing unrevoked grants retain their original limits.

Application checks also run as part of periodic reconciliation below. Provider streams share the elected worker described below. Tests cover unknown-failure preservation, recovery, rejected candidate credentials, delayed observations, credential rotation, disable/re-enable cycles, phone grant eligibility, and CLI/management metadata. The upstream provider remains simulated in automated tests.

## Current directory verification at token issuance

Authorization-code redemption and Refresh Token rotation recheck current DingTalk membership for a Member with an active DingTalk binding and an admitted external identity. They obtain a fresh corporation application token and resolve the stored `unionId` without another browser authorization code. Both provider identifiers must still match the stored identity. A changed employee identifier requires a fresh verified login; refresh does not silently rebind the Member or update provider profile attributes.

| Current observation | Phone-authenticated grant | DingTalk-authenticated grant |
| --- | --- | --- |
| Matching internal employee | Eligible, subject to all other checks | Eligible, subject to all other checks |
| Timeout, unknown failure, or unavailable directory visibility | Retain otherwise valid local eligibility | Return `server_error`; issue no tokens |
| Unreadable local provider credentials | Retain otherwise valid local eligibility | Return `server_error`; issue no tokens |
| Explicit external contact or conflicting identity | Return `invalid_grant` | Return `invalid_grant` |
| Confirmed application-authorization denial | Record revocation and retain otherwise valid local eligibility | Record revocation and return `invalid_grant` |

Phone Members without an active DingTalk binding, including an explicit prebinding that has not yet admitted an external identity, do not require a directory lookup. Factor-only phone registration is also independent. A known revoked application is skipped for phone-based issuance. Disabling interactive DingTalk login does not disable these checks for existing linked Members.

Provider I/O has a total 15-second deadline and occurs before the token transaction. A short-lived local observation binds organization lifecycle, Member eligibility, application configuration and authorization revisions, binding, and provider identifiers. The token transaction rechecks that snapshot and current eligibility; a change during provider I/O can reject issuance, including disable/re-enable or block/unblock cycles. Revoking the application alone leaves phone-based issuance eligible. Directory verification does not create an authentication credential, reset `auth_time`, or extend the original absolute grant deadline.

When an unavailable lookup rejects issuance, it leaves a first-use code or Refresh Token unconsumed. Replay handling still runs when the provider fails: a replayed code or Refresh Token revokes the issued grant. UserInfo, introspection, and management eligibility use stored facts rather than calling the provider for every read. Previously issued offline JWTs remain usable until their expiry.

Automated tests cover phone fallback, definitive denial, directory-only transport, bounded observation lifetime, code/refresh retry after a failed lookup, replay revocation during outages, and concurrent changes to organization, Member, binding, application credentials, and authorization observations. These tests simulate DingTalk; they are not live provider acceptance.

## Periodic reconciliation

The configured authentication process (`serve --directory`) starts a reconciliation worker. The elected worker checks enabled DingTalk applications in enabled organizations on startup, then waits 15 minutes after each completed pass. Applications configured during a pass are picked up by that or a subsequent pass. It checks stored application credentials first, including recovery of previously revoked authorization. For an active application, it visits admitted external identities that retain an active DingTalk binding, in bounded pages. It does not enumerate arbitrary provider users, provision new Members, restore revoked bindings, or create login sessions and grants.

A matching internal employee refreshes optional department evidence and the directory verification timestamp, and can clear the independent external-departure block. A manual block and locally managed display name remain unchanged. A definitive external-contact result establishes current nonmembership and sets the external-departure block. Unknown provider errors, missing visibility, and conflicting or changed identifiers leave the existing Member evidence unchanged; changed employee identifiers still require fresh login. In particular, a failed lookup is not proof of departure. Leave events can establish departure independently through the stream described below.

The worker performs provider I/O before write transactions. Application, organization, Member eligibility, factor, and binding facts are rechecked under row locks before applying each result. Configuration changes, block/unblock cycles, fresh login, or binding revocation during a lookup reject that result. Partial failures do not roll back already accepted Members or prevent checking other Members and organizations. No synchronization changes the authentication time or absolute deadline of existing grants.

Multiple authentication replicas share a PostgreSQL session advisory lock for background work. Coordination uses one additional database connection, separate from the ordinary query pool, with a heartbeat every five seconds and a five-second database timeout. Loss of that connection cancels the current pass; a replica retries leadership after ten seconds. Shutdown cancels provider work and releases the connection before closing the store. Use direct PostgreSQL connections or a proxy that preserves session affinity; transaction-pooling proxies cannot preserve this coordination lock. Manual operator checks can overlap background work, with revision checks rejecting stale results.

The worker logs a generic warning on incomplete work without recording credentials, provider messages, Member identifiers, or raw database errors. Disabling interactive DingTalk login does not stop reconciliation of already configured applications. An installation with no DingTalk applications makes no provider calls. Health-only mode and the separate management process do not start this worker.

For an immediate one-organization pass, without starting OIDC:

```sh
memberid dingtalk reconcile --directory .local/memberid --organization "$ORGANIZATION_ID"
```

The command requires the protected installation and operator database access. It returns current `application` metadata and `checked`, `present`, `departed`, `unavailable`, and `conflicts` counts. It emits available summary JSON even when some work failed, then exits unsuccessfully; inspect both the exit status and summary. A confirmed application revocation stops directory work for that source and is a successful observation with `application.authorizationStatus: revoked`. It is not a claim that every Member was checked. Counts describe the current pass, not a durable audit history. No credential, token, contact value, or individual Member identifier is returned.

Automated tests cover independent manual/departure blocks, preserved identity and names, optional attribute updates, unknown/conflicting evidence, stale writes, pagination with partial failures, single-leader operation with a one-connection query pool, leadership handoff, coordination-connection loss, and provider cancellation on shutdown. Provider responses are simulated and all database tests use isolated disposable databases.

## Directory event streams

Enable Stream mode in each DingTalk enterprise internal application and subscribe to `user_leave_org`, `user_add_org`, and `user_modify_org`. MemberID opens an outbound event subscription for each active application in an enabled organization; no inbound event URL or public ingestion endpoint is required. See DingTalk's [departure](https://open.dingtalk.com/document/orgapp/event-v3user-leave-org), [addition](https://open.dingtalk.com/document/orgapp/event-v3user-add-org), and [modification](https://open.dingtalk.com/document/orgapp/event-v3user-modify-org) contracts. The transport follows the framing and acknowledgement contract in the [official Stream SDK](https://github.com/open-dingtalk/dingtalk-stream-sdk-go/tree/d8d6e1f19d68b231c1514fdac973d866a2882b93); that SDK is not a runtime dependency.

Allow outbound TLS on port 443 to `api.dingtalk.com` and `wss-open-connection.dingtalk.com`, the [documented Stream origins](https://opensource.dingtalk.com/developerpedia/docs/learn/stream/faq/), in addition to the existing directory endpoints. Connection tickets come from the fixed HTTPS gateway. MemberID rejects other WebSocket origins, credentials in URLs, existing query strings, nonstandard ports, and redirects. It sends no machine hostname or local IP. Handshakes take at most ten seconds, frames are limited to 512 KiB, and an idle read expires after three minutes. System ping payloads are echoed; disconnect messages are acknowledged before closing. Tickets, secrets, raw frames, provider messages, and transport errors are not logged.

Only the elected reconciliation worker opens streams. It checks application configuration and organization lifecycle every five seconds, cancels obsolete connections, and reconnects after ten seconds with newly loaded credentials and a fresh ticket. Routine active authorization observations do not churn a connection. Confirmed application revocation or a disabled organization stops its stream; recovery allows a new connection. Shutdown or loss of the coordination connection cancels streams before releasing leadership. A stream failure alone does not establish revoked application authorization or employee departure. Disabling interactive DingTalk login does not stop streams for already configured applications.

For a supported membership event, MemberID requires the configured corporation, an event identifier, a positive provider millisecond timestamp no more than five minutes ahead of the local clock, and 1–1000 nonempty employee identifiers. Keep the installation clock synchronized. It stores a receipt keyed by application namespace and event identifier, with a SHA-256 digest of the relevant canonical fields. Reordered or repeated employee identifiers have the same meaning. Reusing an identifier with conflicting content fails; an exact replay has no further effects. Raw profile changes and contact attributes are discarded. Receipts currently remain in the database indefinitely; include their storage in capacity planning and backups. They are replay protection, not a human audit log.

A `user_leave_org` event atomically sets external departure for already admitted Members with an active matching DingTalk binding, preserves manual blocks, and invalidates older directory observations. Receipt and departure commit before the `SUCCESS` acknowledgement. Transaction failure returns `LATER`, allowing provider redelivery; no acknowledged departure depends on a background queue. In-flight first admissions are also fenced against accepted events. Token transactions and departure updates serialize on the organization so an acknowledged departure prevents subsequent code redemption or refresh for the affected Member. UserInfo, introspection, and management eligibility also observe the stored block. Previously issued offline JWTs retain their short expiry; event delivery is not instantaneous global logout.

Per-Member provider timestamps order membership events; older events cannot overwrite a newer event, and departure wins at equal timestamps. This ordering compares provider events with each other, not with local directory observation times. Delayed first delivery can temporarily block a currently returned Member until a fresh successful check. An add or modify event never directly restores access, changes identity bindings, or creates a Member. Instead it requests a fresh reconciliation, as does every successful stream connection. Notifications coalesce, with at least ten seconds between completed event-triggered passes. Only a matching current internal-employee lookup can clear external departure; manual blocks, revoked bindings, grants, and authentication deadlines remain unchanged.

These fresh checks reuse the regular reconciliation path. Unknown failures leave stored evidence untouched and are retried on a later notification, reconnect, explicit command, or periodic pass. Restart and lost in-memory notifications are covered by the complete startup and periodic passes; there is no separate durable job queue to drain. Unsupported event types are acknowledged and ignored. Unknown employee identifiers never provision identities or match Members by contact information.

Tests exercise actual local TLS/WebSocket framing with a simulated provider, disposable PostgreSQL receipts, concurrent delivery, conflicting replays, timestamp ordering, identity isolation, stale admissions and token observations, credential rotation, lifecycle changes, reconnect, and leader handoff. This is not live DingTalk provider acceptance. GitLab and other relying-party acceptance remain separate checks.
