# Authentication events

This document records the agreed design for MemberID authentication events:
event meaning, correlation, organization visibility, retention, and delivery
failure behavior. **The store, bounded writer, retention cleanup, `sms.send`,
supported-method `authentication.verify`, initial grant issuance, confirmed OIDC
reuse, explicit session/grant revocation producers, authorized queries, and console views are
implemented.**
Authentication policy and token claims are unchanged.

The existing [management history](administration.md#availability-and-audit)
records selected successful management changes atomically. It remains a
separate implemented contract; this design does not silently change its writes
or retention. The [OIDC profile](oidc.md), [phone verification](phone-authentication.md),
and [account linking](account-linking.md) describe current business behavior.

## Purpose and boundaries

Events explain what happened, which verified identity or target was involved,
why an operation reached its result, and what subsequent action was taken.
They cover MemberID authentication and its OIDC session/grant lifecycle.
Consuming applications retain their own business authorization and audit logs.

Business state is authoritative. Authentication events are best-effort evidence:
missing events do not prove that an operation never occurred, and event counts
are not a complete accounting ledger. Events neither grant access nor provide
the state used for rate limits, credential consumption, replay detection, or
revocation. Reading an event cannot establish current identity eligibility.

## Event catalog

Use a stable `type`, an `outcome`, and, where useful, an allowlisted `reasonCode`.
Event types describe operations or observations; they are not management
authorization actions and need not use CRUD verbs.

| Type | Outcomes | Meaning and recording boundary |
| --- | --- | --- |
| `sms.send` | `succeeded`, `rejected`, `failed` | A login or account-linking send reached provider acceptance, was refused by a local limit/validation rule, or failed without confirmed acceptance. Acceptance is not confirmed handset delivery. A timeout leaves delivery uncertain. |
| `authentication.verify` | `succeeded`, `rejected`, `failed` | A supported method established authentication evidence, rejected a credential, or encountered a system/provider failure. For login or linking with an atomic state transition, success is recorded only after that transition commits. It does not assert that an application grant was issued. |
| `oidc.grant.issue` | `succeeded`, `rejected`, `failed` | Initial application grant establishment completed or was refused/failed at its issuance boundary. Success follows the committed grant and token records at code redemption, not merely code issuance or successful factor verification. |
| `oidc.authorizationCode.reuse` | `detected` | Protocol validation recognized reuse of a legitimate authorization code. Arbitrary invalid codes and wrong-client/PKCE attempts are not automatically classified as confirmed reuse. |
| `oidc.refreshToken.reuse` | `detected` | Protocol validation recognized reuse of a consumed Refresh Token. This does not identify which presenter is legitimate or prove malicious intent. |
| `session.revoke` | `succeeded`, `rejected`, `failed` | A session revocation committed, was denied, or could not be confirmed. Include the trigger, such as browser logout, without claiming that downstream applications erased their own sessions. |
| `grant.revoke` | `succeeded`, `rejected`, `failed` | A grant revocation committed, was denied, or could not be confirmed. Distinguish an operator request, client revocation, session logout, and replay handling. |

`succeeded` describes the documented operation boundary, not receipt of the HTTP
response by the caller. `rejected` means a credential, protocol, eligibility, or
limit rule refused the operation. `failed` means an operational error prevented
a confirmed result; it must not imply that an uncertain commit was rolled back.
`detected` reports an observation, separately from its protective response.

For example, record a confirmed replay and the resulting grant revocation as
separate correlated events. If revocation fails, do not report it as successful.
If revocation succeeds but its event is lost, the grant remains revoked. A
successful idempotent no-op, such as revoking an unknown token, must not invent
a target or a new state-change event.

Reasons use stable codes such as `invalidCredential`, `expiredCredential`,
`sendRateLimited`, `providerUnavailable`, `backendUnavailable`, or
`commitUnconfirmed`. Do not copy database errors, provider payloads, or submitted
credentials into `reasonCode`. The server classifies the result; the caller
cannot supply the event type, actor, or outcome.

Normal refresh success, every UserInfo/introspection call, arbitrary HTTP traffic,
new provider-directory events, and new account-management features are outside
this first catalog. Existing expiry and revocation semantics remain unchanged.

## Identity and correlation

Authentication can precede Member selection. A failed phone attempt must not be
attributed to a Member simply because its submitted number matches a binding.
Keep the verified actor separate from the affected target and from the requested
client/organization context. An unidentified caller remains unidentified.
Possession of a reused credential does not identify its presenter as the Member
named by that credential; an authenticated client can be the known actor while
the grant's Member remains the affected subject.

The logical event envelope contains:

| Fields | Meaning |
| --- | --- |
| `eventId`, `type`, `outcome`, `reasonCode` | Server-generated event identity and classified result. Assign `eventId` once and preserve it across audit retries. |
| `occurredAt`, `recordedAt` | UTC time of the observed operation boundary and first successful persistence. Delivery can be delayed or reordered; insertion order is not causal order. |
| `interactionId`, `requestId` | Server-controlled identifiers for the login/linking flow and individual request. A flow can span several requests. These are correlation values, not proof of identity. |
| `actor` | The verified initiator when known: factor, Member, authenticated client, installation operator/manager, or system. Absence of a verified initiator does not prevent a failure event. Actor identity and target identity are distinct. |
| `organizationId`, `memberId`, `clientId` | Optional authoritative event context. A validated client reference is not proof that its caller authenticated as that client. A Member reference requires an explicitly resolved Member context. |
| `factorId`, `bindingId`, `sessionId`, `grantId` | Optional references to established internal records relevant to the event. Never record a new identifier whose creation rolled back as an established resource. |
| `providerId`, `method`, `purpose` | The validated organization provider's internal ID (when applicable), authentication method, and purpose, such as login or account linking. This never contains provider credentials or raw upstream identifiers. |
| `trigger` | A classified cause such as `browserLogout`, `clientRevocation`, `operatorRequest`, or `replayDetection`, when applicable. It describes why the operation ran, separately from whether it succeeded. |
| `causationId` | Optional reference to the triggering event, for example a replay detection that caused grant revocation. The reference can outlive or precede delivery of the other event. |

Capture this bounded envelope at the business boundary. A later writer must not
reconstruct the actor or organization by looking up whatever bindings exist at
delivery time. Unknown references remain absent. Stored events are immutable;
they are not enriched later to assert identities that were unknown at the time.

One phone login might produce the following sequence. The identifiers here are
symbolic labels, not literal MemberID identifiers:

```text
interaction T1:
  sms.send / succeeded
  authentication.verify / succeeded  -> factor F, session S; no Member selected
  oidc.grant.issue / succeeded         -> organization A, Member M, client C, grant G

interaction T2:
  oidc.grant.issue / succeeded         -> another permitted application using S
```

SSO reuse does not invent a new factor-verification event. Separate flows can
share a session; one session can support grants for independent Members in
different organizations. There is no global User inferred from that relationship.

Session/grant record IDs are internal references, not Cookie values or bearer
credentials. The same applies to request/flow correlation: do not use raw OAuth
state, nonce, CSRF values, PKCE verifiers, or browser cookies as log identifiers.
Do not store tokens, authorization or SMS codes, credential hashes, client/provider
secrets, full request/response bodies, or raw provider diagnostics. The first
version does not retain raw phone numbers, source IP addresses, or User-Agent
strings. Where operationally needed, use a masked destination or a server-derived
keyed source fingerprint; a plain hash of an enumerable phone/IP space is not
sufficient. Bound and sanitize all fields.

## Ownership, visibility, and queries

Set event organization ownership only from a validated server-side workflow
that already belongs to one organization, or from the established Member/grant
target. An input organization ID alone is insufficient. Shared or unresolved
authentication events have no organization owner and remain platform-visible.
Do not assign them to `org_system`, duplicate them into every bound organization,
or retrospectively expose them when a new binding appears.

| Reader | Allowed visibility |
| --- | --- |
| Platform administrator | Global events and organization views, subject to current management eligibility. |
| Organization administrator | Events owned by the administrator's own ordinary organization, with the organization-safe field projection. |
| Ordinary Member | No event-query access in the first version. A self-service history requires a separate ownership and visibility design. |

Use the existing [scope/action model](management-permissions.md). The authorization targets are:

| Target | Supported read semantics |
| --- | --- |
| `authenticationEvents`, `authenticationEvents/{eventId}` | Platform aggregate collection and individual event. |
| `organizations/{organizationId}/authenticationEvents`, `organizations/{organizationId}/authenticationEvents/{eventId}` | One organization's collection and individual event. |

Describe permissions as `read` where both `list` and `get` are allowed; the
existing action normalization applies. A collection-only permission does not
implicitly cover instance paths. An organization grant can select its collection
and instances with `organizations/{organizationId}/authenticationEvents/*`.
These targets are registered in the
[current operation catalog](management-operation-catalog.md).

Server-derived ownership, current role eligibility, and field projection still
apply when a scope pattern matches. A Member filter does not turn the records
into Member-owned resources. Apply organization restrictions before filtering,
pagination, counts, or direct event lookup. Neither guessed IDs nor correlation
filters may reveal events in another organization. A new query uses the normal
current authorization check; no new mid-operation rechecking rule is introduced.

An organization view exposes local Member/client/grant context, event result,
method, reason and time. It omits platform-wide factor/session references, source
fingerprints, other organizations' references, and causal links outside the
authorized organization. Correlation must stay within that view rather than
provide a way to traverse shared SSO activity.

For example, ending a shared session produces a platform-level session event and
organization-owned events for grants actually revoked in each organization.
Organization A can see its own grant effects, not organization B's grant, the
global session history, or a count of effects in other organizations.

Application callers cannot create, edit, or delete these records through CRUD
permissions. Emitting an event is a server-side consequence of an operation,
not an extra `create` permission required for login or revocation. Retention
cleanup is a system operation. Existing installation interfaces keep their
separate authority contracts; this design adds no credential or token claim.

## Query API

The console's existing opaque session and current administrator eligibility protect
these GET endpoints. They do not accept installation management credentials:

| Endpoint | View |
| --- | --- |
| `/api/authentication-events` | Platform collection. |
| `/api/authentication-events/{eventId}` | Platform detail. |
| `/api/organizations/{organizationId}/authentication-events` | Organization collection. |
| `/api/organizations/{organizationId}/authentication-events/{eventId}` | Organization detail. |

Lists return `{ "items": [], "organizationNames": {}, "nextAfter": "..." }`, omitting `nextAfter` on the
last page. Optional exact filters are `type`, `outcome`, `method`, `memberId`,
`clientId`, `grantId`, `requestId`, and `interactionId`. `from` is inclusive and
`to` exclusive; both accept RFC 3339 timestamps with an explicit timezone.
`limit` defaults to 50 and accepts 1–100. Pass the returned opaque `nextAfter`
value as `after` while keeping the filters and organization unchanged. Changing
a filter starts a new first page.

`organizationNames` maps only the organization IDs present on the authorized page to current display names. These names are presentation metadata, not historical event evidence; renaming an organization does not change stored events. Empty pages expose no organization names.

Results sort by descending `occurredAt`, then `eventId`, using database timestamp
precision. Pagination is a live view, not a frozen snapshot: later audit delivery
or retention cleanup can change subsequent results. There is no total count.
An expired or foreign event ID in an authorized organization view returns the same
not-found response as an absent ID. Global collection access does not implicitly
fall back to an organization view. A platform administrator selecting an organization
receives the same safe projection as its administrator. Factor actors are omitted;
a Member actor is exposed only when it is the established local target Member.
Causal links are included only when their target is retained and visible in the
same organization. The API never returns raw stored JSON as an unfiltered payload.

## Storage and retention

A separate PostgreSQL `authentication_events` store is implemented. Existing
management records require an organization and actor and describe different operations;
do not force unidentified/global authentication events into that shape. The
query API returns only the typed event envelope, with the projection described above.

Default retention is **90 days from `occurredAt`**, with a positive,
operator-configurable duration. This is a product default, not a legal retention
claim. Set `authenticationEventRetentionDays` in `memberid.json` to 1–36500 days;
omitting it or using zero selects 90. Restart the authentication and console processes to apply
a change, and use the same policy for all replicas. The policy applies to persisted
authentication events, not to
the existing management history, business session/grant lifetimes, or SMS quotas.

The query interfaces exclude records past their retention deadline.
Cleanup removes expired
records in bounded batches, scheduled at least daily while the service is
healthy. Report cleanup failures and lag; a stopped/failing cleaner cannot
promise physical deletion on schedule. Delayed delivery and retries must not
restart retention or reinsert an already-expired event. Changing the configured
duration affects retained records without restoring previously deleted ones.

Backup retention is an explicit operator responsibility. Database cleanup alone
does not erase backup copies; apply expiry filtering and cleanup after restore.
Fallback operational logs have their own documented collection and retention
settings and must not become an unbounded second archive of identity data.

## Business availability and delivery failures

**An audit failure must not change an authentication decision, undo a completed
login or revocation, or turn a failed business operation into success.**
The implemented delivery path is:

```text
execute business operation
  -> confirm business result (commit any required state)
  -> offer immutable event to a bounded in-process queue
  -> background writer persists it independently, with bounded retries
```

The request does not wait for audit persistence or queue space. Rejected attempts
and provider failures can also enqueue their observed result without a successful
business transaction. The background task uses its own bounded lifetime, not a
request context that disappears after the response. It must not re-execute the
business operation to obtain or retry an event.

Use a bounded worker count, memory capacity, retry count/age, write timeout, and
database connection budget. Audit retries must not consume all business
connections or create unlimited goroutines. Successful persistence is deduplicated
by `eventId`, including retries after an uncertain write acknowledgement. The
writer uses a separate transaction; do not insert audit rows into a business
transaction and merely ignore insert errors.

| Failure | Business behavior | Audit behavior |
| --- | --- | --- |
| Queue full/unavailable | Preserve the business result; do not wait for capacity. | Drop the event and account for the observed drop. |
| Audit insert fails or times out | Preserve the business result. | Retry within bounds; report final delivery failure/drop when exhausted. |
| Process crashes after commit or before persistence | Already committed state remains authoritative. | Events in the gap or memory queue may be permanently lost. |
| Business result is unconfirmed | Do not claim successful login/revocation on the strength of a log entry. | Record only the known failure/uncertainty, if delivery remains available. |
| Graceful shutdown | Stop business handling under the existing shutdown contract. | Attempt to drain for a bounded interval; shutdown must eventually finish. |

Expose queue depth, delivery failures, retry exhaustion, drops, cleanup lag and
writer health to operators. Report prolonged failures through a separate,
rate-limited operational logging/monitoring path, not by recursively adding an
event to the failing audit queue. Diagnostics must exclude credential material
and full event payloads. This observability is also best effort: an abrupt crash
can lose both events and in-memory counters, so exact loss counts or complete
gap detection are not guaranteed. Audit degradation must not make the login
service unready solely because auditing is unavailable.

The following remain required business writes with their existing failure
semantics: SMS budget admission, OTP/code consumption, session and grant
creation, Refresh Token rotation/replay state, and session/grant revocation.
Failure to persist them is not an ignorable audit failure. In particular, replay
detection must still attempt its required revocation regardless of event
delivery, and must not report a completed revocation without confirmation.

The selected tradeoff permits audit loss to preserve business availability.
There is no durable queue, mandatory transactional outbox, or zero-loss promise
in this first design. Shared infrastructure failure can still prevent the
business writes themselves; best-effort auditing does not make a failed database
available. No authorization timing or in-flight revocation rule is changed.

## Current delivery and operations

The authentication process uses one background worker, a 256-event in-memory
queue, and one separate PostgreSQL connection. Each write has a two-second
timeout and at most three attempts, with 100/200 ms retry delays. Events waiting
more than 30 seconds in the queue are discarded. No request waits for persistence
or queue capacity. Graceful shutdown attempts a five-second drain; an abrupt
crash can lose pending events. Event IDs stay stable across retries and duplicate
inserts preserve the first `recordedAt`.

Every minute, the same worker deletes at most 1,000 expired rows and reports a
structured `Authentication event delivery status` diagnostic. It contains queue
depth, completed writes, write failures, exhausted retries, observed drops, queue
age expiry, last-write health, cleanup failures, remaining cleanup lag in seconds,
and the Unix time of the last successful cleanup. Counters reset on restart.
Cleanup lag describes the oldest still-expired record after that batch; after a
cleanup failure, the last successful measurement and timestamp remain visible.
Operators must monitor both lag and timestamp. No identity references, raw database
errors, or event payloads are included. This diagnostic uses the existing process
logger, at most once per minute plus shutdown; operators own log collection and
retention. `/healthz` remains process health and does not fail because audit
persistence is degraded. A stopped process cannot perform cleanup or report loss.

Current SMS producers cover accepted sends, local number/source validation and
quota rejection, and provider/backend failures in validated login and account
linking workflows. `sms.send / succeeded` occurs immediately after provider
acceptance, even if the later required challenge-readiness update fails. That
business failure still prevents login normally. A provider timeout produces
`failed / providerUnavailable` without asserting non-delivery. Repeated form
submissions refused before starting a send do not invent a second provider call.
Shared phone login has no Member actor. A registered organization-restricted
client supplies organization ownership; an arbitrary organization hint or matching
phone binding does not. Account linking uses the already validated Member context.
Each HTTP request and stored flow has an independent server-generated correlation
ID; neither value is a cookie, state parameter, code, or credential hash.

SMS verification records its result only after the existing combined verification
transaction returns. Successful login includes the committed factor and session,
without inferring a Member from its phone number. Successful phone linking uses
the authenticated Member actor and the newly verified factor; the source binding
is not mislabeled as the new binding. Failed transitions expose no rolled-back
factor or new session references. Wrong, expired, consumed, and exhausted codes
share `rejected / invalidCredential`; this does not disclose which check failed.
Operational errors use `failed / backendUnavailable`. A transport failure while
committing a completed verification transaction uses `failed / commitUnconfirmed`
and does not assert rollback. Database errors when recording incorrect-code
attempts or evaluating binding eligibility remain operational errors, rather than
being mistaken for invalid credentials or ineligibility.

DingTalk and Feishu login callbacks, and existing DingTalk account linking, use
the same verification event type. A valid browser-bound provider workflow supplies
organization/provider ownership. Unknown or wrongly bound callbacks remain
platform-only with no inferred identity. Provider-reported `access_denied` is
classified as cancellation; standard server/unavailable errors and provider I/O
failures are operational failures. Raw callback error descriptions are excluded.
Reused external callbacks are rejected verification attempts, not confirmed OIDC
code or Refresh Token reuse events. A local cancellation alone does not invent an
upstream verification; any later invalid callback is recorded when received.

Successful external admission captures the actual Member, binding, and factor
from the transaction result, with the committed session for login. These contextual
Member references are not added to shared SSO evidence or JWT claims. No writer
looks up a later binding to enrich an old event. Failed login transitions expose
no newly admitted Member or session; a failed account link can still identify its
previously authenticated Member actor while omitting the uncommitted target factor.
Feishu account linking is not introduced.

Initial grant issuance records the result of the code-redemption transaction.
A code or factor verification alone does not produce an issuance success. Failed
issuance retains its established subject/session context but omits a new grant ID.
Client, redirect URI, and PKCE validation remain in the maintained OIDC library;
requests rejected there never reach this issuance boundary or become confirmed
reuse events. Normal successful refresh remains outside the event catalog.

Confirmed code/Refresh Token reuse records the authenticated client as actor,
with the grant's Member or factor as the affected subject. Reuse and any resulting
revocation have distinct event IDs, linked by `causationId`. Detection remains
valid when the revocation transaction fails; only a confirmed commit produces a
successful revocation event. An already-revoked grant does not produce another
state-change event. Refresh processing still stops at an ineligible/revoked family
before testing consumption. Code expiry between lookup and consumption is a
rejected issuance, not evidence of reuse. No code, token, verifier, client secret,
or credential hash is copied into events.

Explicit revocation producers cover the standard authenticated client revocation
endpoint, browser logout, and the trusted `grant revoke` operator command.
Unknown/mismatched tokens and already-revoked targets do not invent another
successful state change. Client revocation records the affected grant from the
mutation result; if no target can be established after a database failure, its
failure event remains platform-only with the authenticated client context.

Browser logout records one platform-owned session event and organization-owned
events for each grant actually changed, causally linked to that session event.
The verified shared-session factor is the initiator; it is not implicitly a Member
of every affected organization. A rolled-back logout records its failed session
operation without claiming committed grant effects. The transaction revokes all
applicable grants, while the producer retains at most 256 grant event envelopes;
excess committed effects increment the audit drop counter. Queue capacity and
shutdown limits can cause additional loss. This bounds audit memory without
limiting business revocation.

The operator command keeps its database-only configuration contract and labels
its actor as installation operator authority, not an inferred human Member or OS
username. Its dedicated writer attempts a drain for up to five seconds, preserving
the business exit status if auditing fails. This short-lived writer emits current
events and performs no retention cleanup; configured service cleanup and query
expiry policy remain authoritative. Repeated operator revocation preserves the
original revocation timestamp and produces no additional state-change event.

The fresh-install schema is version 18. Existing databases are never migrated or
reset automatically. The new store intentionally has no foreign keys to transient
sessions, flows, grants, or causal events. Events remain historical evidence after
business cleanup. Public queries are not available yet; operator database access
retains its existing trust boundary. Query expiry and organization-safe projection
must accompany the future query interfaces.

## Implementation validation

Unit tests cover full/closed queues, bounded shutdown, maximum queue age, immutable
context, allowlisted fields, and bounded retries with stable event IDs. PostgreSQL
and HTTP integration tests cover deduplication, occurrence-based expiry, bounded
cleanup, SMS success/rejection/provider failure, confirmed provider acceptance
followed by a business-write failure, and authentication success despite audit
insert denial. Verification tests additionally cover wrong/expired codes, failed
attempt writes, login/linking rollback, deferred commit failure, and successful
login/linking despite audit insert denial. Tests use synthetic provider adapters;
they do not prove real SMS delivery. External-provider tests cover committed
Member admission/linking, provider failures versus rejection/cancellation, callback
replay and browser binding, rollback, lookup failures, and audit insert denial.
Real DingTalk and Feishu provider verification is separate from these synthetic
adapter and HTTP checks. OIDC event tests exercise client/PKCE rejection, Member
and factor subjects, issuance rollback, eligibility-read failures, deferred commit
failures, expiry between lookup and consumption, concurrent code exchange, and
replay revocation despite audit insert denial. Explicit revocation checks cover
client ownership, shared-session organization attribution, rollback/commit failure,
idempotence, bounded bulk evidence, and CLI completion during audit insert denial.

Remaining catalog and query work must demonstrate the following before claiming
support:

- Correct event boundaries for successful verification, grant issuance, rejected
  credentials, uncertain provider delivery, confirmed replay and revocation.
  Rolled-back operations produce no committed-success events.
- Login and revocation retain their normal results with audit insert denial,
  timeouts, unavailable writers and full queues. Business-state write failures
  still fail normally. Diagnostic failures do not recurse into the event queue.
- Bounded retries and deduplication after uncertain acknowledgement, queue loss
  on abrupt termination, bounded shutdown, and operator-visible degradation.
- Anonymous/factor-only flows do not invent Members. Ownership remains fixed
  across later binding changes; organization queries, counts, filters and direct
  lookups cannot disclose other organizations or shared SSO context.
- Retention follows occurrence time through delayed delivery, configuration
  changes and restore; query expiry is enforced even when cleanup is delayed.
- Records and fallback diagnostics exclude credentials and unrestricted payloads.

These remaining requirements are not capabilities already implemented. [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#event-collection)
supports isolating logging failures from application operation; its
[verification guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#verification)
also covers failure injection and limiting logging-related resource exhaustion.
