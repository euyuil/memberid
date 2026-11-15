# Authentication events

This document records the agreed design for MemberID authentication events:
event meaning, correlation, organization visibility, retention, and delivery
failure behavior. **This is a design contract, not an implemented feature.**
The event store, background writer, query interfaces, retention worker, and
health indicators described here are not yet available. This document changes
no runtime behavior, database schema, token claims, or authentication policy.

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
| `method`, `purpose` | The authentication method and operation purpose, such as login or account linking, when applicable. |
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

Use the existing [scope/action model](management-permissions.md). The planned
authorization targets are:

| Target | Supported read semantics |
| --- | --- |
| `authenticationEvents`, `authenticationEvents/{eventId}` | Platform aggregate collection and individual event. |
| `organizations/{organizationId}/authenticationEvents`, `organizations/{organizationId}/authenticationEvents/{eventId}` | One organization's collection and individual event. |

Describe permissions as `read` where both `list` and `get` are allowed; the
existing action normalization applies. A collection-only permission does not
implicitly cover instance paths. An organization grant can select its collection
and instances with `organizations/{organizationId}/authenticationEvents/*`.
These are planned authorization paths, not implemented endpoints or registrations
in the [current operation catalog](management-operation-catalog.md).

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

## Storage and retention

Plan a separate PostgreSQL `authentication_events` store. Existing management
records require an organization and actor and describe different operations;
do not force unidentified/global authentication events into that shape. The
logical fields above do not prescribe a completed schema or JSON API.

Default retention is **90 days from `occurredAt`**, with a positive,
operator-configurable duration. This is a product default, not a legal retention
claim. Configuration names and delivery-limit values will be defined with the
implementation. The policy applies to persisted authentication events, not to
the existing management history, business session/grant lifetimes, or SMS quotas.

Queries exclude records past their retention deadline. Cleanup removes expired
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
The proposed path is:

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

## Future implementation validation

Implementation must demonstrate the following behavior before claiming support:

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

These are acceptance requirements, not tests already run or capabilities already
implemented. [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#event-collection)
supports isolating logging failures from application operation; its
[verification guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#verification)
also covers failure injection and limiting logging-related resource exhaustion.
