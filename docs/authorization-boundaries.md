# Tokens and management authorization

This document records the agreed division between tokens and server-side
authorization, the timing of management authorization checks, and the effect of
revocation on operations already in progress. It complements the [Member
roles](roles.md) and [management scopes and actions](management-permissions.md).
The [operation catalog](management-operation-catalog.md) maps existing entry
points to targets, required actions, role coverage, and authorization checkpoints.
The [rollout status](management-operation-catalog.md#current-enforcement) distinguishes
implemented checks from remaining migrations. Token contents and API credential
contracts remain unchanged. The [OIDC profile](oidc.md), [console](console.md), and
[private management API](management-api.md) describe the current interfaces.

## Token and service responsibilities

JWT is a token format, not a choice between authentication and authorization.
An ID Token proves an authentication event to its intended client. An access
token authorizes access within its intended resource audience and OAuth grant;
the resource service validates it and makes the applicable authorization
decision. Access tokens can carry authorization claims: [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2.3)
defines scope and optional role, group, and entitlement claims. This reference
does not claim that MemberID implements that entire JWT profile.

MemberID uses the following division:

| Concern | Authority and responsibility |
| --- | --- |
| Login identity | The OIDC provider issues an ID Token for the client. The client validates it using the [OIDC ID Token rules](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation). An ID Token is not an API bearer credential. |
| API credential | An API that accepts OAuth access tokens validates the intended issuer, audience, token type, signature, lifetime, and applicable OAuth authorization claims. Successful token validation alone does not grant every operation. |
| MemberID management permissions | MemberID maintains its roles, role assignments, scope/action rules, and identity eligibility on the server. It authorizes each management operation using that state. |
| Consuming application permissions | The application or its chosen authorization service owns business roles, resource permissions, and decisions. A MemberID administrator does not automatically become an application administrator. |

For ordinary OIDC clients, `(iss, sub)` identifies the concrete independent
Member. A role or a set of claims describes attributes or authority of that
principal; it does not replace the principal's identity. `aud` identifies the
intended recipient, while authentication and lifetime claims describe the
token's authentication context and validity. The separately registered
[factor-subject mode](oidc.md#login-and-independent-subjects) remains an explicit
exception for authentication evidence before membership exists.

Access tokens may contain the identity and OAuth authorization information
needed by their documented audience. The OAuth/OIDC `scope` claim is distinct
from a management resource selector such as `scope.pattern`. MemberID does not
embed its management roles, assignments, or expanded scope/action permissions in
ordinary OIDC tokens as the source of management authority. A token is issued at
one point in time; changing a server-side assignment does not rewrite it.

The management authorization check can be an internal service function. This
decision does not require a network request to an external policy engine for
each operation or introduce a general application-authorization API. Consuming
applications retain their own policy even when they use MemberID's documented
eligibility queries for current identity facts. Eligibility and token
introspection do not decide whether an application business action is allowed.

## When management authorization is checked

Before a protected management operation starts executing, the server must:

1. Establish the authenticated principal through the interface's documented
   credential or session contract. For Member operations, resolve the concrete
   Member and applicable current identity and session eligibility.
2. Resolve the operation's actual target or destination collection and its
   ownership. Caller-provided paths cannot move a resource into another scope.
3. Evaluate the applicable current server-side authority against the scope,
   action, and operation-specific authorization constraints. For example,
   creating a role assignment checks the recipient and intended authority as
   well as access to the assignment collection.

An update can require several actions on the same target. For example, modifying
ordinary organization properties and its status requires both `update` and
`status.update`. Resolve all required pairs from the request before executing
the bounded operation; reject it in full if any required pair is denied.

This decision is the operation's authorization point. UI capability checks,
client-side permission lists, and an earlier request's successful decision do
not reserve permission for later operations. An optional request-entry check
can reject obvious failures early, but cannot substitute for the authorization
decision at the actual operation boundary. The design does not require two
identical checks for every request.

Once a short, bounded operation has been authorized, its internal steps may
finish under that decision. Authorization need not be repeated before each
database statement, and permissions need not remain unchanged until commit. The
decision covers only the work that was authorized; discovering an additional
target or action requires authorization for that additional work before it
executes. Initial permission checks cannot authorize an open-ended sequence of
future operations.

Each new independent request that performs a protected operation needs a new
server-side decision. Do not carry an allow result across requests through a
JWT, UI state, or session permission snapshot. Repeating a request does not
bypass authorization; any supported idempotency or receipt mechanism retains
its own documented behavior. Adding permission caching would require an
explicit freshness and revocation contract rather than silently weakening this
rule.

## Revocation and operations in progress

The default is to let an already authorized short operation complete. Removing
its actor's authority does not automatically cancel, roll back, or compensate
that operation. Subsequent authorization checks use the updated server-side
state and reject operations whose required authority has been removed.

For example, assume another eligible administrator remains:

1. Member A's request to update a Member profile passes its authoritative
   management authorization check.
2. Another administrator revokes Member A's administrator assignment.
3. The already authorized profile update may finish and commit its associated
   audit event.
4. Member A's next profile-update request is denied because the required
   assignment is absent.

If revocation is recorded before the operation's authorization check reads the
relevant state, that check must account for the revocation. Merely arriving at
the HTTP server before revocation does not establish permission. If the check
and revocation overlap, this design does not require a global ordering between
every management operation and every revocation. It intentionally permits a
write authorized earlier to commit after the revocation has completed.

The operation boundary matters:

| Work | Authorization and revocation rule |
| --- | --- |
| Internal steps of one bounded API operation | Authorize the operation before execution; it may finish after a concurrent revocation. |
| Several independent API requests in a client workflow | Authorize each operation separately. A later request may fail even when earlier requests succeeded. |
| Queued work, long-running bulk jobs, or workflows | Define submission and execution authority, any stage checks, and cancellation semantics explicitly before adding the feature. Do not assume that submission grants indefinite authority. |

Revoking a management role and revoking an OAuth grant are different operations.
Removing an administrator assignment removes management authority; it does not
itself delete the Member, log them out of every application, or remove their
independent business permissions. Conversely, a still-valid token does not
preserve a removed management assignment. The current [token revocation and
logout behavior](oidc.md#lifetimes-revocation-and-logout) continues to apply.
An offline token verifier cannot learn a server-side revocation merely by
checking the same token's signature. Online checks can observe current state at
their check boundary; they do not undo effects already produced.

## Transactions and business constraints

Database transactions keep related changes consistent, such as a Member update
and its successful audit event. A transaction alone does not define when
authorization must be valid or guarantee that revocation cancels work in
progress. An implementation may check authorization inside a transaction, but
this design does not require all writes to serialize with role revocation or
introduce a global permission lock.

Operation-specific data constraints still need appropriate concurrency control.
For example, two concurrent administrator removals must not bypass the existing
[last-available-administrator safeguard](administration.md#availability-and-audit).
Resource ownership, uniqueness, and lifecycle constraints must also remain
valid when changes are applied. Permission to finish an admitted operation is
not a guarantee of success if those constraints fail. Existing transactions and
locks remain in place; this document neither removes them nor weakens their
invariants.

## Current implementation and follow-up work

- OIDC ID Tokens and access tokens remain JWTs under the current profile;
  Refresh Tokens remain opaque credentials. No claim, issuer, subject,
  audience, or token-lifetime change is introduced here.
- The console authenticates through OIDC and gives the browser an opaque
  server-side session cookie. It currently rechecks administrator assignments,
  identity eligibility, and grant/session validity on API requests, and checks
  mutation authorization inside database transactions. This is an existing
  implementation choice, not a new requirement to check every internal step.
- The private management API retains its installation-wide credential and
  `installation-manager` principal. Trusted operator entry points retain their
  separate access contract; they do not acquire Member roles or begin accepting
  ordinary OIDC tokens through this design.
- The scope/action evaluator is implemented and enforces organization/Member
  writes, administrator assignments, provider configuration and management reads.
  Migration of the remaining catalog operations is follow-up work. No job system,
  cancellation protocol, or external policy-decision API is added.

Each remaining migration requires focused validation of its authorization and
revocation boundaries. Organization-update tests cover a decision made before
revocation, completion of the admitted update, and rejection of the next decision;
they do not establish end-to-end guarantees for unrelated workflows.
