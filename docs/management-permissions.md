# Management scopes and actions

This document records the agreed design for MemberID management scopes, CRUD
actions, and wildcard matching. It complements the [Member role definitions](roles.md)
and the [catalog of existing operations](management-operation-catalog.md).
The scope/action parser and evaluator implement these rules. Core management
reads, organization/Member/provider writes and administrator assignments use the shared
check; the [catalog rollout status](management-operation-catalog.md#current-enforcement)
identifies the remaining operation migrations. The [console access
matrix](console.md#first-version-access-model) and [private management API](management-api.md)
continue to describe the available interfaces and their current access contracts.

MemberID authorizes management of its own identities and configuration. Consuming
applications retain their business roles, resources, and authorization decisions.
Management scope here means the resources to which authority applies; it is
separate from the OAuth/OIDC `scope` parameter and introduces no new token claims
or credential type.

## Ownership and scope levels

The ownership model has three levels:

| Level | Coverage |
| --- | --- |
| Platform | The whole MemberID installation, including global resources, the system organization, ordinary organizations, and their Members. |
| Organization | One organization and resources owned by it, including its Members. |
| Member | One concrete Member and resources owned by that Member, such as its authentication bindings. |

These levels describe ownership boundaries. A scope selector can select an
individual object, a resource collection, or a set of paths within those
boundaries. Collections such as `roleAssignments` are not additional identity
levels. Scope coverage alone grants no operation; the permitted actions must
also match.

Platform administrators have installation-wide management responsibility.
Organization administrators are limited to their own ordinary organization.
Ordinary Members have no administrative authority; any supported account
self-service is limited to the authenticated Member and its explicitly allowed
operations. It does not require a baseline role-assignment record. The operation
catalog maps existing functionality to these roles without enabling new APIs.

The system organization, `org_system`, is one organization, not the platform
scope. The selector `organizations/*/**` includes it, along with all ordinary
organizations and their descendants, but excludes the top-level organization
collection and unrelated global platform resources. Selecting only ordinary
organizations requires an explicit distinction; wildcard matching does not
silently exclude the system organization. The role rules still prohibit
organization administrators in `org_system`.

A Member's identity remains organization-specific. A contextual reference to
"self" resolves to the authenticated Member's actual ID and owning organization;
it is not a fourth scope level or a stored wildcard. A different Member belonging
to the same natural person receives no implied access.

Coverage follows ownership, never arbitrary references. For example, a shared
phone authentication factor can have bindings to Members in different
organizations. Authority over one Member's binding does not grant authority over
the shared factor or other bindings. Global signing keys, installation-wide
client registrations, and shared SSO state are not Member-owned descendants
merely because a Member uses them.

## Resource paths and serialization

A permission description pairs a resource selector with actions:

```json
{
  "scope": {
    "pattern": "organizations/{organizationId}/roleAssignments/**"
  },
  "actions": ["create", "read", "delete"]
}
```

This is the design representation of permission semantics, not an implemented
API request, database record, or complete role-assignment schema. Values in braces
are documentation placeholders for concrete opaque IDs; they are not runtime
variables or pattern operators. Collection names use lowerCamelCase. Resource
types belong in the scope path; actions use operation names.

Paths consist of nonempty, case-sensitive segments separated by `/`, without a
leading or trailing slash. Collection names and complete resource IDs occupy
separate segments. IDs retain their existing formats and are not shortened or
split into pattern components. Paths identify authorization targets; they do not
specify HTTP endpoint URLs.

| Path or pattern | Meaning |
| --- | --- |
| `**` | All registered management targets in the installation, including global resources. |
| `organizations` | The organization collection itself. |
| `organizations/{organizationId}` | One organization itself. |
| `organizations/{organizationId}/**` | That organization and all of its owned descendants. |
| `organizations/{organizationId}/members` | That organization's Member collection. |
| `organizations/{organizationId}/members/{memberId}` | One Member itself. |
| `organizations/{organizationId}/members/{memberId}/**` | That Member and its owned descendants. |
| `organizations/{organizationId}/roleAssignments` | That organization's role-assignment collection. |
| `organizations/{organizationId}/roleAssignments/{roleAssignmentId}` | One role assignment in that organization. |

The server resolves target paths from authoritative resource ownership. A caller
cannot put an existing resource under another organization by supplying a
different path. Individual resource reads and mutations must resolve the actual
target; creation must resolve its actual destination collection.

Use `scope.pattern` for both exact paths and patterns. A missing, null, or empty
scope or pattern is invalid, never an implicit platform grant. This design does
not add a `recursive` flag: descendant selection is explicit in the pattern.

## CRUD actions and read normalization

Prefer these four predicates:

| Action | Meaning |
| --- | --- |
| `create` | Create a resource in its destination collection. |
| `read` | Read resources; equivalent to allowing both `list` and `get`. |
| `update` | Modify an existing resource's ordinary properties; independently authorized changes use a qualified action. |
| `delete` | Delete an existing resource. |

Use `read` when both `list` and `get` are allowed. Keep `list` or `get` separately
when access needs to distinguish collection browsing from individual retrieval.
Canonical descriptions replace `list` plus `get` with `read` and remove redundant
`list` or `get` entries alongside `read`. This normalization applies within the
same permission description and scope; it must not combine a `list` grant in one
scope with a `get` grant in another scope.

The same rule applies within an action namespace: `settings.read` expands to
`settings.list` and `settings.get`, not unqualified `list` or `get`. Expand a
terminal `read` segment before matching action patterns, so `**.read` permits
registered `list` and `get` operations at any namespace depth. Normalize a pair
only when its namespace or namespace pattern and its scope are identical.
This does not register new namespaced read operations or automatically split
fields out of an existing response representation.

`read` is an explicit semantic shorthand, not a wildcard or string-matching rule.
It does not include subscriptions, exports, or other separately defined
operations. Additional predicates may be introduced for operations that need
independent authorization and do not fit CRUD. A resource supports only the
operations defined for it; listing CRUD predicates does not create unsupported
endpoints or override lifecycle restrictions. Administrator assignment creation
uses `create`, and revocation uses `delete`; this catalog defines no in-place
assignment `update`. A semantic deletion need not erase historical records.

## Qualified actions and combined requests

Action names consist of nonempty, case-sensitive segments separated by `.`,
without a leading or trailing dot. Prefer a CRUD predicate as the final segment;
an optional namespace identifies a separately authorized operation on the same
resource. Resource types remain in the scope path: use `status.update` on an
organization target, not `organization.update` as its authorization action.
Existing command names and audit event labels need not change.

`status.update` covers organization enable/disable, Member manual block/unblock,
and identity-provider enable/disable. These remain operations on the organization,
Member, or provider itself, not separate status resources. Ordinary `update`
does not include them. Reads retain their documented representations, including
status fields; this distinction introduces no `status.read` operation.

For an update, derive the required actions from the explicitly submitted mutable
fields, even when a submitted value equals its current value. An organization
request containing both `name` and `status` requires both `update` and
`status.update` on that organization. A Member request containing `displayName`
and `manualBlocked` has the analogous requirements. Every required target/action
pair must be allowed; reject the whole operation if any pair is denied. Each
pair may be satisfied by an applicable permission, without borrowing scope and
action from unrelated permissions.

Immutable identifiers, concurrency revisions, and server-generated defaults do
not themselves add update actions. Creation checks `create` on the destination
collection and the resource's creation constraints; it does not require update
permission on a nonexistent object. In particular, a provider's accepted initial
`enabled` value is part of creation. Subsequent changes use `status.update`.

The catalog records which fields belong to each action. It does not automatically
create an action for every field. The organization administrator's inability to
change organization status is represented by its permissions, not a separate
role-name exception after permission evaluation. Identity eligibility, valid
delegation, and resource lifecycle constraints still apply.

## Wildcard grammar

Scope patterns match complete resource paths by segment:

- A literal segment matches only the identical segment.
- `*` matches exactly one nonempty segment and never crosses `/`.
- `**` matches zero or more complete segments.
- Matching is case-sensitive and anchored to the entire path, with no implicit
  prefix or descendant matching.
- A wildcard must occupy a whole segment. Partial globs such as `org_*` and
  `role*`, empty segments, `?`, regular expressions, and other pattern operators
  are invalid.
- Each pattern may contain at most one `**` segment. Multiple `*` segments are
  allowed.

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `organizations/*` | Each organization itself. | `organizations`; Member or role-assignment paths. |
| `organizations/**` | The organization collection itself and all paths below it. | Global resources outside that path. |
| `organizations/*/roleAssignments` | Each organization's role-assignment collection. | Individual role assignments. |
| `organizations/*/roleAssignments/*` | Individual role assignments in any organization. | The collection itself or deeper paths. |
| `organizations/*/roleAssignments/**` | Each role-assignment collection and all paths below it. | Member paths or unrelated global resources. |
| `organizations/{organizationId}/**/roleAssignments` | That organization's role-assignment collection and any registered descendant collection with the same final segment. | Paths ending in an individual assignment ID. |

The zero-segment case is intentional: `organizations/{organizationId}/**` matches
the organization itself as well as descendants. `*` and `**` are not synonyms;
`*` alone matches only a one-segment target.

Action patterns use the same whole-segment rules, with `.` instead of `/` as the
separator. A literal matches exactly, `*` matches one nonempty segment, and `**`
matches zero or more segments. Matching is anchored and case-sensitive, each
pattern permits at most one `**`, and partial globs such as `re*` or `status*`
are invalid. Empty segments and alternate separators are invalid.

| Action or pattern | Matches | Does not match |
| --- | --- | --- |
| `update` | Ordinary `update`. | `status.update`. |
| `status.update` | Exactly `status.update`. | Ordinary `update`; other namespaces. |
| `*.update` | `status.update` and other one-prefix update actions. | Ordinary `update`; actions with two or more prefix segments. |
| `**.update` | Ordinary `update` and update actions at any namespace depth. | `create`, `delete`, or read operations. |
| `*` | Every registered single-segment action. | `status.update` or any other multi-segment action. |
| `**` | Every registered action at any depth. | Unregistered or unsupported operations. |

For grammar illustration, `security.credentials.update` would match
`**.update`, but not `*.update`; that example does not register an operation.
The zero-segment case makes `**.update` match ordinary `update` without requiring
a leading dot. `*` and `**` are no longer interchangeable for actions. Use `**`
when intentionally granting all actions, including namespaced operations.

Patterns apply dynamically to future matching resources and supported, enabled
operations. Consequently, action `*` includes future single-segment predicates,
not only CRUD; `**` also includes future namespaced actions, and `**.update`
includes future update namespaces. An explicit action list does not acquire
newly named operations. Patterns never create resources, enable unsupported
operations, or turn arbitrary strings into
valid authorization targets. A valid collection can be empty; a selector's
current lack of resource instances does not prevent it from covering future
instances.

## Collections and individual operations

Authorize `create` and `list` against the collection path. Authorize `get`,
`update`, `status.update`, and `delete` against the individual resource path.
For example:

| Operation | Target path |
| --- | --- |
| Create or list role assignments | `organizations/{organizationId}/roleAssignments` |
| Get or delete one role assignment | `organizations/{organizationId}/roleAssignments/{roleAssignmentId}` |

The permission example above covers both targets because its trailing `**`
matches the collection itself and its descendants. A selector ending in
`roleAssignments/*` covers individual assignments but does not authorize
creation or collection listing. An exact collection selector permits its allowed
collection operations but does not authorize direct operations on the entries.
In particular, `read` on that exact collection allows `list`; its `get` component
still requires scope coverage of an individual resource.

`list` authorizes the collection's defined listing representation; it does not
require or imply separate `get` authority for each returned record. Enforce
organization boundaries and any applicable record-visibility constraints before
filtering, counting, and pagination. A resource-specific `get` grant does not
automatically authorize browsing its parent collection. Creating a resource does
not itself grant subsequent access; existing selectors determine coverage of the
new resource.

## Authorization boundaries and remaining work

An allowed operation must have applicable authority whose scope selector covers
the target and whose actions allow the operation. Do not combine a matching
scope from one permission with an unrelated action grant from another. Matching
also remains subject to current authentication, identity eligibility, role
eligibility, and operation-specific constraints.

The [token and server-side authorization design](authorization-boundaries.md)
defines when those facts are checked. MemberID keeps management authority on the
server and authorizes each operation before execution. An already authorized
short operation may finish after a concurrent revocation; subsequent independent
operations need a new decision. A matching scope or token claim does not reserve
authority for an entire future workflow.

In particular, creating a role assignment requires checking the intended
recipient, role, and scope of the authority being granted, not just the path
where the assignment would be stored. An organization administrator cannot grant
a platform role, grant access in another organization, or assign authority to a
foreign Member. Wildcards do not bypass these restrictions or the existing
[administrator-availability safeguards](administration.md#availability-and-audit).

The [operation catalog](management-operation-catalog.md) supplies mappings for
existing functionality and identifies operator-only contracts. Assignment IDs
and API serialization, persistence schema, management API changes, additional
capabilities, and the remaining enforcement migrations remain follow-up work.
Built-in role permissions are defined in code, with current administrator
assignments read from the existing store for each operation. This implementation
does not introduce custom roles, exclusion or deny rules, an application-authorization
service, or changes to the database schema, token contents, or OIDC behavior.
