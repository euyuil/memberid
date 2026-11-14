# Management operation catalog

This catalog maps existing functionality to the agreed [roles](roles.md),
[scope/action rules](management-permissions.md), and [authorization
boundaries](authorization-boundaries.md). The mappings are design contracts for
the shared evaluator. Adoption is incremental as recorded below; existing
administrator assignments, identity eligibility and lifecycle constraints remain
authoritative. The catalog does not itself add endpoints, token claims, or schema.

The catalog covers the console, account linking, and the corresponding private
management API and operator commands. Protocol login, token issuance/renewal,
provider callbacks for ordinary login, process setup, signing keys, and client
registration keep their separate documented contracts. They are not implicitly
Member management operations.

## Current enforcement

The scope/action parser supports qualified CRUD actions, read expansion and the
documented whole-segment wildcards. The evaluator requires every target/action
pair and rejects unsupported operations even for platform-wide permissions.
Built-in role permissions live in code; assignments remain in `administrators`.

| Operations | Enforcement status |
| --- | --- |
| O5-O6: organization updates | Shared scope/action checks at the existing transactional authorization point, including explicitly submitted unchanged status fields. Private/CLI updates retain their installation-only entry contract. |
| Remaining catalog operations | Existing operation-specific authorization; migration to the shared evaluator remains follow-up work. |

The pure evaluator has no permission lock or cross-request allow cache. Its
database-backed tests cover completion after revocation of an admitted bounded
update and denial of the next decision. Existing lifecycle locks remain in place.

## Reading the catalog

- `O` abbreviates `organizations/{organizationId}` and `M` abbreviates
  `organizations/{organizationId}/members/{memberId}` **in this document only**.
  Expand them when constructing a target. Braces denote documentation
  placeholders, not runtime variables or pattern syntax.
- **Platform** means an eligible, explicitly assigned system Member;
  **organization admin** means an eligible administrator of that same ordinary
  organization. **Self** means the concrete Member selected through its current
  eligible authentication binding, not every identity of the same natural person.
- **Manager** means the private API's installation credential;
  **operator** means trusted CLI access. Neither is another Member role or a
  way to impersonate a Member. Operator-only interfaces remain unavailable to
  ordinary OIDC tokens, including tokens for platform administrators.
- Operation tables use `list` and `get` to identify their different targets.
  Permission descriptions allowing both at the same scope prefer `read`.
- An entry can require several target/action pairs. All must be authorized before
  the bounded operation executes. A semantic `delete` can revoke access while
  preserving historical identity or evidence.

### Authorization checkpoints

| Checkpoint | Current behavior and intended boundary |
| --- | --- |
| Console read | Resolve the current console session, grant and eligible administrator; constrain the requested organization or global view before querying. The shared evaluator will check the listed read targets here. |
| Console write | Request-entry authentication/scope/CSRF checks precede the service transaction. Its current `authorizeManagement` check is the authoritative operation boundary. Provider configuration reaches this boundary after optional upstream credential verification and before saving. |
| Account view | Resolve the SSO session and explicitly selected eligible Member before rendering the account view. An administrator assignment is not required. |
| Account commit | After fresh target-factor verification, validate the current session, request, source binding and Member in the transaction that commits the binding. Opening the page or starting verification does not reserve authority for this later step. |
| Private API / CLI | Authenticate the installation credential on every private request, or use the trusted operator entry point. Store transactions still enforce resource and lifecycle constraints. There is no delegated Member policy evaluator on these paths today. |

After an operation passes its authoritative check, the [short-operation
completion rule](authorization-boundaries.md#revocation-and-operations-in-progress)
applies. Existing locks and last-administrator safeguards remain. These mappings
do not remove identity checks from an unfinished multi-request verification flow.

## Resource targets

These are authorization paths, not new HTTP URLs or storage tables. Ownership
comes from stored relationships, not caller-supplied path strings.

| Target | Ownership and meaning |
| --- | --- |
| `organizations` | Platform organization collection; creation and platform listing. |
| `O` | One organization; ordinary properties and status share this target. |
| `O/members`, `M` | Member collection and individual Member. |
| `M/bindings`, `M/bindings/{bindingId}` | Explicit Member bindings; no authority over the shared factor or its other bindings. |
| `O/roleAssignments`, `O/roleAssignments/{roleAssignmentId}` | Administrator assignments. The current store keys them by Member; the placeholder specifies the logical target, not a new public ID format or API. |
| `O/providers` | Combined directory of configured provider applications. |
| `O/providers/{providerType}` | Typed destination collection, currently `dingtalk` or `feishu`. |
| `O/providers/{providerType}/{providerId}` | One provider application. Preserve its namespace ID and resolve it with its type and organization. |
| `O/managementEvents` | Organization-owned management history collection, optionally filtered by Member. |
| `memberDirectory` | Platform aggregate Member directory view. Listing this view does not grant individual Member mutations. |
| `managementEvents` | Platform aggregate management history view. It does not make events Member-owned merely because they reference a Member. |
| `authenticationFactors/{factorId}` | Global factor inspected through an operator interface; not a descendant of any one Member. |

The two aggregate views are authorization targets for existing queries, not
additional Member identities or copies of records. An organization administrator
uses its own organization collections; it does not receive either global view.
Provider types group collections within organization ownership and do not add an
identity ownership level.

## Member-role permissions

The matrix preserves current Member-facing behavior. Availability through an
operator interface is recorded separately and does not grant that interface to a
Member. All administrative entries require current identity/session eligibility.

| Operation family | Platform administrator | Organization administrator | Ordinary Member |
| --- | --- | --- | --- |
| Read organizations | Global collection and any organization | Own organization only | Account-page organization context only |
| Create organization | `create` on `organizations` | No | No |
| Rename organization | `update` on any `O` | `update` on own `O` | No |
| Enable/disable organization | `status.update` on ordinary `O` | No | No |
| List/get/create Members | Any organization's collection or Member; global directory | Own organization's collection or Member | Account-page self context only; no management directory |
| Rename Member | `update` on any `M` | `update` on own organization's `M` | No self-service rename interface |
| Manually block/unblock Member | `status.update` on any `M` | `status.update` on own organization's `M` | No |
| Read bindings and assignment lists | Any organization | Own organization | No administrative list; only the account flow's necessary source context |
| Grant/revoke administrator | `create` / `delete` for assignments in any organization | `create` / `delete` for assignments in own ordinary organization | No |
| List/create/configure providers | Any supported organization: `list`, `create`, `update`, `status.update` on the relevant targets | Same operations within own organization | No |
| Read management events | Global view or any organization's collection | Own organization's collection | No |
| Self-service phone/DingTalk binding | As Self, with the same verification requirements | As Self, with the same verification requirements | `create` on selected Self's binding collection, through the account flow |

The status distinction is in permissions: organization administrators receive
`status.update` for their Members and providers, not for `O` itself. Do not grant
them `status.update` or `**.update` indiscriminately over `O/**`; that would also
cover organization status. Broad scope coverage can instead be paired with
narrow actions, and status authority scoped to the applicable resource kinds.
No additional role-name check is needed after those permission decisions.

System organization membership grants nothing by itself, and there is no system
organization administrator role. Platform authority does not override the rule
that `org_system` cannot be disabled. Provider support restrictions also remain:
Feishu configuration and binding in the system organization are not supported.

## Organization and Member operations

Console route prefixes below are literal `/api`; substitute the expanded `O`
and `M`. Source and test references are indexed by row ID below.

| ID | Existing entry and business operation | Target | Action | Member authority | Conditions and checkpoint |
| --- | --- | --- | --- | --- | --- |
| O1 | `GET /api/organizations`: platform directory | `organizations` | `list` | Platform | Console read; bounded pagination. |
| O2 | Same route: organization admin navigation | Own `O` | `get` | Organization admin | Console read; existing code reads one organization and wraps it as a list. This is not a grant to browse the root collection. |
| O3 | `GET /api/O`: organization detail | `O` | `get` | Platform; own organization admin | Console read; resolve actual organization. |
| O4 | `POST /api/organizations`: create | `organizations` | `create` | Platform | Console write; reserved system ID cannot be created; initial enabled state is server-generated. |
| O5 | `PATCH /api/O` with `name` | `O` | `update` | Platform; own organization admin | Console write; valid name; identity remains stable. |
| O6 | Same PATCH with `status` | `O` | `status.update` | Platform | Console write; cannot disable system organization. Combined `name` and `status` require O5 and O6. |
| M1 | `GET /api/O/members`: Member directory | `O/members`; `O/roleAssignments` | `list` on both | Platform; own organization admin | Console read; filter before pagination; current response includes a separate organization-wide `administratorIds` list. |
| M2 | `GET /api/members`: global Member directory | `memberDirectory` | `list` | Platform | Console read; defined rows include organization name and administrator flag, not arbitrary related objects. |
| M3 | `GET /api/M`: composite Member detail | `M`; `M/bindings`; `O/roleAssignments` | `get`; `list`; `list` | Platform; own organization admin | Console read; current endpoint returns all three components. Require all pairs before fetching the composite response. |
| M4 | `POST /api/O/members`: create Member | `O/members` | `create` | Platform; own organization admin | Console write; no administrator assignment or verified binding is created. System Members require platform access. |
| M5 | `PATCH /api/M` with `displayName` | `M` | `update` | Platform; own organization admin | Console write; organization-bound Member lookup and valid display name. |
| M6 | Same PATCH with `manualBlocked` | `M` | `status.update` | Platform; own organization admin | Console write; preserve administrator availability. Clearing manual block does not clear external departure. Combined fields require M5 and M6. |

The action requirements describe the future evaluator; the composite reads
currently rely on broad administrator/organization checks. They do not authorize
partial responses by silently dropping a denied component. Listing a defined
representation does not require separate `get` checks on every returned row.
The administrator flag inside a directory row is part of that representation;
the separate full `administratorIds` array is an assignment collection read.

The corresponding private entries all require Manager and use the private
checkpoint. Their resource/action mapping follows the same business operations,
with the following response differences:

| Private entry | Mapping | Response or action requirements |
| --- | --- | --- |
| `GET /v1/organizations` | O1 | `list` on `organizations`. |
| `GET /v1/O` | O3 | `get` on `O`. |
| `POST /v1/organizations` | O4 | `create` on `organizations`. |
| `PATCH /v1/O` | O5/O6 | `update`, `status.update`, or both, according to submitted fields. |
| `GET /v1/O/members` | M1 without assignment bundle | `list` on `O/members`; no assignment-list requirement. |
| `GET /v1/M` | M3 without binding/assignment bundles | `get` on `M`; no binding-list or assignment-list requirement. |
| `POST /v1/O/members` | M4 | `create` on `O/members`. |
| `PATCH /v1/M` | M5/M6 | `update`, `status.update`, or both, according to submitted fields. |

`memberid organization create`, `member create`, and `member block|unblock`
expose O4, M4, and M6 to Operator through the operator checkpoint. These
interfaces do not acquire console authentication or delegated Member permissions.

## Assignments, providers, bindings, and audit

| ID | Existing entry and business operation | Target | Action | Authority | Conditions and checkpoint |
| --- | --- | --- | --- | --- | --- |
| A1 | Assignment IDs embedded in console Member list/detail | `O/roleAssignments` | `list` | Platform; own organization admin | Console read; this is the explicit second/third requirement in M1/M3. No standalone role-assignment API exists. |
| A2 | `PUT /api/M/administrator`, `enabled=true`; `administrator grant` CLI | `O/roleAssignments` | `create` | Platform; own organization admin; Operator via CLI | Console write or operator checkpoint; eligible recipient belongs to O; assigned role/scope cannot escape that organization or grant platform authority from an ordinary organization. Existing assignment is an idempotent no-op. |
| A3 | Same PUT with `enabled=false`; `administrator revoke` CLI | Resolved assignment in `O/roleAssignments/{roleAssignmentId}` | `delete` | Same as A2 | Same checkpoints; preserve last available administrator. Resolve the assignment by organization and Member; retain current no-op behavior if absent. No in-place assignment `update` is defined. |
| P1 | `GET /api/O/providers`: combined provider directory | `O/providers` | `list` | Platform; own organization admin | Console read; metadata and callback URLs, never client secrets. |
| P2 | `POST /api/O/providers/{kind}`: configure new provider | `O/providers/{providerType}` | `create` | Platform; own organization admin | Console write after credential verification; enabled organization, valid provider type/identity and revision; initial `enabled` is part of creation. |
| P3 | `PUT /api/O/providers/{kind}/{providerId}`: name or credential configuration | `O/providers/{providerType}/{providerId}` | `update` | Platform; own organization admin | Console write; immutable type/client/tenant identity; expected revision; verify a supplied secret. Empty secret preserves the old credential. |
| P4 | Same PUT: explicitly submitted `enabled` | Same provider target | `status.update` | Same as P3 | Console write; disabling must preserve administrator availability. Current request shape requires both `displayName` and `enabled`, so updates require P3 and P4 even if one value is unchanged. |
| B1 | Bindings in M3; `GET /v1/M/bindings` | `M/bindings` | `list` | Console: Platform or own organization admin; private: Manager | Console read or private checkpoint; includes active and revoked records, not global factor administration. |
| B2 | `POST /v1/M/bindings`; `member bind-factor` CLI | `M/bindings` | `create` | Manager / Operator only | Existing active verified factor, matching organization/provider namespace, correct Member and unoccupied slot. No contact-based proof or implicit identity merge. |
| B3 | `DELETE /v1/M/bindings/{factorId}` | Resolved `M/bindings/{bindingId}` | `delete` | Manager only | Private checkpoint; resolve factor selector to this Member's stored binding ID, preserve administrator availability, retain revoked record. Repetition cannot restore or transfer it. |
| B4 | `GET /v1/factors/{factorId}`; `factor inspect --phone` CLI | `authenticationFactors/{factorId}` | `get` | Manager / Operator only | Existing factor lookup; neither route creates or verifies a factor. A Member binding grant does not imply this global read. |
| E1 | `GET /api/events` for one organization, optionally one Member | `O/managementEvents` | `list` | Platform; own organization admin | Console read; organization restriction precedes Member filtering and pagination. Member reference does not change ownership. |
| E2 | Same route without organization restriction | `managementEvents` | `list` | Platform | Console read; organization admin requests are always constrained to their own O, never this global view. |

`kind` in the existing provider routes supplies the canonical `providerType`;
the stored namespace supplies `providerId`. The directory is a combined view,
whereas creation selects a typed collection. There is no console provider-delete
or individual provider-get endpoint. A private DingTalk inspection is recorded
separately below. Ordinary `update` does not cover P4, and neither status action
permits forging upstream `authorizationStatus` or directory departure evidence.

## Account linking and workflow steps

| ID | Existing entry | Target and action | Authority and conditions | Checkpoint |
| --- | --- | --- | --- | --- |
| S1 | `GET /account/link/phone` or `/account/link/dingtalk` | Selected `M`, `get` of the fixed account-page context | Self, including administrators acting for themselves; resolve Member through the session's eligible factor binding. No administrative Member, binding, or assignment directory access follows. | Account view; an older session can view but cannot commit a new link. |
| S2 | Phone page POST that successfully verifies and links | `M/bindings`, `create` | Self; fresh source authentication and fresh SMS proof, original source binding, valid browser/form/client context, no occupied or revoked slot replacement. | Account commit; consume proof, create/check factor, create binding and complete request atomically. |
| S3 | DingTalk verification completed at `GET /account/dingtalk/callback` | `M/bindings`, `create` | Self; same source/context requirements and fresh verified provider identity in the selected organization's namespace. | Account commit after provider I/O; no partial factor or binding on failure. |
| S4 | Phone send/cancel and DingTalk start/cancel form submissions | Verification workflow state; no additional management action | Same bound account request, CSRF and documented freshness rules. Sending a challenge, consuming callback state, or canceling does not grant binding authority. | Validate each step; eventual creation still requires S2/S3. |

The source authentication must still be within the existing five-minute limit
when committing. Current session or binding revocation, Member ineligibility,
request cancellation, or changed provider/return context can reject a flow that
started earlier. This is consistent with the short-operation rule: the initial
page or verification start is not the final binding authorization point.
The account-page representation includes the selected Member, organization and
necessary source context; it does not expose the console detail bundle. Self
does not include another independently owned Member merely through matching
contact attributes. No self-service unbind, rename, or Feishu-link operation is
introduced. Successful linking preserves the subject, original authentication
time, session, and grant lifetimes.

## Private and operator workflow contracts

All private routes require Manager on every attempt; CLI entries require Operator.
The entries below account for compound or auxiliary operations without inventing
delegated Member APIs. Read-only POST queries are reads, not resource creation.

| ID | Existing entry | Resource/action mapping or workflow classification | Constraints and checkpoint |
| --- | --- | --- | --- |
| I1 | `GET /v1/O/dingtalk-application`; `dingtalk inspect` CLI | `get` on the resolved `O/providers/dingtalk/{providerId}` | Private/operator checkpoint. Omitted provider selector must resolve unambiguously; multiple sources are a conflict. |
| I2 | `PUT /v1/O/dingtalk-application`; `dingtalk configure` CLI | `create` on typed provider collection for initial configuration, otherwise `update` on resolved provider | Current operator shape sets credentials and revision, not `displayName` or `enabled`. Existing enabled state is retained; a new application defaults to enabled. Credential verification and revision/lifecycle checks still apply. |
| I3 | `PUT /v1/M/updates/{updateId}`; GET at the same path | Initial update requires M5/M6 according to submitted fields. GET reads the immutable receipt at `M/updates/{updateId}`. | Private checkpoint; original update and receipt commit atomically. Exact accepted PUT replay returns the receipt without changing current Member state. Conflicting reuse is rejected. Receipt recording is an operation effect, not an independently editable grant. |
| I4 | `POST /v1/organization-enrollments`; `GET /v1/O/enrollment` | Compound provisioning: `create` organization, initial Member and explicit binding; GET reads the receipt at `O/enrollment` | Private checkpoint; new non-system organization and Member, already verified active phone factor, atomic creation. Replays return historical acceptance, not a new authentication or permission. |
| I5 | `POST /v1/eligibility`; `POST /v1/O/member-eligibility` | Current identity-fact reads for the supplied binding tuple or bounded Member candidates; separate operator query contracts | Private checkpoint; existing input limits, organization isolation and false/empty results remain. These are not policy-decision APIs and create no authentication evidence or role grants. |
| I6 | `dingtalk allow-system-member` / `cancel-system-member` CLI | Prepare, replace, or cancel a pending system admission workflow; not an administrator assignment or completed binding | Operator checkpoint; existing system Member, exact provider identity, active configured source, no occupied DingTalk binding; approval expires and requires later fresh provider verification. |
| I7 | `dingtalk sync` / `reconcile` CLI; related background processing | Refresh authoritative provider and directory observations; not a Member's manual `status.update` | Existing source credentials, revision and verification contracts. Confirmed external loss of eligibility remains authoritative even if no administrator remains. |

Receipts retain their existing immutable replay contracts. This catalog does not
introduce receipt listing, editing, deletion, or a Member-delegated retry API.
I5-I7 are explicitly retained query/workflow contracts, not new registered Member
actions. Their future delegation, if needed, requires its own design.

Console `/auth/login`, `/auth/callback`, `/api/session`, and `/api/logout` are
session lifecycle endpoints under the [console contract](console.md#sessions-requests-and-audit).
Static assets, callbacks and private `/healthz` are also accounted for outside
the resource action matrix. Private health still requires its credential.
Writing a successful audit event is an effect of an authorized operation, not an
extra `create` permission that administrators must hold on management history.

## Implementation and test evidence

These links identify existing operation code and checks. [Evaluator tests](../internal/authorization/permissions_test.go)
cover scope/action semantics; [organization authorization tests](../internal/identity/authorization_integration_test.go)
cover the first migrated operations and the revocation boundary. Other linked
tests remain baselines, not proof that every catalog operation is migrated.

| Rows | Implementation | Existing automated checks |
| --- | --- | --- |
| O1-O6, M1-M6, E1-E2 | [Console routes and handlers](../internal/console/http.go), [management queries](../internal/identity/management.go), [transactional mutations and events](../internal/identity/administrators.go) | [Console integration](../internal/oidcprovider/console_integration_test.go): organization scope, global Member directory, filtered pagination, platform audit, ordinary-Member rejection, and next-request revocation. |
| A1-A3 and availability constraints | [Administrator store](../internal/identity/administrators.go), [administrator CLI](../cmd/memberid/administrators.go) | [Administrator integration](../internal/identity/administrators_integration_test.go): forged actor fields cannot widen scope; system reservation, current grant checks, concurrent last-administrator removal, and system admission. |
| P1-P4, I1-I2 | [Provider console routes](../internal/console/providers.go), [provider management checks](../internal/identity/providers.go), [DingTalk configuration](../internal/identity/dingtalk_applications.go), [Feishu configuration](../internal/identity/feishu.go) | [Provider console and Feishu integration](../internal/oidcprovider/feishu_integration_test.go), [private DingTalk integration](../internal/management/dingtalk_integration_test.go), [DingTalk CLI integration](../cmd/memberid/dingtalk_integration_test.go). |
| B1-B4 and ordinary private organization/Member routes | [Private routes](../internal/management/http.go), [identity store](../internal/identity/store.go), [CLI creation/blocking](../cmd/memberid/manage.go), [binding CLI](../cmd/memberid/bindings.go) | [Private HTTP integration](../internal/management/http_integration_test.go), [identity-store integration](../internal/identity/store_integration_test.go), [CLI integration](../cmd/memberid/manage_integration_test.go), [credential separation](../internal/oidcprovider/management_integration_test.go). |
| S1-S4 | [Account selection and DingTalk linking](../internal/oidcprovider/account.go), [phone account flow](../internal/oidcprovider/account_phone.go), [phone binding transaction](../internal/identity/phone_link.go) | [DingTalk account integration](../internal/oidcprovider/account_integration_test.go), [phone account integration](../internal/oidcprovider/account_phone_integration_test.go): freshness, identity changes during verification, replay, cancellation, binding conflicts, organization independence and unchanged grants. |
| I3 | [Receipt HTTP operations](../internal/management/member_updates.go), [immutable update store](../internal/identity/member_updates.go) | [Receipt HTTP integration](../internal/management/member_updates_integration_test.go), [concurrent updates and rollback](../internal/identity/member_updates_integration_test.go). |
| I4-I5 | [Enrollment store](../internal/identity/enrollment.go), [candidate eligibility](../internal/management/eligibility.go), [identity eligibility](../internal/identity/eligibility.go) | [Enrollment HTTP integration](../internal/management/enrollment_integration_test.go), [enrollment transactions](../internal/identity/enrollment_integration_test.go), [eligibility HTTP integration](../internal/management/eligibility_integration_test.go). |
| I6-I7 | [System admission](../internal/identity/system_admission.go), [provider CLI](../cmd/memberid/dingtalk.go), [provider synchronization](../internal/identity/dingtalk_authorization.go), [directory reconciliation](../internal/identity/dingtalk_reconcile.go) | [System admission guards](../internal/identity/administrators_integration_test.go), [provider authorization](../internal/identity/dingtalk_authorization_integration_test.go), [directory reconciliation](../internal/identity/dingtalk_reconcile_integration_test.go). |

## Review and future enforcement acceptance

Documentation review must verify the following against the catalog and sources:

- Every console resource route, related private route and CLI command maps to a
  row or an explicitly classified workflow/session endpoint.
- Organization admin permissions cover Member/provider `status.update` but not
  organization `status.update`; neither system membership nor `O/**` by itself
  grants authority. Ordinary Members receive no administrative directory access.
- `update`, `*.update`, `**.update`, `*`, and `**` have the documented positive
  and negative matches. Read normalization stays within one scope and namespace.
- Creation/listing use collection targets; reads/updates/deletions use actual
  instance targets. Binding lookup uses the stored binding, not a factor ID
  disguised as a binding ID. Mixed-field and composite-read requirements are
  complete, and a denied pair rejects the whole operation.
- Member, provider and assignment changes retain eligibility and lifecycle
  constraints; manual status actions cannot erase external departure or fabricate
  provider verification. Self-service does not inherit operator privileges.

As each remaining operation is migrated, add focused tests for its mappings and the
authorization-before/after-revocation boundary alongside each affected operation.
Existing next-request revocation and last-administrator tests are useful baselines,
not proof of every migrated operation or all in-flight concurrency behavior. Exact
role-assignment API/ID representation, persistent permission storage, and new
capabilities remain separate implementation work. No deletion of organizations,
Members, or provider applications, custom roles, deny rules, or external policy
service is introduced here.
