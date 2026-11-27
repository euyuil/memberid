# Administration console

The console is a separate HTTP process in the same MemberID executable. Its React/shadcn UI and session API share one origin. It signs in through this installation's standard OIDC Authorization Code flow with PKCE S256. The installation management credential is never sent to a browser.

## Production hostnames

Use two HTTPS hostnames for a production deployment that includes the browser console. Run both processes from the same MemberID release. They can share a host, installation directory, and PostgreSQL database.

| Hostname example | Process and internal port | Audience |
| --- | --- | --- |
| `auth.example.invalid` | `memberid serve` on port 8080 | Users and OIDC clients. This is the issuer, and it serves sign-in, discovery, and other OIDC endpoints. |
| `admin.example.invalid` | `memberid serve-console` on port 8082 | Administrators. This serves the console UI, its same-origin API, and the OIDC callback. |

A single HTTPS reverse proxy can listen on port 443 for both hostnames. Route requests by hostname to the corresponding listener and preserve the configured HTTPS origins. Keep the backend ports reachable only on loopback or the private network used by the proxy. Set the console hostname's access policy at the proxy or network layer, such as requiring VPN access for administrators. Keep the issuer reachable by user browsers, relying parties, and the console process. If you use `serve-management` for installation-wide integrations, expose it only to trusted callers on a private listener.

Administrators start at the console hostname. The browser goes to the issuer to authenticate and returns to the console's registered `/auth/callback` URL to establish the console session. Choose the issuer before integrating applications and keep it stable when moving the proxy or console. Changing the console hostname requires updating `console.json` and its registered callback. Changing the issuer also requires coordinating client configuration and existing account associations. See [GitLab account association](gitlab.md#associate-the-intended-gitlab-account).

Both processes currently use the protected installation configuration and the same database. The console's configuration loader reads the OIDC signing key. The two hostnames let operators enforce different network access policies for the login and console endpoints.

## First-version access model

Fresh database initialization creates the enabled organization `org_system`, named `System organization`. This exact ID is reserved and immutable. It cannot be created by ordinary organization APIs, adopted through enrollment, or disabled. There is no organization-kind field, default customer organization, or organization-less Member.

A stored administrator assignment plus a currently eligible Member is required for console access. System organization membership alone grants nothing. Assignments are Member-specific; a second Member sharing a phone number or natural person receives no implied access.

The [Member role definitions](roles.md) and [management scopes and actions](management-permissions.md) record the agreed design. The following matrix describes currently implemented console behavior; it does not implement the resource selectors or replace the remaining per-role operation design.

| Operation | Platform administrator (`org_system`) | Organization administrator |
| --- | --- | --- |
| List/view organizations | All organizations | Own organization only |
| Create or enable/disable ordinary organizations | Yes | No |
| Rename organization | Any | Own organization |
| List/create/rename/block/unblock Members | Any organization | Own organization |
| Grant/revoke administrator assignment | Any organization | Own organization |
| Read bindings and management events | Any organization | Own organization |
| Set or reset a Member password or change the password username | Any organization, including `org_system` | No |
| List, configure and disable identity providers | Any organization | Own organization |
| Create, inspect, update, disable and retire SAML applications | Any organization | Own organization |
| List OIDC applications | All or selected owner | Own organization |
| Register and maintain OIDC applications | Any organization or installation-wide | Own Member applications |
| Read, set or clear a Member's managed email | Any organization | Own organization |

Platform administrators can switch organizations from the management scope in the header while retaining their original operator identity. The sidebar groups Organizations, Members, and Identity providers under Identity management; OIDC and SAML applications under Application integrations; and Authentication events and Operation history under Activity. Switching between them keeps the selected organization. In the all-organization scope, platform administrators see members from every organization. Each row identifies its organization and opens the member detail in that organization. Organization administrators see their own organization in the header. These permissions belong exclusively to MemberID management and are not added to business application identity claims. There are no custom roles, invitations, deletion, or bulk operations in this version. Explicit operator binding and first-administrator recovery use the operator tools.

## Switch the signed-in Member

The account menu's **切换身份** action selects a different administrator Member.
This is separate from the platform administrator's management-scope selector.
Candidates are limited to explicit, currently eligible bindings of the phone
factor used by the current console grant, with a current administrator assignment
on each Member. Membership, contact attributes, another login method, or platform
administrator privileges do not add candidates. Password and external-provider
sessions show no phone-switch candidates; authenticate with phone to use this flow.

`GET /api/identities` returns this self-service list in pages of 50, with `after`
and `nextAfter` Member cursors. `POST /api/identity-switch` accepts `memberId` and a
local `returnTo` page, and requires the current console cookie, exact Origin and
CSRF value. It returns an authorization URL, not an authentication credential.
The browser navigates to the normal OIDC Authorization Code flow with PKCE S256,
`login_hint` identifying the selected Member, `prompt=none`, and the existing
eight-hour authentication-age limit. The console client must be preauthorized
for this silent flow, as in the documented setup. Missing SSO, required consent,
or expired authentication fails the switch without silently authenticating again.

The single-use login state retains the selected Member and initiating console
session hash. The callback validates the returned subject, source session, current
source and target eligibility and administrator assignments, and identical phone
factor and SSO-session provenance. It creates a separate grant for the selected
Member and atomically replaces only the initiating console session, rotating its
CSRF value. Permissions are resolved independently for the new Member on each
management operation. Switching does not merge roles, revoke other applications'
grants, reset authentication time, or extend the original authentication deadline.

Success returns to the new Member's console home with a full page load, clearing
the previous identity's forms and cached data. Failure does not replace the previous
session and returns to its stored page with an error. Browser tabs share the
console cookie: a tab checks the current session on focus or becoming visible
and reloads at the new identity's home when the session changed. Old forms cannot
write with the previous CSRF value, and the replaced session is no longer usable.

## Console navigation and directories

The console follows the shadcn Base Nova [Sidebar-07 example](https://ui.shadcn.com/blocks/sidebar#sidebar-07), with collapsible first-level menus and nested page links. The menu containing the current page starts open; each menu can be toggled independently. The header trigger and clickable sidebar edge toggle the desktop navigation; Ctrl+B or Command+B provides the same shortcut. Collapsing retains only first-level icons and shows menu names in tooltips on hover or keyboard focus. Clicking a parent icon opens its page links in a Dropdown Menu to the right, with a check beside the current page. Selecting a page closes the menu and keeps the sidebar collapsed. Arrow keys navigate the popup, Escape dismisses it and returns focus to the parent icon, and outside interaction also dismisses it. This popup extends the official example; the expanded sidebar and mobile Sheet continue to use inline collapsible menus. The selected page highlights its nested link and parent menu; collapsing the sidebar preserves each menu's open state. The sidebar starts expanded on page load. Below 768 CSS pixels, the same navigation becomes a modal Sheet that closes on navigation, Escape, or outside interaction. Both navigation modes preserve the selected organization. The organization selector sits at the top of the sidebar; the header contains the navigation toggle and page breadcrumbs. Breadcrumbs link back to parent pages; Member detail and filtered history retain the originating Member directory and its filters. Long names truncate without exposing entity IDs. Narrow screens retain a single-line breadcrumb, preserving the current page label in three-level paths. Clicking the current administrator's name or avatar opens an account menu beside the desktop sidebar, or within the viewport on mobile, with their name, management role, Member details, and console sign-out. The Member details link always targets the signed-in identity, independently of the selected management scope.

Organization, Member, identity-provider, and operation-history lists share a directory layout with a toolbar, consistent row spacing, status labels, and a record-count footer. Rows display a single line of readable names, status, and other relevant fields; long names are truncated with the full text available on hover. Organization and Member names open their detail pages, and provider names open a detail dialog. Entity IDs are omitted from directory rows and remain available in details with selectable text and a copy action. Copy failures remain visible and allow manual selection. Operation history shows recorded actor and target names, specific actions, and one-line before/after differences. The all-organization view includes an organization column; a selected organization omits it. Target names link to the corresponding Member, organization, or provider detail. The details action opens full timestamps, names, identifiers, and raw previous/submitted fields. Detail pages group information and actions with Card components and use semantic Badge variants with explicit status text. Sign-in blockers remain visible in an Alert. Counts describe the current page, not the total matching records. Existing cursor pagination and server-side Member search/filter semantics are unchanged.

Member search and filters share a compact toolbar directly above the table, without a second directory title. Search continues to accept a complete Member ID even though IDs are not displayed in rows. Opening a Member from a filtered directory and returning preserves the original scope and filters. Page errors appear in a persistent, dismissible notification without moving the directory controls. Dialog validation continues to use its reserved feedback area.

Organization details show an editable name with an explicit Save action and reserved validation, request-error, and success feedback. A successful save updates the displayed organization name without reloading the page. The organization ID remains read-only. Enabled/disabled status and its separate confirmation action are grouped below the profile; only platform administrators can change ordinary organization status, and the disable confirmation retains its sign-in warning.

## Managed Member email

Member detail includes **受管邮箱** for administrators. Setting, changing or clearing an address uses the dedicated email resource and an expected revision. Conflicting addresses or stale revisions leave the dialog open with actionable feedback. The dialog warns that changes can affect downstream account association. Operation history records the administrator and the before/after values. Ordinary Members cannot edit this field through account self-service. See [managed email](member-email.md) for authority, validation and reassignment boundaries.

## Organization identity providers

Choose an organization, then open **身份提供商** (Identity providers). This directory lists the configured DingTalk and Feishu applications. Add multiple applications of either type with distinct application IDs and recognizable display names. Edit the display name, rotate the application secret, or enable and disable a source independently. The provider type, application ID, and tenant or corporation ID identify the binding namespace and stay fixed after creation. A replacement application gets its own row.

Saving a new secret verifies the application credentials before storing an encrypted value. Leaving the secret blank during editing keeps the existing one. An operator-initiated disable is rejected if it would remove the last eligible administrator from an organization that currently has one. Confirmed upstream revocation applies even in that case. Configuration changes are audited with actor and provider IDs, display name, type, and enabled state.

The create/edit and detail views show separate login and account-link callback URLs and upstream permission requirements. **检查已保存凭据** performs a bounded, non-mutating application-token check using the saved secret. Its result identifies the configuration revision and check time, distinguishes acceptance, explicit upstream denial and unavailable verification, and never returns tokens or upstream messages. It does not verify directory permissions, member visibility, enterprise identity or callback registration, and never changes source authorization or binding status. This session/CSRF-protected `POST /api/organizations/{organizationId}/providers/{kind}/{providerId}/check` requires the built-in provider `credential.check` permission before and after upstream I/O; organization administrators are limited to their own organization. Configuration changes during a check invalidate its result.

See [Feishu setup](feishu.md) and [DingTalk setup](dingtalk.md) for the required application and runtime settings.

## OIDC applications

Platform administrators open **OIDC 应用** in the application integrations group. For a Member application, the console assigns the immutable client ID and configures the display name, login and logout callbacks, account-link return destinations, one or all login organizations, refresh, consent, and optional identity evidence. The console can also edit the registration, enable or disable it, and rotate its secret. `prompt=consent` still requires confirmation for a preauthorized application.

Application details show the management owner (`ownerOrganizationId`) alongside the organization whose Members may sign in (`organizationId`). Creating in the installation-wide directory assigns the system organization as owner. Creating in a selected organization assigns that organization as both owner and the only permitted login organization. An installation operator can choose another owner at creation with `client add --owner-organization`. Editing the login restriction preserves the owner. Its organization administrators can edit callbacks, rotate credentials, and disable or re-enable their Member applications. Platform administrators retain control over login organization policies, identity evidence scopes and audiences, and consent bypass. Factor clients and legacy cross-organization registrations remain platform-managed.

An owner administrator or platform administrator can publish an owner-restricted Member client using the console API. Send a same-origin authenticated `PUT /api/organizations/{ownerId}/oidc-applications/{clientId}/publication` with the session CSRF header and `{"enabled":true}`. The owner remains eligible. A consumer administrator explicitly enables use with the same body at `PUT /api/organizations/{consumerId}/oidc-applications/{clientId}/enablement`. Duplicate writes have one effect. A published client keeps its original ID, callback list, credentials, consent policy and platform-controlled evidence policy.

Withdrawing a consumer (`{"enabled":false}`) prevents further authorization and revokes its grants, including refresh and online UserInfo access. Other consumers remain eligible. A new enablement requires fresh authorization. Unpublishing removes all external enablements and revokes their grants. Global application disablement revokes every grant. Offline JWT validation can continue until token expiry, and relying parties control their own sessions.

To release identity evidence, enter a custom scope such as `member:evidence` and an exact resource audience such as `https://api.example.test`. When the client requests that scope, the access token for that audience carries the organization, Member and binding IDs along with authentication factor ID, type, method and times. An ordinary login without the evidence scope uses the UserInfo audience. The recipient must validate the token and decide its own resource permissions. See [access-token claims](oidc.md#token-validation-and-eligibility).

Send `evidenceScope` and `evidenceAudience` together when editing the policy. Omitting both preserves the existing pair. Two empty strings remove it. Omitted account-return and consent fields also retain their values. Changing or removing an existing pair revokes grants containing its old scope. An already issued JWT may still be accepted offline until expiry. Updates require the current revision, and the management history records policy changes.

The installation operator creates protected system clients (`--system`) and factor-subject clients (`--subject factor`). The console shows the subject kind and the evidence policy of factor clients read-only. The protected console registration is read-only. Its secret can be rotated with the operator's `memberid client rotate-secret` command. Ordinary Members have no application management access.

The create and rotate dialogs return the new secret once. Rotation immediately replaces the old verifier. Disabling a registration blocks fresh authorization, code exchange and renewal, and revokes its current MemberID grants. Re-enabling requires a new authorization. The application's own session and offline JWT expiration continue to follow the relying party's policy. New registration events record the management owner and acting administrator, including platform administrators acting on an organization's application. Historical entries retain their original attribution. Secret values and verifiers are excluded.

## SAML applications

Choose an organization, then open **SAML 应用**. Platform administrators can select any organization; organization administrators remain in their own organization. Ordinary Members cannot access this directory or its API. The all-organization entry is an organization picker, not an aggregate of foreign trust policies.

**接入信息** reads the running authentication service’s fixed `/saml/metadata` endpoint and displays its Entity ID, HTTP-Redirect SSO endpoint, metadata URL and one public signing certificate with SHA-256 fingerprint and validity. The downloadable PEM contains only that certificate. The console uses normal TLS verification, a five-second timeout, no redirects and a 64 KiB response limit, and rejects unexpected issuer, endpoint or certificate shapes. It does not read local signing files or change deployment settings. Unavailable metadata is reported without claiming SAML is disabled or showing a stale certificate. A successful read describes the replica that answered, not every replica or a completed SP login. The same-origin `GET /api/organizations/{organizationId}/saml-identity-provider` checks current organization-view permission before and after the fetch.

Add an application with its external entity ID, exact HTTPS POST ACS, request-signature certificates and policy, allowed attributes, consent policy, and enabled state. The detail view displays the fixed binding and the configured NameID format. New console registrations use persistent; edits preserve the existing format. Use the operator CLI or private registration API to select unspecified before any mapping exists. [Legacy mapping administration](saml-nameid.md) is operator-only and has no console form. The form accepts PEM public certificates, never private keys. Signed requests are required by default; the unsigned exception is explicit and does not bypass verification of a present signature. Registration does not enable the SAML listener or configure its signing identity.

The allowed attributes include independent `DisplayName` and `Email` checkboxes. Email is disabled by default, comes only from the managed Member record, and is omitted when unset. Allowing it does not assert mailbox ownership.

Edit an application's enabled state to disable it reversibly. The detail dialog offers permanent retirement with a separate confirmation and a reversible disable alternative. Retirement preserves the entity ID and NameID mappings, cannot be undone, and does not sign out existing downstream sessions. Retired applications remain inspectable. A concurrent update returns a conflict without overwriting the other administrator's work; refresh and inspect before saving again. An uncertain response is not retried automatically.

The directory is paginated by stable registration ID, 50 per page. Its same-origin API uses `/api/organizations/{organizationId}/saml-service-providers` with the registration contract in the [private API guide](management-api.md#saml-service-provider-registration), but uses the console session, CSRF protection, and current Member authorization. It returns 200 for successful writes. Service authorization constrains every operation to its organization's resources; installation credentials and account self-service contexts cannot enter this boundary. Public before/after trust settings and the authenticated actor are captured atomically in operation history. History links open the referenced application even when it is not on the directory's first page.

## Page URLs and navigation

The console uses ordinary paths at the root of its dedicated origin. Organization
and Member IDs identify resources; names do not participate in routing.

| Path | Page |
| --- | --- |
| `/organizations` | Organization directory (platform administrators). |
| `/organizations/{organizationId}` | Organization details. |
| `/organizations/{organizationId}/members` | Organization Member directory. |
| `/organizations/{organizationId}/members/{memberId}` | Member details. |
| `/organizations/{organizationId}/providers` | Organization identity providers. |
| `/organizations/{organizationId}/events` | Organization operation history. |
| `/members` | All-organization Member directory (platform administrators). |
| `/events` | All-organization operation history (platform administrators). |
| `/authentication-events` | Platform authentication events. |
| `/organizations/{organizationId}/authentication-events` | Organization authentication events. |
| `/providers` | Organization picker for provider management (platform administrators). |
| `/oidc-applications` | Installation OIDC application management with all-organization management scope (platform administrators). |
| `/organizations/{organizationId}/oidc-applications` | Registrations owned by the selected organization. Organization administrators can create and manage their own Member applications here. Platform administrators can use the installation-wide view to create platform-owned applications. |
| `/saml-service-providers` | Organization picker for SAML application management (platform administrators). |
| `/organizations/{organizationId}/saml-service-providers` | Organization SAML applications; `after` cursor and optional `serviceProviderId` detail selection. |

After login, `/` replaces itself with `/organizations` for a platform administrator
or `/organizations/{organizationId}/members` for an organization administrator.
Concrete links keep their explicit scope; an unauthorized link displays an access
error instead of silently substituting another organization. Server-side API
authorization remains authoritative. The system organization uses the ordinary
`/organizations/org_system` path.

Member lists use query parameters `q`, `status` (`active` or `blocked`),
`administrator` (`yes` or `no`), and `after`. Organization directories also use
`after`. Operation history uses `memberId` to filter to a Member and `before` for
pagination. For example, `/organizations/{organizationId}/events?memberId={memberId}`
opens that Member's operation history. Changing filters resets pagination.
Switching organizations retains the current section and clears resource details,
filters, and pagination. Hash fragments are not application routes.

Provider details can be opened with `providerId` on the organization provider directory.

Resource links support opening in a new tab, refreshing, and browser back/forward
navigation. When a Member is opened from a list, browser history state retains the
list's scope, filters, and cursor for the return link, including through a page
refresh. A directly opened Member detail defaults to its own organization's list.
Create/edit dialogs remain page-local; a successful create opens the new resource.

The Go console serves its frontend entry point for the listed page paths, including
direct deep-link requests. `/assets/` serves files; missing files, unknown paths,
and unknown API/authentication endpoints do not receive the frontend entry point.
The reverse proxy only needs the existing hostname routing, without a global
fallback or rewrite rule.

An unauthenticated deep link displays the login entry at that address.
`/auth/login?returnTo=...` accepts only a local, supported page path with its query
string (at most 4096 bytes). The server stores this destination with the expiring,
browser-bound, single-use login transaction. The registered callback stays
`/auth/callback`; its query cannot replace the stored destination. Successful login
returns to the requested page. A failed login returns there with an error so a retry
retains the target. Expired console sessions offer the same login entry at the
current page. External URLs and API/authentication endpoints are rejected as return
targets. Explicit console logout returns to `/`.

## Build and register the console

Build with `sh scripts/check.sh` or `sh scripts/package.sh VERSION NEW_OUTPUT_DIRECTORY`. Both build the locked frontend before embedding it in Go. Node/npm are build dependencies; the resulting executable needs neither at runtime.

Initialize a protected installation and a new database as described in [operator setup](operations.md). Fresh installations use schema version **33**. Existing schema 26–32 databases use the [explicit forward upgrade](database-upgrades.md); startup never migrates or erases data. Start the OIDC process before starting the console so its discovery and keys are reachable.

Register a dedicated confidential Member client with no organization restriction:

```sh
memberid client add --directory .local/memberid --name "MemberID Console" --system \
  --redirect https://admin.example.invalid/auth/callback --preauthorized
```

Capture the returned secret directly into a protected file named `console-client-secret` in the installation directory; do not copy the JSON object into that file. The file contains only the secret, optionally followed by a newline. Protect its directory and Windows ACLs as for other installation credentials. Create `console.json` in that directory:

```json
{
  "origin": "https://admin.example.invalid",
  "clientId": "<returned client_id>",
  "clientSecretFile": "console-client-secret"
}
```

The console validates the client, secret, all-organization Member policy, and exact callback against the database registration. It requests only `openid profile`, with no Refresh Token. The registration is available immediately. After rotating the protected console secret, replace its local secret file and restart the console process to load it.

```sh
memberid serve --directory .local/memberid --listen 127.0.0.1:8080
# In a second process using the same installation and database:
memberid serve-console --directory .local/memberid --listen 127.0.0.1:8082
```

For production, set the console origin to the HTTPS origin at the root of its hostname and use the [hostname routing above](#production-hostnames). For loopback-only development, explicitly initialize with `--allow-loopback-http`, register `http://127.0.0.1:8082/auth/callback`, and set the console origin to `http://127.0.0.1:8082`. Use the exact `127.0.0.1` address in the development configuration.

## Bootstrap and recovery

Follow [first-time setup](administration.md#first-time-setup) to provision `org_system/root` during deployment. Then open the standard administration console and sign in with the password from the protected file. The [operator bootstrap](administration.md#bootstrap-and-recovery) supports installations that prefer a verified phone or DingTalk binding. The console checks administrator access at the OIDC callback and on subsequent management requests.

Ordinary organization administrators can then be assigned in the console once their login binding is available. Creating a Member does not verify a phone or fabricate an external binding. Operator recovery, last-available-administrator protection, and external-departure precedence are described in the same guide.

Platform administrators can use [Member password management](administration.md#organization-scoped-passwords) from the Member detail to prepare the first organization administrator's login. Give the recipient the organization ID, username and generated password through a protected channel.

## Sessions, requests, and audit

Login state and nonce are browser-bound and single-use, with a five-minute callback lifetime. ID Token issuer, audience, signature, expiry, nonce, and access-token hash are checked using the maintained OIDC relying-party implementation. The verified response is tied to its exact stored grant. The browser receives an opaque HttpOnly SameSite=Lax cookie, Secure with a `__Host-` name on HTTPS; it never receives OIDC bearer credentials or the client secret.

Console sessions expire after 30 minutes of inactivity or eight hours after original authentication, whichever comes first. The API entry point resolves and renews the opaque console session and passes only its Member and grant references to the operation service. The service checks current administrator assignment, Member/organization/factor/binding eligibility, and grant/SSO revocation and expiry once at its authorization boundary. Reads check before response queries; mutations check inside their transaction. Provider configuration also checks before upstream verification to reject unauthorized external calls, then checks again in the save transaction. The session view and logout resolve their current administrator directly.

Mutations require the exact configured Origin and a session-bound CSRF header. A lost administrator assignment or invalid source identity/grant/session returns `401 sign_in_required`; an eligible administrator without the requested permission receives `403 forbidden`. Request-shape, CSRF, and route validation can reject a request before service authorization. No authority is cached across requests. Revocation takes effect at subsequent authorization checks; a completed earlier response is not recalled. Provider directory changes apply once verified and recorded by the existing reconciliation/stream machinery.

The [authorization timing and revocation design](authorization-boundaries.md)
defines the agreed operation boundary: an already authorized short operation
may finish after a concurrent revocation, while subsequent independent operations
need a fresh server-side decision. It does not require permission checks before
every internal step. The transaction checks described above are current console
behavior. See [query validation](console-query-validation.md) for the measured
query reductions and the opt-in profiling fixture.

“Sign out of console” deletes only this console session; it does not log out of MemberID SSO or downstream applications. A subsequent login can reuse eligible SSO within the original authentication limit. Existing business application sessions remain owned by those applications.

The browser uses `/api/session`, `/api/organizations`, `/api/members` (platform administrators only), `/api/organizations/{organizationId}/members`, the Member `administrator` subresource, `/api/organizations/{organizationId}/providers`, `/api/events`, and `/api/logout`. This same-origin UI API is distinct from the documented private `/v1` integration API; it does not accept management bearer credentials or actor impersonation fields. Direct foreign-organization requests are rejected regardless of visible navigation. Directory pages contain at most 50 records, ordered by opaque ID; event pages use descending numeric IDs. In the Member directory, search names or IDs and filter by identity status or administrator assignment. These conditions apply across the selected scope before pagination. A successful create opens the new organization workspace or Member detail. An interrupted create request is not automatically retried: refresh the directory before creating another record.

The Member detail separates identity status from sign-in blockers. It shows disabled organizations, Member blocks, and missing or revoked bindings using the current detail data. Sign-in also checks factor and provider availability.

From a Member detail page, open the operation history filtered to that Member. The history shows the selected Member and lets administrators return to the detail page or view the full organization history.

Successful console changes and administrator CLI operations write atomic events containing the actor Member ID, target IDs, action, changed fields, and timestamp. Events also preserve the actor, organization, and target display names at the time of the write, along with previous editable values for renames, manual blocks, organization status, administrator assignments, system admission, and provider configuration. Later renames do not rewrite these snapshots. Provider events identify the application and record credential updates only as a boolean. Missing historical names or previous values are not inferred from live entities; known submitted values remain visible without an invented before value. A removed manual block is shown as unblocked, not as proof of overall sign-in eligibility. Selected operator update/revocation operations use `installation-operator`. The console summarizes known changes and retains the raw payload for each record. These are management change records, not a complete authentication/security log; failed attempts, provider reconciliation, and historical operations are not reconstructed. No tokens, codes, provider secrets, or admission union IDs are included. Configure database access, backups, and retention for private identity data; automatic management-history retention is not implemented.

## Authentication event API

The authorized [authentication-event query API](authentication-events.md#query-api)
provides platform and organization list/detail endpoints with bounded filtering,
cursor pagination, retention exclusion and organization-safe fields. It uses this
console's session and authorization boundary. Select **认证记录** (Authentication events) in the activity navigation.
Authentication events are best-effort evidence and have a default 90-day retention;
this policy does not change transactional management history.

Filter by event type, outcome, or method. **更多筛选** adds Member/client/grant IDs,
request/interaction IDs, and a time range. Time controls use the browser's local
timezone and send explicit UTC instants; start is inclusive and end exclusive.
Filters and the cursor live in the URL, survive refresh/back/forward, and apply on
the server before pagination. New filters and organization switching reset the
cursor. Counts describe only the displayed page. Organization cells show current names; technical organization IDs remain in record details. The empty state reports no matching
records, not proof that authentication did not occur.

Details fetch the record again with current authorization and show occurrence and
persistence times separately, established actor/target references, and classified
reasons. Request and interaction links start a new query in the selected view;
causal links fetch only through that view's endpoint. Expired or inaccessible
records can disappear between the list and detail request. Organization views do
not reconstruct missing platform fields. The warning that records may be incomplete
reflects best-effort delivery, including failures the service cannot observe.

The page supports desktop and narrow-screen navigation, scrollable tables/details,
keyboard dismissal with focus return, bounded pagination, and retryable loading
errors. Authentication events and transactional operation history remain separate
navigation entries.

## Validation

Database/HTTP integration tests cover scoped access, ordinary-member rejection, explicit system admission, browser-bound callbacks, replay rejection, CSRF, current eligibility, audit attribution, and last-administrator concurrency. They use synthetic phone/provider fixtures. They do not establish real SMS delivery, live DingTalk behavior, or a deployed HTTPS/proxy configuration.

Identity-switch HTTP tests additionally cover a single SMS verification reused
across independent organization and platform Members, candidate filtering and
cursors, independent read/write permissions, preserved authentication deadlines,
source-session consumption, concurrent callbacks, stale CSRF, callback replay,
subject/provenance mismatches, logout, revocation, and transactional insert failure.
OIDC hint tests require the current binding and registered client policy and
preserve the independent `id_token_hint` subject constraint.

A separate temporary HTTPS deployment on 2026-11-16 exercised the packaged
implementation with synthetic seeded phone-session evidence. Desktop and
390-pixel browser inspection covered the account menu, identity dialog, completed
organization/platform switches, foreign-organization denial and stale-CSRF
rejection. The other-tab session handler was exercised by dispatching a focus
event because the headless browser reports both pages as visible and focused.
The isolated browser context ignored local certificate errors; separate HTTPS
requests verified both endpoints against the generated development CA. This
establishes UI behavior, not browser trust-store acceptance or real SMS delivery.

For targeted browser inspection, build the frontend and run the opt-in fixture against a disposable PostgreSQL server:

```sh
MEMBERID_CONSOLE_BROWSER_FILE=/private/new-console-status.json \
  go test -tags=integration -run '^TestConsoleBrowserFixture$' -timeout 22m -v ./internal/oidcprovider
```

Set `MEMBERID_TEST_DATABASE_URL` as documented in CONTRIBUTING. The private status file contains the temporary URL, synthetic phone number, and latest synthetic code. Create a sibling file with suffix `.stop` to end inspection and clean up that fixture's database/status files. The fixture times out after 20 minutes and is never compiled into the release executable. Do not expose its status file or test server publicly.

For console layout changes, inspect the desktop and collapsed sidebar, the narrow-screen navigation drawer (including Escape and focus return), long names and IDs, filtered and empty Member directories, detail-to-directory return, and each directory's pagination. Keep synthetic fixture screenshots separate from real identity data.

## Member binding details and self-service entry

Each sign-in method in a Member detail opens read-only binding metadata: status and binding/revocation times, provider namespace/name, application and enterprise identifiers, and the stored external identity (Feishu OpenID or DingTalk UnionID and, when known, employee ID). Reads retain Member/organization ownership and administrator checks. Phone values, credential verifiers and provider secrets are not added to this projection. Provider identity fields cannot be edited or reassigned here.

**绑定本人的登录方式** appears only on the current administrator's own Member. The session/CSRF-protected `POST /api/account-link` accepts no target Member or return URL; it requests fresh OIDC authentication with the current Member as a login hint. The callback requires that same Member and authentication within five minutes before opening the issuer's `/account?memberId=...` page. An identity selected from another organization cannot satisfy this continuation. The account page independently checks the verified browser session, its freshness and Member evidence, and lists only configured linking methods. Binding still requires the existing account flow's explicit provider/phone proof and CSRF checks. It cannot use administrator authority to bind another Member, recover or transfer a revoked binding, or merge identities. No NameID or migration operation is introduced.

## Member application grants

**查看应用授权** in a Member's sign-in methods opens a read-only, paginated OIDC grant list. It shows the client name/ID, original scopes, authentication time, effective grant deadline and stored lifecycle state (active, expired or revoked). This is not the application's session inventory or its authorization policy, nor proof of current Member eligibility. Browser idle expiry alone does not expire an otherwise valid grant; session revocation and absolute expiry do affect it. Expired records can disappear under the existing protocol cleanup policy, so this is not an audit archive.

`GET /api/organizations/{organizationId}/members/{memberId}/grants` requires current Member-view and `M/grants:list` permission. Platform administrators can inspect any organization's Members; organization administrators stay within their organization. Ownership and both the grant's organization and Member subject are checked explicitly. Grants for another Member or a shared factor subject are excluded. Pages contain 50 records by default (maximum 100), ordered by opaque grant ID with an `after` cursor. Responses omit bearer/refresh tokens, credential verifiers, factor IDs and shared browser-session IDs. The console offers no grant-revocation action.
