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
| List, configure and disable identity providers | Any organization | Own organization |

Platform administrators can switch organizations from the management scope in the header while retaining their original operator identity. The sidebar has separate Organizations, Members, Identity providers, and Operation history entries. Switching between them keeps the selected organization. In the all-organization scope, platform administrators see members from every organization. Each row identifies its organization and opens the member detail in that organization. Organization administrators see their own organization in the header. These permissions belong exclusively to MemberID management and are not added to business application identity claims. There are no custom roles, invitations, deletion, bulk operations, credential resets or client-registration pages in this version. Explicit operator binding and first-administrator recovery use the operator tools.

## Console navigation and directories

The desktop sidebar can collapse to an icon rail. On narrow screens, the header opens a modal navigation drawer with keyboard focus handling. Both navigation modes preserve the selected organization, and the header continues to show that management scope. The account area identifies the current administrator separately from the selected scope.

Organization, Member, identity-provider, and operation-history lists share a directory layout with a toolbar, consistent row spacing, status labels, and a record-count footer. Rows display a single line of readable names, status, and other relevant fields; long names are truncated with the full text available on hover. Organization and Member names open their detail pages, and provider names open a detail dialog. Entity IDs are omitted from directory rows and remain available in details with selectable text and a copy action. Copy failures remain visible and allow manual selection. Operation history shows a one-line change summary that opens the complete changes and actor/target identifiers in a detail dialog. Status labels retain their text alongside color indicators. Counts describe the current page, not the total matching records. Existing cursor pagination and server-side Member search/filter semantics are unchanged.

Member search and filters share a compact toolbar directly above the table, without a second directory title. Search continues to accept a complete Member ID even though IDs are not displayed in rows. Opening a Member from a filtered directory and returning preserves the original scope and filters. Page errors appear in a persistent, dismissible notification without moving the directory controls. Dialog validation continues to use its reserved feedback area.

## Organization identity providers

Choose an organization, then open **身份提供商** (Identity providers). This directory lists the configured DingTalk and Feishu applications. Add multiple applications of either type with distinct application IDs and recognizable display names. Edit the display name, rotate the application secret, or enable and disable a source independently. The provider type, application ID, and tenant or corporation ID identify the binding namespace and stay fixed after creation. A replacement application gets its own row.

Saving a new secret verifies the application credentials before storing an encrypted value. Leaving the secret blank during editing keeps the existing one. An operator-initiated disable is rejected if it would remove the last eligible administrator from an organization that currently has one. Confirmed upstream revocation applies even in that case. Configuration changes are audited with actor and provider IDs, display name, type, and enabled state.

See [Feishu setup](feishu.md) and [DingTalk setup](dingtalk.md) for the required application and runtime settings.

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
| `/providers` | Organization picker for provider management (platform administrators). |

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

Initialize a protected installation and a new database as described in [operator setup](operations.md). This increment uses fresh schema version **16**. Existing databases are not migrated or erased. Start the OIDC process before starting the console so its discovery and keys are reachable.

Register a dedicated confidential Member client with no organization restriction:

```sh
memberid client add --directory .local/memberid --id memberid-console \
  --redirect https://admin.example.invalid/auth/callback --preauthorized
```

Capture the returned secret directly into a protected file named `console-client-secret` in the installation directory; do not copy the JSON object into that file. The file contains only the secret, optionally followed by a newline. Protect its directory and Windows ACLs as for other installation credentials. Create `console.json` in that directory:

```json
{
  "origin": "https://admin.example.invalid",
  "clientId": "memberid-console",
  "clientSecretFile": "console-client-secret"
}
```

The console validates the client, secret, all-organization Member policy, and exact callback against local registration. It requests only `openid profile`, with no Refresh Token. Restart the OIDC process after client registration; restart both processes after client secret rotation and replace the protected console secret file. Configuration is not hot-reloaded.

```sh
memberid serve --directory .local/memberid --listen 127.0.0.1:8080
# In a second process using the same installation and database:
memberid serve-console --directory .local/memberid --listen 127.0.0.1:8082
```

For production, set the console origin to the HTTPS origin at the root of its hostname and use the [hostname routing above](#production-hostnames). For loopback-only development, explicitly initialize with `--allow-loopback-http`, register `http://127.0.0.1:8082/auth/callback`, and set the console origin to `http://127.0.0.1:8082`. Use the exact `127.0.0.1` address in the development configuration.

## Bootstrap and recovery

Follow [administrator setup](administration.md#bootstrap-and-recovery) to provision a system Member, establish a verified phone or DingTalk binding, and explicitly grant administrator access. The console can be used to initiate that standard OIDC login; it rejects management access until the assignment exists. Sign in again after granting the role.

Ordinary organization administrators can then be assigned in the console once their login binding is available. Creating a Member does not verify a phone or fabricate an external binding. Operator recovery, last-available-administrator protection, and external-departure precedence are described in the same guide.

## Sessions, requests, and audit

Login state and nonce are browser-bound and single-use, with a five-minute callback lifetime. ID Token issuer, audience, signature, expiry, nonce, and access-token hash are checked using the maintained OIDC relying-party implementation. The verified response is tied to its exact stored grant. The browser receives an opaque HttpOnly SameSite=Lax cookie, Secure with a `__Host-` name on HTTPS; it never receives OIDC bearer credentials or the client secret.

Console sessions expire after 30 minutes of inactivity or eight hours after original authentication, whichever comes first. Every API request rechecks administrator assignment, Member/organization/factor/binding eligibility, and grant/SSO revocation and expiry. Mutations recheck authorization inside their transaction and require the exact configured Origin and a session-bound CSRF header. Revocation takes effect on subsequent requests; a completed earlier response is not recalled. Provider directory changes apply once verified and recorded by the existing reconciliation/stream machinery.

The [authorization timing and revocation design](authorization-boundaries.md)
defines the agreed operation boundary: an already authorized short operation
may finish after a concurrent revocation, while subsequent independent operations
need a fresh server-side decision. It does not require permission checks before
every internal step. The transaction checks described above are current console
behavior; the design document introduces no runtime changes.

“Sign out of console” deletes only this console session; it does not log out of MemberID SSO or downstream applications. A subsequent login can reuse eligible SSO within the original authentication limit. Existing business application sessions remain owned by those applications.

The browser uses `/api/session`, `/api/organizations`, `/api/members` (platform administrators only), `/api/organizations/{organizationId}/members`, the Member `administrator` subresource, `/api/organizations/{organizationId}/providers`, `/api/events`, and `/api/logout`. This same-origin UI API is distinct from the documented private `/v1` integration API; it does not accept management bearer credentials or actor impersonation fields. Direct foreign-organization requests are rejected regardless of visible navigation. Directory pages contain at most 50 records, ordered by opaque ID; event pages use descending numeric IDs. In the Member directory, search names or IDs and filter by identity status or administrator assignment. These conditions apply across the selected scope before pagination. A successful create opens the new organization workspace or Member detail. An interrupted create request is not automatically retried: refresh the directory before creating another record.

The Member detail separates identity status from sign-in blockers. It shows disabled organizations, Member blocks, and missing or revoked bindings using the current detail data. Sign-in also checks factor and provider availability.

From a Member detail page, open the operation history filtered to that Member. The history shows the selected Member and lets administrators return to the detail page or view the full organization history.

Successful console changes and administrator CLI operations write atomic events containing the actor Member ID, target IDs, action, changed fields, and timestamp. Selected operator update/revocation operations use `installation-operator`. The console summarizes known changes and retains the raw payload for each record. These are management change records, not a complete authentication/security log; failed attempts, provider reconciliation, and historical operations are not reconstructed. No tokens, codes, provider secrets, or admission union IDs are included. Configure database access, backups, and retention for private identity data; automatic event retention is not implemented.

## Validation

Database/HTTP integration tests cover scoped access, ordinary-member rejection, explicit system admission, browser-bound callbacks, replay rejection, CSRF, current eligibility, audit attribution, and last-administrator concurrency. They use synthetic phone/provider fixtures. They do not establish real SMS delivery, live DingTalk behavior, or a deployed HTTPS/proxy configuration.

For targeted browser inspection, build the frontend and run the opt-in fixture against a disposable PostgreSQL server:

```sh
MEMBERID_CONSOLE_BROWSER_FILE=/private/new-console-status.json \
  go test -tags=integration -run '^TestConsoleBrowserFixture$' -timeout 22m -v ./internal/oidcprovider
```

Set `MEMBERID_TEST_DATABASE_URL` as documented in CONTRIBUTING. The private status file contains the temporary URL, synthetic phone number, and latest synthetic code. Create a sibling file with suffix `.stop` to end inspection and clean up that fixture's database/status files. The fixture times out after 20 minutes and is never compiled into the release executable. Do not expose its status file or test server publicly.

For console layout changes, inspect the desktop and collapsed sidebar, the narrow-screen navigation drawer (including Escape and focus return), long names and IDs, filtered and empty Member directories, detail-to-directory return, and each directory's pagination. Keep synthetic fixture screenshots separate from real identity data.
