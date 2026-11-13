# Administration console

The console is a separate HTTP process in the same MemberID executable. Its React/shadcn UI and session API share one origin. It signs in through this installation's standard OIDC Authorization Code flow with PKCE S256. The installation management credential is never sent to a browser.

## First-version access model

Fresh database initialization creates the enabled organization `org_system`, named `System organization`. This exact ID is reserved and immutable. It cannot be created by ordinary organization APIs, adopted through enrollment, or disabled. There is no organization-kind field, default customer organization, or organization-less Member.

A stored administrator assignment plus a currently eligible Member is required for console access. System organization membership alone grants nothing. Assignments are Member-specific; a second Member sharing a phone number or natural person receives no implied access.

| Operation | Platform administrator (`org_system`) | Organization administrator |
| --- | --- | --- |
| List/view organizations | All organizations | Own organization only |
| Create or enable/disable ordinary organizations | Yes | No |
| Rename organization | Any | Own organization |
| List/create/rename/block/unblock Members | Any organization | Own organization |
| Grant/revoke administrator assignment | Any organization | Own organization |
| Read bindings and management events | Any organization | Own organization |

Platform administrators can switch organizations from the management scope in the header while retaining their original operator identity. The selection applies to the organization workspace and operation history. Organization administrators see their own organization in the header. These permissions belong exclusively to MemberID management and are not added to business application identity claims. There are no custom roles, invitations, deletion, bulk operations, credential resets, provider configuration pages, or client-registration pages in this version. Provider configuration, explicit factor binding, and first-administrator recovery remain operator tasks.

## Build and register the console

Build with `sh scripts/check.sh` or `sh scripts/package.sh VERSION NEW_OUTPUT_DIRECTORY`. Both build the locked frontend before embedding it in Go. Node/npm are build dependencies; the resulting executable needs neither at runtime.

Initialize a protected installation and a new database as described in [operator setup](operations.md). This increment uses fresh schema version **14**. Existing databases are not migrated or erased. Start the OIDC process before starting the console so its discovery and keys are reachable.

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

Expose the two origins through a correctly configured HTTPS reverse proxy. The console origin has no path, trailing slash, query, or fragment. For loopback-only development, explicitly initialize with `--allow-loopback-http`, register `http://127.0.0.1:8082/auth/callback`, and set the console origin to `http://127.0.0.1:8082`. An arbitrary HTTP origin or a `localhost` alias is rejected. `serve-management` remains the independent private integration listener; do not route its installation-wide bearer API through the console.

## Bootstrap and recovery

Follow [administrator setup](administration.md#bootstrap-and-recovery) to provision a system Member, establish a verified phone or DingTalk binding, and explicitly grant administrator access. The console can be used to initiate that standard OIDC login; it rejects management access until the assignment exists. Sign in again after granting the role.

Ordinary organization administrators can then be assigned in the console once their login binding is available. Creating a Member does not verify a phone or fabricate an external binding. Operator recovery, last-available-administrator protection, and external-departure precedence are described in the same guide.

## Sessions, requests, and audit

Login state and nonce are browser-bound and single-use, with a five-minute callback lifetime. ID Token issuer, audience, signature, expiry, nonce, and access-token hash are checked using the maintained OIDC relying-party implementation. The verified response is tied to its exact stored grant. The browser receives an opaque HttpOnly SameSite=Lax cookie, Secure with a `__Host-` name on HTTPS; it never receives OIDC bearer credentials or the client secret.

Console sessions expire after 30 minutes of inactivity or eight hours after original authentication, whichever comes first. Every API request rechecks administrator assignment, Member/organization/factor/binding eligibility, and grant/SSO revocation and expiry. Mutations recheck authorization inside their transaction and require the exact configured Origin and a session-bound CSRF header. Revocation takes effect on subsequent requests; a completed earlier response is not recalled. Provider directory changes apply once verified and recorded by the existing reconciliation/stream machinery.

“Sign out of console” deletes only this console session; it does not log out of MemberID SSO or downstream applications. A subsequent login can reuse eligible SSO within the original authentication limit. Existing business application sessions remain owned by those applications.

The browser uses `/api/session`, `/api/organizations`, `/api/organizations/{organizationId}/members`, the Member `administrator` subresource, `/api/events`, and `/api/logout`. This same-origin UI API is distinct from the documented private `/v1` integration API; it does not accept management bearer credentials or actor impersonation fields. Direct foreign-organization requests are rejected regardless of visible navigation. Directory pages contain at most 50 records, ordered by opaque ID; event pages use descending numeric IDs. In the Member directory, search names or IDs and filter by identity status or administrator assignment. These conditions apply across the current organization before pagination. An interrupted create request is not automatically retried: refresh the directory before creating another record.

From a Member detail page, open the operation history filtered to that Member. The history shows the selected Member and lets administrators return to the detail page or view the full organization history.

Successful console changes and administrator CLI operations write atomic events containing the actor Member ID, target IDs, action, changed fields, and timestamp. Selected operator update/revocation operations use `installation-operator`. These are management change records, not a complete authentication/security log; failed attempts, provider reconciliation, and historical operations are not reconstructed. No tokens, codes, provider secrets, or admission union IDs are included. Configure database access, backups, and retention for private identity data; automatic event retention is not implemented.

## Validation

Database/HTTP integration tests cover scoped access, ordinary-member rejection, explicit system admission, browser-bound callbacks, replay rejection, CSRF, current eligibility, audit attribution, and last-administrator concurrency. They use synthetic phone/provider fixtures. They do not establish real SMS delivery, live DingTalk behavior, or a deployed HTTPS/proxy configuration.

For targeted browser inspection, build the frontend and run the opt-in fixture against a disposable PostgreSQL server:

```sh
MEMBERID_CONSOLE_BROWSER_FILE=/private/new-console-status.json \
  go test -tags=integration -run '^TestConsoleBrowserFixture$' -timeout 22m -v ./internal/oidcprovider
```

Set `MEMBERID_TEST_DATABASE_URL` as documented in CONTRIBUTING. The private status file contains the temporary URL, synthetic phone number, and latest synthetic code. Create a sibling file with suffix `.stop` to end inspection and clean up that fixture's database/status files. The fixture times out after 20 minutes and is never compiled into the release executable. Do not expose its status file or test server publicly.
