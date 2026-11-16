# Administrator identities and operator setup

Fresh schema version **21** creates the enabled organization `org_system`, named `System organization`. The exact ID is reserved: ordinary creation and enrollment cannot claim it, and it cannot be disabled. There is no organization-kind field, default customer organization, organization-less Member, or global User.

An administrator is an explicitly assigned Member with at least one currently eligible authentication binding. Membership in `org_system` alone grants no privileges. A platform administrator can manage all organizations; an ordinary organization administrator is limited to their own organization. The identity store rechecks a Member administrator's current grant, SSO session, assignment, and eligibility when authorizing mutations. These roles belong to MemberID management and are not added to consuming applications' identity claims. See [Member roles](roles.md) for the agreed definitions, including ordinary system Members and the absence of a system-organization administrator role.

The [shared administration console](console.md) exposes individual administrator access; operator bootstrap remains available through the CLI. The private management API retains its independent installation-wide credential and does not accept Member actor impersonation.

## First-time setup

During deployment, initialize the fresh database with an operator-owned password output path:

```sh
memberid database init --initial-root-password-file /path/to/protected/initial-root-password
```

The command creates `org_system/root`, binds a generated password, and explicitly grants platform administrator access. The plaintext password is written only to the new file. Read access to that file is the deployment operator's credential for first login. Keep the parent directory private and outside serving containers. Use mode `0700` for the directory on POSIX or a restrictive ACL on Windows. MemberID checks for an existing output file before connecting to the database, then creates it exclusively with mode `0600` on POSIX. If the file appears after the check or writing fails, MemberID rolls back database initialization. If the connection fails after the file is written, preserve the file and run `memberid database check` to determine whether initialization committed before retrying.

After starting the services, open the standard administration console. Sign in with organization ID `org_system`, username `root`, and the password in the file. Save it in a password manager and remove the initial file when no longer needed. The password remains valid until it is rotated.

If the initial password is lost, run `memberid setup reset-password` from the protected deployment environment. Save the replacement from stdout. This rotates the same Member's credential and revokes its existing grants and password-authenticated SSO sessions. Offline JWT verifiers can still accept already-issued access tokens until expiry. The command preserves existing administrator assignments and blocks.

## Organization-scoped passwords

Platform administrators can set or reset a Member's password from the console in any organization, including the system organization. Open **登录方式** on the Member detail page. Set a username when creating the credential. Reset uses the existing username, including `root`. The console shows the random password once in the success dialog. Save it before closing the dialog. Existing sign-in bindings and eligibility state are preserved. The console records the acting administrator without putting the credential in the operation history.

An installation operator can provision or rotate an existing Member's password with `memberid member set-password --organization ORGANIZATION_ID --member MEMBER_ID --username USERNAME`. Save the generated password from stdout. Usernames contain 1–64 lowercase ASCII letters, digits, dots, underscores, or hyphens, beginning with a letter or digit. Each is unique within its organization. A Member has one locally managed username. Repeating the command with the same username rotates the password and revokes prior grants and password sessions. The reserved system `root` uses the recovery command above.

MemberID generates passwords from 24 bytes of cryptographic randomness and persists a PBKDF2-HMAC-SHA-256 hash with an independent 16-byte salt and a stored work factor. Sign-in throttles each organization and username to ten attempts in five minutes and bounds concurrent password derivations per process. Passwords and password hashes are excluded from event payloads. Use HTTPS and keep the database, deployment shell, and operator command output protected.

## Bootstrap and recovery

To provision the first platform administrator through an external provider, initialize the fresh database with `memberid database init` without a password output path. Create the intended platform Member explicitly:

```sh
memberid member create --organization org_system --name "Installation administrator"
```

Retain the returned `id` as `MEMBER_ID`. Use an enabled authentication provider to establish an eligible binding.

**Phone:** start a standard OIDC login with a registered Member client and complete phone verification. Verification persists the factor even before a Member is selectable. Inspect that already verified phone with `memberid factor inspect --phone PHONE_NUMBER`, then bind the returned factor ID explicitly:

```sh
memberid member bind-factor --organization org_system --member MEMBER_ID --factor FACTOR_ID
```

**DingTalk without SMS:** configure a dedicated DingTalk application for `org_system` using the [provider commands](dingtalk.md). Independently confirm the intended person's exact union ID in that application's namespace and prepare admission to the existing Member:

```sh
memberid dingtalk allow-system-member --member MEMBER_ID --union-id PROVIDER_UNION_ID
```

This approval lasts 24 hours and is consumed atomically by successful fresh DingTalk verification of that exact identity. It creates neither authentication evidence nor an administrator assignment. The person then selects `org_system` in an OIDC DingTalk login and completes verification. Unapproved corporation employees cannot automatically create system Members. Approval cannot replace or restore an existing or revoked DingTalk binding. Repeating preparation replaces only that Member's pending approval; cancel it with `memberid dingtalk cancel-system-member --member MEMBER_ID`.

After a verified, eligible binding exists, explicitly assign administrator access:

```sh
memberid administrator grant --organization org_system --member MEMBER_ID
```

For an ordinary organization, use its ID with the same command. Creating a Member does not verify a phone number or fabricate a provider binding. Another Member sharing a contact attribute or natural person receives no implied access.

`memberid administrator revoke --organization ORGANIZATION_ID --member MEMBER_ID` removes an assignment. Trusted CLI/database operator access remains independent of Member roles and must be protected. Recovery after provider departures requires provisioning another verified, eligible Member; commands cannot bypass authentication or silently restore revoked bindings. There is no default password or automatically privileged bootstrap Member.

## Availability and audit

Manual administrator removal, Member blocking, and binding revocation cannot remove an organization's last currently available administrator. Concurrent manual mutations share a database transaction lock, including immutable Member updates. External departures and confirmed provider revocations remain authoritative even if no administrator remains. Disabling an ordinary organization remains an explicit installation or platform operation.

Successful administrator changes, admission preparation, and selected organization/Member updates or binding revocations write atomic management events. Trusted CLI entry points use `installation-operator`; private API mutations use `installation-manager`; authenticated Member mutations use the initiating Member ID. Management mutation services require an explicit server-created principal. An empty principal is denied, and HTTP input cannot select an installation identity. Rejected operations do not leave success events. Records contain target IDs, action, changed fields, and time; admission union IDs, tokens, codes, and provider secrets are excluded.

These events are a limited management change history, not a complete authentication/security log. Historical actions, failed attempts, and provider reconciliation are not reconstructed. Administrators can read events within their scope through the console. Configure database access, backups, and retention for private identity data; automatic retention is not implemented.

The [authentication event contract](authentication-events.md) separately defines
authentication/lifecycle events, organization visibility, retention, and
best-effort delivery. Its store, writer, retention cleanup, and SMS send and
supported-method verification, grant issuance, confirmed OIDC reuse, and explicit
session/grant revocation events are implemented. Authorized queries remain planned.
This does not change the existing transactional management events.

## Validation boundaries

Database integration tests cover reserved-ID handling, system admission, administrator eligibility, concurrent removal, rollback, external-departure precedence, actor scope, and provider/audit lock ordering. Provider evidence is synthetic. Real SMS delivery, live DingTalk login, and deployed acceptance are separate checks.
