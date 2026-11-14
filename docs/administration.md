# Administrator identities and operator setup

Fresh schema version **15** creates the enabled organization `org_system`, named `System organization`, with no Members or administrator assignments. The exact ID is reserved: ordinary creation and enrollment cannot claim it, and it cannot be disabled. There is no organization-kind field, default customer organization, organization-less Member, or global User.

An administrator is an explicitly assigned Member with at least one currently eligible authentication binding. Membership in `org_system` alone grants no privileges. A platform administrator can manage all organizations; an ordinary organization administrator is limited to their own organization. The identity store rechecks a Member administrator's current grant, SSO session, assignment, and eligibility when authorizing mutations. These roles belong to MemberID management and are not added to consuming applications' identity claims. See [Member roles](roles.md) for the agreed definitions, including ordinary system Members and the absence of a system-organization administrator role.

The [shared administration console](console.md) exposes individual administrator access; operator bootstrap remains available through the CLI. The private management API retains its independent installation-wide credential and does not accept Member actor impersonation.

## Bootstrap and recovery

Initialize a protected installation and a fresh database using [operator setup](operations.md). Existing databases are not migrated or erased. Create the intended platform Member explicitly:

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

Successful administrator changes, admission preparation, and selected organization/Member updates or binding revocations write atomic management events. Trusted operator entry points use `installation-operator`; authenticated Member mutations use the initiating Member ID. Rejected operations do not leave success events. Records contain target IDs, action, changed fields, and time; admission union IDs, tokens, codes, and provider secrets are excluded.

These events are a limited management change history, not a complete authentication/security log. Historical actions, failed attempts, and provider reconciliation are not reconstructed. Administrators can read events within their scope through the console. Configure database access, backups, and retention for private identity data; automatic retention is not implemented.

## Validation boundaries

Database integration tests cover reserved-ID handling, system admission, administrator eligibility, concurrent removal, rollback, external-departure precedence, actor scope, and provider/audit lock ordering. Provider evidence is synthetic. Real SMS delivery, live DingTalk login, and deployed acceptance are separate checks.
