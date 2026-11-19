# Administrator-managed Member email

MemberID stores one administrator-managed email attribute per Member and releases it only to explicitly authorized SAML applications. It is an organization-owned directory assertion, not proof of mailbox ownership, an authentication factor, a binding, or an account identifier. Member IDs, OIDC subjects, and persistent SAML NameIDs remain independent of the value.

## Authority and provenance

The only supported source is `administrator`. Platform administrators can manage any organization; organization administrators can manage only their own. Console operations resolve current management authority and require the separate `organizations/{organizationId}/members/{memberId}/email` permission. Ordinary Members, account self-service, and external authentication callbacks cannot update the value. The operator CLI and private management credential retain installation-wide authority.

Reads return `address`, `source`, `mailboxVerified`, `revision`, `updatedBy`, and `updatedAt`. `mailboxVerified` is always `false`: no verification message is sent, and callers cannot supply a source or verification flag. `updatedBy` is the administrator Member ID, `installation-operator`, or `installation-manager`. The source is reported even for an empty address; it describes the supported authority, not an existing mailbox assertion. A never-configured value has revision zero, empty `updatedBy`, and null `updatedAt`.

Every effective change records the actor, organization, Member, previous address/revision, resulting value/provenance, and timestamp in the management audit. Attribute and audit commit together; an audit failure rolls back the change. Management history contains personal data and requires appropriate access, backup, and retention controls. Authentication events do not include email values.

Provider contact/profile changes and login methods cannot replace this source. There is no fallback to upstream email, phone numbers, or synthetic addresses. Adding an upstream source requires a separate explicit ownership and conflict policy.

## Values and updates

The supported profile is one ASCII address of at most 254 bytes, with an unquoted local part of at most 64 bytes and a DNS-style domain containing a dot. Display names, comments, lists, quoted local parts, domain literals, whitespace, and internationalized local parts are rejected. Internationalized domains must use ASCII A-labels. Domain casing is normalized; local-part casing is preserved. No DNS, delivery, or mailbox-ownership check is performed.

Only one Member in an organization may hold a given nonempty address. Conflict comparison is conservatively case-insensitive, including the local part. Duplicates return `409 email_taken` without changing either Member. Equal addresses in different organizations are allowed and never merge those identities. This constraint establishes neither global ownership nor permission to associate downstream accounts.

Writes require both `address` and the inspected current `revision`. Empty address explicitly clears the attribute while preserving revision history. Effective updates increment the revision; identical values with the correct revision return the current record. Stale revisions return `409 conflict`, including recreation of a cleared value with revision zero. After an uncertain response, inspect the current record before another intentional write.

Changing or clearing an address releases its current uniqueness reservation. Reassignment may affect SPs that use email as identity: coordinate downstream accounts before changing it. Retired email addresses are not reserved as permanent identifiers. An update does not revoke sessions or recall an already issued assertion.

## Management interfaces

The console Member detail shows **受管邮箱** (Managed email), the administrator source, and unverified mailbox status. Administrators can set, replace, or clear the value; the dialog warns about downstream account association. Changes appear in the Member's operation history. The current record is `email` in the authorized Member detail response. Writes use `PUT /api/organizations/{organizationId}/members/{memberId}/email` with the normal Origin and CSRF checks.

The private API supports `GET` and `PUT /v1/organizations/{organizationId}/members/{memberId}/email` using the existing installation credential. PUT accepts exactly this replacement shape:

```json
{"address":"member@example.test","revision":0}
```

See the [OpenAPI contract](management.openapi.json). Ordinary OIDC tokens do not authorize this interface. The operator CLI uses `MEMBERID_DATABASE_URL`:

```sh
memberid member email inspect --organization ORG_ID --member MEMBER_ID
memberid member email set --organization ORG_ID --member MEMBER_ID --address member@example.test --revision 0
memberid member email set --organization ORG_ID --member MEMBER_ID --address '' --revision 1
```

## SAML release and account association

Add `Email` to an SP's `attributes` list or select **向应用发送受管邮箱（Email）** in its configuration. Default registrations release no email. `Email` and `DisplayName` are independent entries; unknown or duplicate entries are rejected. The assertion uses name `Email`, NameFormat `urn:oasis:names:tc:SAML:2.0:attrname-format:basic`, and one `xs:string` value. No mailbox-verification attribute is emitted.

Missing or cleared email is omitted even when permitted. Authentication can still succeed; an SP requiring email must enforce that provisioning requirement itself. The final issuance transaction reads the current address under the Member lock, serializing against updates, including first assignment. SP policy changes invalidate unfinished requests through the existing revision binding.

Use persistent NameID for recurring account identification. Automatic email association is appropriate only when the SP operator has independently established that the trusted directory authority controls the relevant existing accounts, the address belongs to the intended account, and reassignment is coordinated. This feature alone proves none of those downstream ownership facts. Otherwise, use authenticated account linking or an authorized explicit mapping. An administrator-provided email is not proof of control of an existing account.

OIDC continues to accept `email` scope without issuing `email` or `email_verified`. Administrator-managed SAML email does not silently become verified OIDC email; OIDC publication requires a separate explicit release contract.

## Validation and installation boundary

Fresh schema version 30 stores email separately from Members and authentication factors. Startup rejects incompatible schemas without automatic migration or data deletion. [Explicit forward upgrades](database-upgrades.md) start at schema 26.

Focused checks cover mailbox input, management and self-service boundaries, organization isolation, duplicate/stale/concurrent writes, audit rollback, and issuance locking. HTTP tests cover current-value release, missing attributes, stable NameID after edits, equal addresses on independent Members, and phone/password/DingTalk/Feishu reuse without OIDC email claims. [Independent consumer acceptance](saml-interop.md) exercises the packaged CLI and checks omitted, released, changed, and cleared email at the SP. Upstreams are synthetic; mailbox delivery, real-provider email authority, and automatic downstream account association are not claimed.

On 2026-11-16, Chrome validation on a disposable HTTPS deployment confirmed administrator sign-in, duplicate-address feedback, setting and clearing email, re-assignment, before/after audit display, and the SP Email checkbox persisting after save. The temporary deployment and its database were removed after acceptance.
