# Management API

MemberID's management interface provides installation-wide operator access to organization identities, Members, existing authentication factors, explicit bindings, and current eligibility. It is a separate administrative contract, not an OIDC, OAuth, or SCIM endpoint. Applications retain their own business permissions.

The self-contained [OpenAPI contract](management.openapi.json) describes request and response schemas. API JSON uses exact lowerCamelCase field names. Unknown, repeated, incorrectly cased, or null request fields are rejected; each request must contain one JSON object of at most 32 KiB with `Content-Type: application/json`.

## Run and authenticate

Initialize the [installation and empty database](operations.md), then run a separate process using the same executable and database:

```sh
memberid serve-management --directory .local/memberid --listen 127.0.0.1:8081
```

This process starts without an SMS provider, OIDC client, or authenticated Member. The public `serve` process does not route management requests, and `serve-management` does not route OIDC or login requests. Both use the same identity store and implementation.

Every management request, including `/healthz`, requires `Authorization: Bearer MANAGEMENT_CREDENTIAL`. Load the random credential from the protected installation's `management-secret` file into the caller's secret store. Never put it in a URL, browser, ordinary log, repository, or client-side application. The server retains and compares only its SHA-256 verifier from `secrets.json`; it does not read the plaintext credential file during serving. OIDC access tokens, ID Tokens, client secrets, and browser login cookies do not grant management access.

The credential authorizes every organization in the installation. It represents the `installation-manager` principal, not an end-user Member. There is no tenant administrator delegation or actor impersonation parameter. Restrict access to trusted integration backends and operators. Requests with an `Origin` header are rejected, and the listener does not enable CORS.

The default listener is loopback HTTP. An explicitly isolated private-network or container deployment may pass `--allow-private-listen` with a literal private or wildcard bind address. This flag does not configure encryption or firewall rules: terminate TLS at a private proxy for network clients and restrict the upstream network to that proxy and trusted callers. Do not publish the management port or route it through public OIDC ingress. Hostnames and public bind addresses are refused. `/healthz` reports process availability, not provider or database readiness.

Authenticated non-GET operations emit the fixed management principal, HTTP method, route template, and response status to the process log. These entries omit credentials, request/response bodies, contact values, and path identifiers. They are operational access records, not a durable identity-change audit ledger or proof of an initiating human identity.

## Identity operations

| Method and path | Input or result |
| --- | --- |
| `POST /v1/organizations` | Required `name`; optional `id`. Returns the created Organization with status 201. |
| `GET /v1/organizations` | Paged organization identities. |
| `GET /v1/organizations/{organizationId}` | One Organization. |
| `PATCH /v1/organizations/{organizationId}` | At least one of `name` or `status` (`enabled` or `disabled`). |
| `POST /v1/organizations/{organizationId}/members` | Required `displayName`; optional `id`. Returns the created Member with status 201. |
| `GET /v1/organizations/{organizationId}/members` | Paged Members in exactly that organization, including blocked Members. |
| `GET /v1/organizations/{organizationId}/members/{memberId}` | One Member in the specified organization. |
| `PATCH /v1/organizations/{organizationId}/members/{memberId}` | At least one of `displayName` or boolean `manualBlocked`. |
| `GET /v1/organizations/{organizationId}/members/{memberId}/bindings` | All explicit relationships for this Member, including revoked ones. |
| `POST /v1/organizations/{organizationId}/members/{memberId}/bindings` | `authenticationFactorId` of an existing, active, provider-verified factor. Returns the binding. |
| `DELETE /v1/organizations/{organizationId}/members/{memberId}/bindings/{factorId}` | Revokes an existing relationship; 204, including a repeated revocation. |
| `GET /v1/factors/{factorId}` | Existing factor identity and status. Contains sensitive provider subject data; restrict its disclosure. |
| `POST /v1/eligibility` | Checks an explicit organization, Member, factor, and factor type. |

Creation generates an identifier when `id` is omitted. An explicitly supplied identifier must use the [identity model](identity-model.md) format and must be unused. Duplicate creation returns 409; it does not update, merge, or reassign an identity. Display names are nonblank text of at most 128 Unicode code points without control characters. Changing a name preserves the stable Member subject.

Every Member lookup or mutation is constrained by its organization. A Member in another organization returns 404. Disabling an organization prevents its Members from passing current eligibility without deleting their identities. Manual unblock preserves an independent external-departure block. An organization's enabled status and the Member's own status are separate facts; inspect eligibility for the complete binding decision.

Binding requires an existing verified factor ID. This API does not create a factor from a phone number, verify a contact attribute, create a login session, or infer that two Members represent the same person. Repeating an active identical binding preserves its identity. A conflicting or revoked relationship remains reserved and returns 409 instead of transferring access. One factor can be explicitly bound to independent Members in different organizations, but cannot be shared by different Members in the same organization.

## Directory pagination

Organization and Member directories return `{"items": [...], "nextAfter": "..."}`. `nextAfter` is omitted on the final page. Send that value as `after` in the next request. `limit` defaults to 50 and accepts 1 through 100. Only these two query parameters are accepted, once each; query parameters are not supported on other operations.

Results are ordered by stable identifier, using a bounded keyset cursor. Pages are current database observations, not a frozen snapshot across requests. Names and contact attributes are not identity selectors. These administrative directories expose all records in scope to the installation manager; they are not an end-user resource directory or a business-authorization filter.

## Eligibility and failures

An eligibility request contains:

```json
{
  "organizationId": "ORGANIZATION_ID",
  "memberId": "MEMBER_ID",
  "authenticationFactorId": "FACTOR_ID",
  "authenticationFactorType": "phone"
}
```

Replace identifier placeholders with actual returned IDs. `authenticationFactorType` is `phone` or `dingtalk`. A current active factor and binding, enabled organization, and unblocked Member produce `{"eligible": true, "bindingId": "..."}`. A missing relationship, wrong organization or factor type, revoked binding, disabled factor or organization, or blocked Member produces `{"eligible": false}`. Malformed identifiers or unsupported factor types return 400. The lookup evaluates these facts in one database query.

Eligibility is not proof of a new authentication event and grants no business permissions. A resource server must separately validate the OIDC access token's signature, issuer, audience, lifetime, and claims, then apply its own authorization policy. The query supplies current identity facts; it cannot retract already issued JWTs from offline verifiers before their short expiry.

Domain failures return a JSON `error` code with 400 (`invalid_request`), 401 (`unauthorized`), 403 (`ineligible` or `browser_access_denied`), 404 (`not_found`), 409 (`conflict`), 415 (`json_required`), 422 (`member_id_conflict`), or 500 (`internal_error`). Internal database details are not returned. Unknown routes and unsupported methods may use ordinary HTTP errors. Do not retry non-idempotent creation blindly after an uncertain network outcome: use an explicit identifier and inspect its existing record before deciding whether to retry.

## Validation and current limits

Integration tests exercise a real HTTP server and disposable PostgreSQL: credential separation from actual issued OIDC tokens, unauthorized mutations, organization isolation, pagination, binding conflicts and revocation, independent block sources, eligibility, and independent process startup without login providers or clients. Unit tests cover strict JSON and the listen-address boundary. These tests do not establish deployed network isolation.

Grant inspection and revocation are available through the [operator CLI](operations.md#inspect-and-revoke-oidc-grants). Provider configuration, account self-service, HTTP grant administration, and automated management credential rotation are separate increments. Atomic organization enrollment is described below. This interface does not initialize or migrate a database, and introduces no deletion of organizations or Members.

## Atomic organization enrollment

Trusted integrations may use `POST /v1/organization-enrollments` to create a new organization, its initial independent Member, and an explicit binding in one database transaction. This operation requires the same installation management credential as the other management operations. It is a provisioning decision, not an authentication flow, and assigns no application role or permission.

The request contains `organizationId`, `name`, `memberId`, `bindingId`, and `authenticationFactorId`. The caller supplies unused organization and Member identifiers in the documented formats and a UUID binding identifier. The factor must already have been verified by MemberID's phone authentication provider and remain active. Phone numbers or contact attributes cannot be supplied in place of verified factor evidence. DingTalk admission is a separate provider workflow; it is not phone enrollment. An initial Member uses the display name `Member`, which can be changed independently afterward.

The organization identifier is the operation's stable idempotency boundary. MemberID retains a hash of the accepted tuple and an immutable receipt. The first success and exact retries return status 200 with `organizationId`, `memberId`, `bindingId`, `authenticationFactorId`, and the original `createdAt`. UUID binding casing is normalized to lowercase before comparison. Reusing an accepted organization identifier with a different tuple returns 409. The operation cannot adopt an organization that already exists without an enrollment receipt.

A rejected transaction leaves no partially created organization, Member, binding, or receipt. If the candidate Member ID was already in use, status 422 with `error: member_id_conflict` lets the caller choose a fresh Member ID and retry the otherwise unaccepted request. Other identifier or binding conflicts return 409 and require investigation or a new unused candidate before retry. An uncertain network response does not justify changing accepted identifiers: retry the same tuple or read `GET /v1/organizations/{organizationId}/enrollment` first.

A successful retry returns historical acceptance only. It does not rename an organization, recreate identities, reactivate factors or bindings, clear manual or departure blocks, or issue any new login proof. The receipt remains stable after later eligibility changes. Query current identity eligibility separately before applying the consuming application's authorization policy. If a consuming application needs business roles or enrollment steps of its own, it owns that coordination and its own idempotency rules.
