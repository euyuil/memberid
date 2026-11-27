# Feishu authentication

MemberID supports Feishu enterprise self-built applications on the mainland Feishu platform. Each ordinary MemberID organization can configure multiple Feishu applications alongside DingTalk and phone authentication.

## Setup

1. In the [Feishu developer console](https://open.feishu.cn/app), create, publish, and enable an enterprise self-built application. Use its availability settings to choose who can sign in. Copy the application's App ID, App Secret, and the intended Feishu tenant's Tenant Key.
2. Register the exact MemberID issuer URL with the `/auth/feishu/callback` suffix in the application's **Security Settings**, for example `https://login.example.invalid/auth/feishu/callback`. When upgrading from schema 35 or earlier, register the new redirect URL before switching MemberID and verify a fresh Feishu sign-in.
3. In the [MemberID console](console.md#organization-identity-providers), select the organization, open **身份提供商** (Identity providers), and add a Feishu application. Supply a display name, Tenant Key, App ID, and App Secret. Repeat for each application. One App ID may be registered once per installation.
4. Set `MEMBERID_FEISHU_ENABLED=true` on the OIDC process and restart it. Run the console and OIDC process with the same installation directory and database. Enable DingTalk and phone independently as needed.

Add the console's own OIDC redirect separately from the Feishu callback. An organization-restricted OIDC client directly displays the organization's available applications. A client serving multiple organizations, such as the administration console, asks for the MemberID organization ID before listing the organization's external options.

The Feishu application needs permission to authenticate the intended users. The default UserInfo fields include `open_id` and `tenant_key`. Basic first-login authentication requests no additional user-authorized contact or offline-access scopes. Membership reconciliation also needs the application directory permissions below. See the official [authorization page](https://open.feishu.cn/document/authentication-management/access-token/obtain-oauth-code) and [user information endpoint](https://open.feishu.cn/document/server-docs/authentication-management/login-state-management/get).

## Authentication and identity

MemberID binds the upstream state to the browser, the downstream OIDC transaction, and the selected application's revisions. It sends a PKCE S256 challenge and uses the [documented v2 exchange for that authorization page](https://open.feishu.cn/document/authentication-management/access-token/get-user-access-token). Callback state is single-use and expires after five minutes. The server fetches UserInfo over TLS, requires the exact configured `tenant_key`, and stores the verified `open_id` in the selected application's namespace. The upstream code and tokens are discarded.

The first successful login for a previously unbound identity creates an independent ordinary Member. Subsequent logins from that application reuse the Member and its OIDC subject. Matching contacts or display names do not attach to a pre-existing Member or merge identities from different apps. Existing Members can explicitly add Feishu through [self-service account linking](account-linking.md#feishu), using `/account/link/feishu?memberId=<member-id>` and the additional exact `/account/feishu/callback` provider callback. Linking preserves the selected Member, OIDC subject, SAML NameIDs, and original session/grant deadlines. Feishu admission and linking to `org_system` are unavailable. The downstream flow continues to use MemberID's own OIDC code, session, tokens and refresh policy, with `amr=feishu`.

## Application status and revocation

The console verifies new secrets through the [Feishu self-built application token endpoint](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/authentication-management/access-token/tenant_access_token) before saving them. Credentials are encrypted with the protected installation `providerKey` and bound to the provider namespace, tenant, App ID, and configuration revision. The token check establishes application authorization. The expected tenant is independently verified on each fresh login.

The enabled OIDC process checks enabled applications on startup and before each membership reconciliation batch. When a login exchange indicates that the application is unavailable to that tenant, MemberID checks the application credentials before treating the failure as application-level revocation. Confirmed application removal, uninstallation, or disablement makes only that source ineligible for new login, code redemption, refresh, and online token verification. Other configured providers and phone remain eligible according to their own rules. Unknown errors and per-user authorization failures leave the stored application state intact. A successful app check can restore upstream authorization for an enabled source.

Administrators can independently disable an application from the provider list. Offline JWT verifiers can continue to accept already-issued JWTs until their short expiry. Confirmed employee departure is reconciled as described below. Member blocking and explicit binding revocation remain independent local controls.

This integration is covered by simulated Feishu HTTP responses and disposable database tests. Verify actual application availability, redirect configuration, and a real Feishu login in the target tenant before deployment.

## Employee membership reconciliation

The OIDC process uses the application's [self-built tenant access token](https://open.feishu.cn/document/authentication-management/access-token/tenant_access_token) and [single-user directory lookup](https://open.feishu.cn/document/server-docs/contact-v3/user/get), with `user_id_type=open_id`. Grant the application's **Get contact basic information** (获取通讯录基本信息) permission, or a supported application directory-read permission, and **Get user employment information** (获取用户受雇信息) so the employee status fields are returned. Publish and approve the permission change, and include admitted employees in the application's directory data-access range. The lookup also needs the returned `open_id`. Missing status fields or directory visibility are incomplete evidence and require operator attention; enabling the adapter does not grant those upstream permissions.

Only already admitted Feishu bindings are visited, including explicitly linked identities. The stored application namespace determines the self-built application credential and its single tenant. Admission has already required the exact configured tenant key, and the tenant and App ID cannot be edited in place. The lookup must return the exact admitted application's open ID. No directory listing, contact matching, cross-application identity mapping or Member provisioning occurs.

| Directory observation | Stored effect |
| --- | --- |
| Matching open ID and explicit `is_resigned=true` | Record departure for this binding; block the Member's authentication and issuance through all factors in its organization. |
| Matching open ID, `is_resigned=false`, `is_activated=true`, and explicit false frozen/exited/unjoined flags | Clear this binding's departure evidence after final revision checks. |
| Frozen, exited, unjoined, inactive, missing status, unknown user, unexpected subject or ambiguous provider response | Retain existing evidence; report an unknown or unavailable outcome. These states never prove departure or restoration. |
| Insufficient directory/field permissions | Retain existing evidence; report a permission or unknown-field outcome. |
| Network failure, rate limit or temporary outage | Retain existing evidence and retry later. |
| Confirmed application-level denial | Make only that authentication source unavailable; preserve all membership evidence and other factors' own policy. |

The lookup is outside the database transaction and has a 20-second deadline. The commit locks the organization and rechecks organization lifecycle, Member eligibility, application configuration/authorization revisions, factor status and binding identity/status. A concurrent block, revocation, provider change or newer membership observation rejects the stale result. Both presence and departure advance the Member eligibility revision, preventing older concurrent observations from overwriting newer evidence. Repeated results are idempotent in eligibility effect. No external events are consumed, so there is no event delivery/order contract.

### Scheduling and recovery

On startup and one minute after each completed batch, the process visits at most 100 admitted bindings, oldest attempted first. Attempt ordering and confirmed observations are durable. Missing observation rows enter the next batch; failed lookups advance retry ordering without altering eligibility, so an unavailable employee cannot starve other identities. Restart resumes this ordering and retains confirmed departure. Revoked bindings can still be looked up to establish current employment; the lookup never restores the binding. Disabled or unauthorized applications and disabled factors are skipped, with prior evidence retained.

For `N` eligible bindings and `A` enabled applications, a complete sweep takes at most `ceil(N/100)` batches when the set is stable. With available upstream services and a responsive database, budget each batch for up to `A × 10 seconds` of application checks, `100 × 20 seconds` of individual lookups and the one-minute interval. Successful low-latency lookups normally finish sooner; this is a polling contract, not immediate upstream revocation. Outages, missing permissions, a stopped OIDC process or repeated policy conflicts can extend the delay without a finite success guarantee. Fix the cause and restart the OIDC process for an immediate batch. Safe warning counters distinguish checked, present, departed, permission-denied, unknown, unavailable and conflicting outcomes without logging identities or provider responses.

Fresh Feishu login for an existing binding also performs the authoritative lookup. A successful presence observation may restore that source's departure state, but manual blocks, DingTalk departure evidence, other Feishu departures, revoked bindings and revoked sessions/grants remain effective. A proof must still match the observed Member revision at final admission and expires as directory evidence after one minute. Linking cannot bypass the current source Member eligibility.

Stored departure is shared by SSO reuse, OIDC authorization/code redemption/refresh, online token validation/UserInfo and SAML assertion issuance. Final issuance and reconciliation use complementary organization locks. This blocks future MemberID authentication and issuance; it does not terminate downstream application sessions or immediately invalidate JWTs accepted by offline verifiers. Applications retain their own authorization and session policy.

### Database and validation

Schema 28 adds `feishu_memberships` and a versioned forward migration from 27; source 26 upgrades through 27 in the same maintenance transaction. Existing identity, binding, session, grant and NameID rows are preserved. An upgrade seeds pending checks for existing Feishu bindings and never invents departure or presence evidence. Follow [database upgrades and recovery](database-upgrades.md), keeping the matching source executable, database, installation configuration and keys for recovery.

Unit and disposable-PostgreSQL/HTTP tests use synthetic upstream responses. They cover employee status and permissions, namespace mismatches, departure before login/during provider I/O/before final issuance, stale snapshots, source isolation, manual blocks and revocations, restart, bounded retries and existing account linking. A real tenant must separately verify its directory permissions, employee statuses, data-access range and actual reconciliation delay. These tests do not establish real-provider or downstream-session termination acceptance.
