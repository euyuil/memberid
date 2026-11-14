# Feishu authentication

MemberID supports Feishu enterprise self-built applications on the mainland Feishu platform. Each ordinary MemberID organization can configure multiple Feishu applications alongside DingTalk and phone authentication.

## Setup

1. In the [Feishu developer console](https://open.feishu.cn/app), create, publish, and enable an enterprise self-built application. Use its availability settings to choose who can sign in. Copy the application's App ID, App Secret, and the intended Feishu tenant's Tenant Key.
2. Register the exact MemberID issuer URL with the `/login/feishu/callback` suffix in the application's **Security Settings**, for example `https://login.example.invalid/login/feishu/callback`.
3. In the [MemberID console](console.md#organization-identity-providers), select the organization, open **身份提供商** (Identity providers), and add a Feishu application. Supply a display name, Tenant Key, App ID, and App Secret. Repeat for each application. One App ID may be registered once per installation.
4. Set `MEMBERID_FEISHU_ENABLED=true` on the OIDC process and restart it. Run the console and OIDC process with the same installation directory and database. Enable DingTalk and phone independently as needed.

Add the console's own OIDC redirect separately from the Feishu callback. An organization-restricted OIDC client directly displays the organization's available applications. A client serving multiple organizations, such as the administration console, asks for the MemberID organization ID before listing the organization's external options.

The Feishu application needs permission to authenticate the intended users. The default UserInfo fields include `open_id` and `tenant_key`. MemberID requests no additional contact or offline-access scopes. See the official [authorization page](https://open.feishu.cn/document/authentication-management/access-token/obtain-oauth-code) and [user information endpoint](https://open.feishu.cn/document/server-docs/authentication-management/login-state-management/get).

## Authentication and identity

MemberID binds the upstream state to the browser, the downstream OIDC transaction, and the selected application's revisions. It sends a PKCE S256 challenge and uses the [documented v2 exchange for that authorization page](https://open.feishu.cn/document/authentication-management/access-token/get-user-access-token). Callback state is single-use and expires after five minutes. The server fetches UserInfo over TLS, requires the exact configured `tenant_key`, and stores the verified `open_id` in the selected application's namespace. The upstream code and tokens are discarded.

The first successful login for a previously unbound identity creates an independent ordinary Member. Subsequent logins from that application reuse the Member and its OIDC subject. Matching contacts or display names do not attach to a pre-existing Member or merge identities from different apps. Feishu self-service account linking and Feishu admission to `org_system` are unavailable. The downstream flow continues to use MemberID's own OIDC code, session, tokens and refresh policy, with `amr=feishu`.

## Application status and revocation

The console verifies new secrets through the [Feishu self-built application token endpoint](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/authentication-management/access-token/tenant_access_token) before saving them. Credentials are encrypted with the protected installation `providerKey` and bound to the provider namespace, tenant, App ID, and configuration revision. The token check establishes application authorization. The expected tenant is independently verified on each fresh login.

The enabled OIDC process checks enabled applications on startup and every 15 minutes after each completed pass. When a login exchange indicates that the application is unavailable to that tenant, MemberID checks the application credentials before treating the failure as application-level revocation. Confirmed application removal, uninstallation, or disablement makes only that source ineligible for new login, code redemption, refresh, and online token verification. Other configured providers and phone remain eligible according to their own rules. Unknown errors and per-user authorization failures leave the stored application state intact. A successful app check can restore upstream authorization for an enabled source.

Administrators can independently disable an application from the provider list. Offline JWT verifiers can continue to accept already-issued JWTs until their short expiry. Feishu directory synchronization and per-user deprovisioning are outside this integration. Use Member blocking or explicit binding revocation to terminate a user's local access.

This integration is covered by simulated Feishu HTTP responses and disposable database tests. Verify actual application availability, redirect configuration, and a real Feishu login in the target tenant before deployment.
