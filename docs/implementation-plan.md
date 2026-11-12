# Implementation plan

MemberID provides independent Member identities within each organization through standard OpenID Connect. A person may have multiple independent Members. A matching contact attribute does not link those identities.

## Current status

The repository contains an independently buildable Go executable, process health checks, local contribution hooks, and CI. PostgreSQL organization, Member, factor, and binding storage and basic operator commands are implemented with integration tests. Protected installation initialization, signing-key validation, and file-backed confidential-client registration and secret rotation are also available. Optional PNVS phone delivery and transaction-bound persisted verification are implemented with synthetic-provider tests. The confidential Authorization Code profile, phone login UI, persisted SSO, UserInfo, introspection, revocation, and RP-initiated logout are implemented with real HTTP and database tests. Standard rotating Refresh Tokens now preserve original authentication and absolute deadlines, with atomic replay-family revocation and seven-day grant inactivity expiry. A separate protected HTTP management process now supports organization and Member administration, explicit bindings, directories, and current eligibility. Operator commands also inspect grant lifecycle metadata and revoke individual grants. Atomic phone-factor organization enrollment and immutable retry receipts are implemented. Member updates also support atomic immutable receipts for safe retries after lost responses. Encrypted organization-scoped DingTalk application configuration and credential rotation are available through the CLI and management API. Optional DingTalk login and verified independent Member admission are implemented with browser-bound, single-use callbacks and atomic session creation. Explicit application-authorization synchronization and current revocation enforcement are implemented with stale-observation and lifecycle checks. Current directory verification protects code redemption and refresh, including phone fallback during unknown outages and replay revocation despite provider failures. Periodic application and admitted-Member reconciliation now runs with replica coordination, partial-failure reporting, and stale-write protection. Outbound DingTalk streams now apply departures atomically before acknowledgement, persist replay receipts, and trigger fresh reconciliation after positive events or reconnect. Protected management credential rotation now preserves unrelated installation material and requires an explicit management-process restart. MemberID-hosted DingTalk account linking now uses fresh session and provider evidence, exact separately registered return destinations, and atomic non-transferring bindings. Local native distributions now include versioned executables, checksums, documentation, and third-party notices; the Linux container copies the same executable and uses externally supplied configuration and CA trust. An opt-in packaged-provider fixture now exercises an unmodified GitLab client through standard OIDC, with separate browser acceptance recorded in [the GitLab guide](gitlab.md). See [the supported OIDC profile](oidc.md) and [distribution guide](distribution.md).

## Delivery sequence

Each step must produce a focused, tested PR. Merge a completed PR before starting dependent work.

1. Establish typed organization, Member, authentication-factor, and explicit binding rules with isolated PostgreSQL persistence.
2. Add explicit empty-database initialization and operator commands for organizations, Members, provider settings, client registration, and eligibility.
3. Add independently optional phone and DingTalk authentication adapters, with synthetic providers confined to tests.
4. Implement the confidential web-client OIDC profile using a maintained protocol library: Authorization Code with PKCE S256, Discovery, JWKS, ID Tokens, access tokens, UserInfo, rotating Refresh Tokens, introspection, revocation, and RP-initiated logout.
5. Add Member account management and a separately protected management API. Keep application permissions outside MemberID.
6. Package the same executable for native and container deployments with complete configuration, key-management, lifecycle, and third-party notices.
7. Verify standard client interoperability, including a real unmodified GitLab deployment. Record supported profiles, observed versions, and any remaining limitations.

The initial profile does not include a global User account, SAML, SCIM, LDAP, dynamic client registration, device flow, or a new administration RBAC framework.

## Acceptance

Cover organization isolation, stable and distinct Member subjects, explicit factor linking, eligibility changes, redirect and client binding, PKCE, one-time codes, concurrent refresh, replay revocation, session deadlines, consent, and logout limits.

Tests must use disposable owned resources and synthetic data. Provider simulation is distinct from real provider verification. Successful GitLab login is interoperability evidence, not OIDC certification.

Protect existing installation data. New schema initialization must refuse a nonempty database. Document supported deployment behavior and operational limitations before inviting production use.
