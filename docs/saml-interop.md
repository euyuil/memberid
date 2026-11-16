# Independent SAML consumer acceptance

The opt-in fixture in `internal/interop/saml/` uses Node-SAML 5.2.0 and its independent XML/signature implementation to consume the normal packaged MemberID executable. It does not import MemberID's Go protocol code, start a special IdP build, or invoke a production external provider. A synthetic organization and password-authenticated Member are provisioned through the ordinary operator CLI.

## Run

Use the repository's Go 1.27.4 and Node.js 26.13.1/npm 11.20.0 toolchains, Docker with Linux containers, and OpenSSL with `req -addext` support. Run from the repository root; Git Bash provides the POSIX shell on Windows:

```sh
mkdir -p dist
sh scripts/package.sh saml-acceptance dist/saml-acceptance
npm --prefix internal/interop/saml ci --ignore-scripts
export MEMBERID_SAML_PACKAGE="$(node -e 'console.log(require("node:path").resolve("dist/saml-acceptance"))')"
npm --prefix internal/interop/saml test
```

Use a new package destination. The executable must match the host (Linux or Windows amd64); the fixture checks `BUILDINFO` and its SHA-256 entry before starting it. In PowerShell, set `$env:MEMBERID_SAML_PACKAGE` to the absolute package directory. Without this variable, the test reports a skip, not acceptance. The Linux build job supplies its native package and runs the test in CI.

The fixture binds a free HTTPS port from 19001 through 19009, uses distinct random `auth-saml-*.memberid.localhost` and `sp-saml-*.memberid.localhost` names, and creates a labelled, disposable PostgreSQL 18.6 container with loopback-only database access and tmpfs data. The native executable listens on an additional ephemeral loopback HTTP port behind the fixture's HTTPS proxy. Port 19000 and the persistent development preview are not used.

TLS, SP signing, and IdP signing use separate generated keys. The automated client resolves only its fixture names to loopback and explicitly trusts the generated TLS certificate while checking hostnames. No system/browser trust entries are installed. The owner-checked cleanup stops the executable and HTTPS server, removes the database container and its data, and deletes its generated installation and keys under `.local/saml-interop-*`. The caller's distribution remains available. After a force-killed runner, inspect any remaining labelled resources before removing only those owned by that run.

## Consumer policy and checks

The HTTPS SP serves login, POST ACS, and a cookie-authenticated session endpoint. Node-SAML generates signed RSA-SHA256 Redirect requests and requires both response and assertion signatures. Its configuration pins the IdP entity ID/certificate, enables `validateInResponseTo: "always"` and `rejectReplayedAssertions: true`, and uses its atomic in-memory request consumption and assertion-ID reservation. This cache is suitable for this single-process fixture; deployed multi-process SPs need shared atomic storage.

Node-SAML 5.2.0 only warns about Destination/Recipient mismatches. The consumer therefore explicitly validates the exact ACS Destination from the independently verified response reference and Recipient from Node-SAML's verified assertion, before creating an application session. These checks are consumer policy, not a claim that the library defaults enforce them. See the [upstream library](https://github.com/node-saml/node-saml/tree/v5.2.0) and [SAML Web Browser SSO profile](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf).

Acceptance covers:

- A signed AuthnRequest, ordinary password/consent flow, signed POST response, and authenticated SP session with a persistent NameID.
- Opaque URL-shaped RelayState returned unchanged without becoming the IdP form destination or an SP redirect.
- Repeated and simultaneous ACS submissions. Exactly one simultaneous response creates a session. A separate probe restores only the pending request ID and leaves the assertion cache intact, proving assertion-ID replay rejection independently of request consumption.
- Correctly signed negative responses for Audience, Recipient, Destination, response and subject InResponseTo, issuer, expired Conditions, future NotBefore, and expired bearer confirmation. Each must fail for the intended constraint and leave the caller unauthenticated.
- Signature tampering, and checks that captured MemberID output excludes the tested assertion, NameID, and password. The fixture does not print raw protocol messages or credentials.
- Blocking the Member through the ordinary operator CLI after starting another SAML login. The pending transaction cannot issue an assertion, while the SP's already established application session remains authenticated.
- Administrator-managed email through the packaged CLI: default omission, explicit SP attribute authorization, current-value updates, clearing without synthesis, provenance without mailbox verification, and stable NameID throughout.
- [Signing rollover](saml-signing.md) using the operator commands: public candidate export, failed candidate preservation, SP trust overlap, explicit process restart, old in-flight response acceptance, a missed SP trust update and rollback, and old-key rejection after trust removal. A consistent PostgreSQL/protected-file backup is restored into a new isolated database/directory, preserving NameID and OIDC keys. Measured single-process restart interruptions are reported; the fixture requires each restart to finish within 30 seconds, which is a test bound rather than a deployment guarantee.

Only the negative-response driver receives the synthetic IdP private key to create valid signatures around invalid constraints. The SP receives the public certificate. This distinguishes semantic validation from simply rejecting a broken signature.

## Observed acceptance and limits

On 2026-11-16, the Windows amd64 `0.0.0-email104-final` distribution with schema 25 passed all 15 scenarios (16 passing test results including the parent) with Go 1.27.4, Node 26.13.1, PostgreSQL 18.6 and Node-SAML 5.2.0. The added managed-email scenario exercised the packaged CLI and an authenticated SP session through omission, explicit release, update and clearing while preserving NameID.

On 2026-11-16, the Windows amd64 `saml101` distribution built with Go 1.27.4 and Node.js 26.13.1 passed all 12 consumer scenarios (13 test results including the parent), using HTTPS port 19001 and the pinned PostgreSQL 18.6 image. Its executable SHA-256 was `4a27005b0b6e96962349f80201da2fba9aa12a12f9bd8c1e1682640d1674bdef`. The temporary fixture was removed after the run.

The `saml105` distribution passed the expanded 13 scenarios (14 test results including the parent) on the same date and toolchain, again using HTTPS port 19001 and pinned PostgreSQL 18.6. Its executable SHA-256 was `a8835ed980a4586d4131c3c999c828bd92d305a79c9cc0bed6034a156c683e60`. The operator blocked the Member after a new login had started; MemberID reported no eligible identity and emitted no assertion, while the existing SP session retained its NameID and remained authenticated. The fixture removed its temporary installation, signing/TLS keys, and database after the run.

The Windows amd64 `saml102` distribution passed the expanded 14 scenarios (15 test results including the parent) on 2026-11-16 with the same toolchain, HTTPS port 19001, and pinned PostgreSQL 18.6. Its executable SHA-256 was `2daf58446f3f544d6e9acb13c931457c60e33cb44ef44f72e5eefd5310db9395`. The three signing-change restarts measured 231, 232, and 240 milliseconds in this local fixture. The SP accepted both the old in-flight response and the new signer during overlap, rejected the new signer when trust was intentionally stale, recovered after explicit rollback, and rejected the old signer after trust removal. Restoring the consistent backup into a new database and installation preserved the original certificate, NameID, and OIDC public keys. The fixture removed its database, restored database, protected backup, and generated keys after the run.

This establishes automated HTTP interoperability with this explicitly configured independent consumer. It is not browser inspection, an unmodified GitLab SAML deployment, general SAML conformance/certification, or real DingTalk/Feishu/SMS validation. ForceAuthn remains explicitly unsupported; the IdP returns a signed `RequestUnsupported` status without silently reusing an existing session. See [initial profile acceptance](saml.md#initial-profile-acceptance) for the baseline criteria and separately tracked extensions.
