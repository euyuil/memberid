# Repository Guidelines

MemberID is a self-hosted OpenID Connect provider with independent member identities for each organization. Use **MemberID** in documentation and UI, and `memberid` for repository, package, executable, and image names where appropriate.

The repository is being bootstrapped. These guidelines define intended implementation boundaries; they do not imply that tooling, integrations, or protocol certification already exist.

## Product and Identity Boundaries

- Keep MemberID independently buildable, deployable, and manageable. A clean checkout must build and run using only its declared public dependencies and documented configuration.
- Provide one MemberID implementation and release artifact for all supported deployments. Applications integrate through documented interfaces; keep application-specific adapters in their owning projects.
- An organization's Member is an independent identity. The same natural person may have separate Members in different organizations. Do not introduce a mandatory global User account or automatically merge Members across organizations.
- Keep Member identities separate from authentication factors and external provider bindings. Matching phone numbers, email addresses, or display names alone must not link accounts or transfer access.
- Identify OIDC accounts by the standard `(iss, sub)` pair. Subjects must remain stable across profile or credential changes, must not be reassigned, and must distinguish different Members within an issuer.
- MemberID owns organization and Member identity, authentication, provider bindings, and its own management access. Consuming applications own their business roles, resource permissions, and authorization decisions. Do not import application-specific administrative roles or resource grants into identity claims.
- Keep management interfaces separate from OIDC protocol interfaces. Document management authentication and authorization explicitly; being an authenticated Member must not imply administrative access.
- Keep external authentication providers optional and isolated behind their integration boundaries. Do not make a particular SMS vendor, enterprise platform, or downstream application a prerequisite for operating MemberID.

## OpenID Connect and Token Lifecycle

- Implement standard OIDC and OAuth behavior using suitable maintained protocol libraries. Keep protocol and cryptographic behavior grounded in maintained implementations and published standards.
- Use Authorization Code flow with PKCE using `S256` for interactive clients. Document supported discovery metadata, endpoints, client authentication methods, scopes, claims, and logout behavior. Advertise only capabilities actually implemented.
- Use the standard token endpoint and Refresh Token grant for renewal. Do not introduce a private renewal endpoint, a proprietary intermediate authentication proof, or a mandatory iframe flow.
- Server-side state for authorization transactions, sessions, grants, and Refresh Token rotation is allowed. Choose state and transaction boundaries that support protocol correctness, replay detection, revocation, and documented logout behavior.
- Keep ID Tokens, access tokens, and Refresh Tokens distinct in purpose and validation. ID Tokens authenticate a user to their intended client; they are not API bearer credentials. APIs must validate access tokens for the intended issuer, recipient, lifetime, and permissions.
- Validate redirect URIs, client identity, PKCE, issuer, audience, signatures, expiry, and applicable nonce and state bindings at the correct protocol boundaries. Authorization codes must be single-use and bound to the original client and authorization request.
- Protect Refresh Tokens and client credentials at rest and in logs. Make token rotation and replay handling atomic. Keep original authentication time, session limits, and grant expiry explicit; renewal must not silently turn an expiring login into an unlimited one.
- Clients may refresh automatically during foreground use through standard OAuth requests, without a separate confirmation click or navigation when the existing grant remains valid. Fresh authentication, consent, or interaction may still be required when the protocol or configured policy requires it.
- Do not require a shared browser origin or application-specific behavior for protocol interoperability. Browser and backend clients must follow their documented security model, including appropriate credential storage, cookie protection, and CSRF defenses.
- Treat compatibility with an unmodified GitLab OIDC client as an acceptance target. Do not claim OIDC certification or complete conformance from a successful integration alone.

## Project Structure, Build, and Run

- Before changing code, read applicable directory instructions and relevant documentation. Inspect the actual implementation, dependency manifests, lockfiles, scripts, and runtime requirements rather than assuming a stack or layout.
- Create directories and abstractions only when implementation needs them. Keep protocol handling, identity rules, persistence, provider integrations, and management UI responsibilities clear without speculative frameworks.
- Once tooling is introduced, use the runtime versions, package manager, lockfiles, and commands declared by this repository. Record reproducible installation, build, test, run, and deployment commands in `CONTRIBUTING.md` and `docs/`.
- Run commands from the repository root unless documented otherwise. Verify the target shell, tool versions, executable permissions, and line endings when crossing host or container boundaries. POSIX scripts and hooks must use LF line endings.
- Reuse existing persistent toolchain installations. Do not install ad hoc Go distributions in temporary directories; follow the repository's documented toolchain management.
- Keep standalone build and deployment validation independent of local workspace overrides and consumer repositories. Application-specific deployment and authorization configuration belongs in the consuming application.
- Keep generated output, caches, runtime data, database files, and raw logs out of version control. Add appropriate ignore rules when introducing them.

## Coding Style and Documentation

- Write documentation, code comments, commit messages, and pull request text in English. Localized UI and explicitly localized documentation use their target language.
- Follow the conventions and formatters of each language and package. Prefer clear domain names such as `organization` over project-defined abbreviations.
- In Go, use `ID` for identifier initialisms, such as `OrganizationID`, and `id` for a standalone unexported identifier. Use explicit JSON tags for API names.
- Use lowerCamelCase for project-defined HTTP/JSON fields, with `Id` suffixes such as `organizationId` and `memberId`. Preserve names required by OIDC, OAuth, and other external protocols, including `client_id`, `redirect_uri`, and `refresh_token`.
- Use descriptive plural snake_case database table names and snake_case columns. Keep independently owned identifiers and revision counters distinct.
- Validate untrusted input at actual boundaries. Avoid silent security fallbacks, speculative compatibility layers, and retries of non-idempotent operations without an explicit safety mechanism.
- Keep each change focused on one coherent outcome, including relevant tests and documentation. Preserve unrelated work and user data; do not reset a checkout or delete data to simplify a change.
- Keep `README.md` concise: project purpose, getting started, and documentation entry points. Keep repository policy in `AGENTS.md`, contributor procedures in `CONTRIBUTING.md`, and detailed architecture, protocols, deployment, and operations in `docs/`.
- Document identity boundaries, token lifecycle, configuration, supported client behavior, and operational limitations when they change. Do not present design intentions as verified behavior.
- For login and management UI, keep fields and action areas stable during validation, requests, and countdowns. Reserve space for feedback or use accessible feedback outside normal layout; do not hide actionable messages to prevent layout shifts.

## Testing and Acceptance

- During the demo stage, allow breaking changes and qualify fresh installations and current behavior without upgrade rehearsals, historical-data migrations, or speculative compatibility layers. This does not authorize deleting existing data.
- Prioritize implemented business behavior and focused automated checks. Use actual-browser inspection for a concrete UI or browser-specific uncertainty, not as a mandatory gate for every change. Do not repeat passed acceptance without a relevant change, failed assertion, or unresolved gap.
- Test meaningful behavior and security regressions, not implementation details or coverage counts. Reuse existing helpers before adding new test infrastructure.
- Use synthetic identities, credentials, organizations, and fixtures. Isolate test databases and state, clean up owned test resources, and never run destructive tests against a user's working database.
- Stub external providers in unit tests. Use targeted integration tests for actual database transactions, token issuance and validation, session expiry, concurrent code redemption, Refresh Token rotation and replay, revocation, and organization isolation.
- Verify that separate Members remain distinct even when they share contact attributes. Test account binding and management authorization boundaries explicitly.
- Verify discovery, authorization, token exchange, UserInfo, key rotation, and supported logout behavior through real HTTP interfaces. Include negative cases for invalid clients, redirect URIs, audiences, expired credentials, and replayed credentials.
- Validate GitLab compatibility with an unmodified GitLab deployment and its standard OIDC integration. Document the exact versions, configuration, and observed outcomes. A simulated client is insufficient. Automated checks against an actual GitLab deployment must complete its OIDC callback and confirm its authenticated application session; distinguish this from actual-browser inspection.
- Keep generic interoperability checks here and application-specific integration checks in each consuming application. Both must consume the same MemberID release implementation.
- Run checks appropriate to the change and report their results. Distinguish static checks, unit tests, database integration tests, browser verification, real provider verification, and deployed acceptance. Mark checks not performed or blocked explicitly.
- Do not invent existing CI jobs, scripts, coverage thresholds, or successful checks. Follow the tooling actually present in the repository.

## Commits and Pull Requests

- When the repository owner requests implementation or fixes, that request authorizes the complete delivery workflow within the requested scope: create branches, edit code, run checks, commit, push, open PRs, address CI and review findings, and squash-merge into `main`. Do not request another merge confirmation once the merge conditions are satisfied.
- Explicit task boundaries override this default. Discussion, planning, review-only work, and requests to prepare changes without submitting them do not authorize publication or merging. Follow explicit instructions such as "do not commit", "draft PR only", or "wait for my review".
- For a task containing multiple independent issues, work sequentially by default: revalidate one issue against current `main`, implement a focused fix if needed, validate it, submit one PR, wait for its checks, resolve blocking findings, and squash-merge it before starting implementation of the next issue. Start the next branch from the updated `main`. Do not accumulate completed, unmerged PRs unless the owner requests that workflow.
- Before fixing each issue, confirm that it still exists and warrants a change. If it is not a real issue or is already resolved, record the evidence and skip it. Prefer a focused correction over speculative abstractions or unnecessary defensive code.
- Before merging, review the complete PR diff and existing review feedback, verify that required checks pass for the latest revision, and satisfy repository protection and approval requirements. Resolve routine CI failures and merge conflicts within scope without asking for renewed permission. Never bypass checks or required approvals.
- An implementation item is complete only after its PR is verified as merged into `main`, or the issue is explicitly skipped with evidence. Opening a PR alone does not complete an implementation task.
- Use Conventional Commits, such as `feat: add OIDC client registration`. Keep each commit focused.
- Scope each PR to one clearly stated purpose and a complete outcome that can be reviewed, validated, and merged independently. Include the implementation, tests, and documentation needed for that outcome.
- Split unrelated cleanup, broad refactoring, and additional features into separate PRs when they provide independently useful results. Do not bundle independent concerns into the same PR.
- Keep tightly coupled changes together so intermediate merged states build, remain usable, and preserve correctness. Do not split a change so that a later PR is required to make an earlier one work correctly.
- Judge PR size by the reasoning and validation required to review it. Use diff size as a review signal, not a hard line-count limit. A reviewer should be able to understand the whole change around one concrete problem; split changes that require independent lines of reasoning.
- For an unusually large PR, explain why its changes form one coherent outcome, why further splitting is not reasonable, and provide validation evidence covering the affected components and their interactions.
- The first commit on the empty default branch requires explicit authorization. After bootstrap, integrate changes into `main` through PRs using squash merge. Do not push changes directly to `main`, force push, or create merge commits.
- Use descriptive purpose-based branch names such as `feat/oidc-discovery` or `fix/refresh-token-replay`. Do not use agent-branded prefixes such as `codex/`, `claude/`, `copilot/`, or `cursor/`, or include agent credits elsewhere in branch names.
- Preserve the configured human Git identity. Verify author and committer identities before committing and the submitting account before opening a PR.
- Review the complete staged diff and proposed commit message. Run `git diff --check`, `git diff --cached --check`, relevant validation, and a staged Gitleaks secret scan before committing. Do not bypass hooks or weaken checks to make a change pass.
- When versioned hooks exist under `.githooks/`, enable them with `git config --local core.hooksPath .githooks`. Verify that the directory and hooks exist first; until then, run the required checks explicitly.
- Describe the concrete problem, resulting behavior, and validation in each PR. Include relevant UI evidence where useful and identify any unperformed checks. Merge only within the authorized scope after required checks pass and blocking findings are resolved.
- Treat releases, package or image publication, deployment, and shared-environment changes as separate operations that require authorization within the task scope.

## Secrets, Dependencies, and Licensing

- Treat all repository content as public. Never commit secrets, real identity data, private business information, personal machine configuration, machine-specific absolute paths, or unreviewed logs and screenshots.
- Use placeholders and synthetic examples. Review proposed files and Git metadata for credentials, private infrastructure details, internal identifiers, unrelated personal information, and third-party material before publication.
- Review the actual versions and license files of direct and transitive dependencies, copied code, assets, generators, and bundled material before adoption or updates. Include browser-delivered, build, development, test, and distributed binary or image contents in the review.
- Prefer the latest suitable upstream-supported LTS release, or the latest stable release when no LTS exists. Verify support status and compatibility, and document any constraint requiring an older supported version.
- Record dependency versions, licenses, attribution requirements, and distribution constraints in `docs/third-party-components.md` when introducing third-party components. Preserve required notices and keep the resolved inventory current.
- Do not incorporate material with missing, unclear, or incompatible license terms. Do not introduce disclosure obligations, commercial-use restrictions, or redistribution constraints without an explicit project licensing decision.
- MemberID's project license has not been selected. Public repository visibility does not settle that decision. Do not add a project license file, declare a project license in metadata, or describe a release as licensed open source until the owner selects the license.

## Coding Agent Attribution

- Never credit coding agents, tools, vendors, or models as authors or contributors in commits, PRs, generated notices, badges, hidden comments, or session links. Ordinary factual references to a product being integrated are allowed.
- Never use agent identities as Git authors, committers, or PR authors. Preserve legitimate human authorship.
- The attribution ban applies regardless of capitalization, formatting, or trailer name, including agent credits in `Co-Authored-By`, `Assisted-by`, `Generated-by`, `Signed-off-by`, or `Reviewed-by`.
- Disable automatic attribution where supported. Inspect effective settings, branch names, Git identities, the full commit message, and raw PR text before publication.
- If a tool or enforced setting cannot comply, stop before creating the affected Git object or publishing the affected content and report the blocker. Never bypass security controls or accept prohibited attribution.
