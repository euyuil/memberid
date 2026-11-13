# Contributing

## Setup

Use Git, Go 1.27.4, a POSIX shell, and Gitleaks 8.30.1. On Windows, Git Bash provides the shell. Reuse a persistent Go installation or the official Go toolchain mechanism; do not install toolchains in temporary directories.

From the repository root, enable the versioned hooks:

```sh
git config --local core.hooksPath .githooks
```

Inspect any existing hooks configuration before changing it. The hooks require Gitleaks on Git's PATH and reject whitespace errors, detected secrets, and known coding-agent attribution patterns. They do not modify the staged content.

## Checks

```sh
sh scripts/check.sh
go test -race ./...
gitleaks git --redact --no-banner --no-color
git diff --check
```

The check script disables parent Go workspaces, checks formatting, runs vet and tests, and builds `dist/memberid` (`memberid.exe` on Windows). Builds use `-trimpath -buildvcs=false` to omit local paths and implicit VCS metadata. The race detector requires a supported C toolchain; CI runs it on Linux.

The executable can serve process health alone or the configured [OIDC provider](docs/oidc.md); operator commands and the separate [management process](docs/management-api.md) manage stored organizations, Members, and explicit factor bindings. See [the implementation plan](docs/implementation-plan.md) for the remaining identity and OIDC work.

For routine demo changes, select focused checks for the affected behavior and preserve the required PR CI checks. Fresh-installation acceptance does not require an upgrade rehearsal. Actual-browser inspection is targeted to UI or browser-specific uncertainty; automated real-client interoperability and interactive browser results must be reported separately.

## Local distributions

After the checks, run `sh scripts/package.sh VERSION NEW_OUTPUT_DIRECTORY` from the repository root. The output parent must exist. Packaging supports Linux and Windows amd64, includes notices and file checksums, and refuses existing destinations. The Linux package includes a container recipe that uses the same executable. See [distribution and deployment](docs/distribution.md) for cross-building, trust-store mounts, runtime configuration, and verification. These commands create local artifacts only.

CI builds each native package, verifies its checksums and version, and checks that an existing destination cannot be overwritten. On Linux it also runs the minimal image and compares its executable with the native package. Runtime secrets, CA bundles, and databases are supplied separately.

## Pull requests

Create a focused purpose-named branch from current `main`. For each independent issue, implement and validate the fix, submit one PR, wait for required checks, resolve blocking findings, and squash-merge it. Verify the merge, then start the next issue from the updated `main`. Do not accumulate completed, unmerged PRs unless the owner explicitly requests that workflow.

CI runs the build and tests on Linux and Windows, Linux race tests, and full-history secret scanning. The security job checks the pinned Gitleaks archive checksum before execution. Workflow dependencies are pinned to reviewed revisions.

Before committing, inspect the full staged diff and verify the configured human author and committer. Run the staged secret scan; do not bypass hooks. Before publication, review public text, Git metadata, configuration, examples, and build output for private information. Automated secret scanning does not establish that all sensitive information has been removed.

## Licensing

The project license remains undecided. Review exact dependency and bundled-material licenses before adoption, record the outcome in [the component inventory](docs/third-party-components.md), and retain required notices.

## PostgreSQL integration tests

Run `sh scripts/test-integration.sh` with Docker and the pinned Go toolchain available. The runner starts a labelled, disposable PostgreSQL 18.6 container, binds it only to loopback, runs integration tests with the race detector, and removes only its owned container. Local trust authentication is confined to that temporary test server; it is not a deployment configuration.

To use an already disposable test server, set `MEMBERID_TEST_DATABASE_URL` and run `go test -race -tags=integration -timeout=5m ./...`. The configured database role must be able to create and drop test databases. Each test creates a unique database and removes only that database. Do not use a production or personal working server.

## GitLab interoperability

See [the GitLab guide](docs/gitlab.md) for the pinned unmodified client, packaged-provider fixture, local prerequisites, synthetic SMS boundary, and separate browser inspection. CI compiles `go test -tags=interop ./internal/interop`; an actual GitLab deployment requires the explicit package environment variable and is not part of that compile check.
