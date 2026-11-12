# Third-party components

The project license remains undecided. This inventory records third-party obligations without assigning a license to MemberID.

## Runtime and toolchain

The executable uses Go 1.27.4 and the reviewed PostgreSQL driver dependencies listed below. The [upstream stable release index](https://go.dev/dl/?mode=json) and exact `go1.27.4` license files were reviewed.

Go is distributed under BSD-3-Clause with an additional patent grant. Standard-library vendored `golang.org/x/crypto`, `x/net`, `x/sys`, and `x/text` carry BSD-3-Clause notices and patent grants. Retained notices are under `third_party/go/` and must accompany distributed binaries. No Go source is modified. Default builds do not enable the optional BoringCrypto implementation.

The toolchain includes build-only third-party material, including its Go module tooling, pprof, demangle, and compiler support packages. Their upstream license and patent files remain in the unmodified toolchain distribution; the compiler itself is not redistributed as part of MemberID. This review does not cover future container base images, which need a separate inventory before adoption.

## CI and development

| Component | Exact version or revision | Terms and use |
| --- | --- | --- |
| actions/checkout | v7.0.1, `3d3c42e5aac5ba805825da76410c181273ba90b1` | MIT action, executed unmodified in CI; not bundled into MemberID. |
| actions/setup-go | v7.0.0, `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` | MIT action, executed unmodified in CI; not bundled into MemberID. |
| Gitleaks | v8.30.1 | MIT CLI, executed unmodified locally and in CI; not bundled into MemberID. |
| Git and POSIX shell | Host or runner installation | Development tools, not copied or redistributed by MemberID. Git and GNU Bash have GPL terms governing their own distributions; invoking them does not incorporate their code into this executable. |

The action releases' actual `LICENSE` and `.licenses/npm/` files were reviewed, including their bundled dependencies. The resolved action inventory is in [CI components](ci-components.md). It includes MIT, Apache-2.0, ISC, 0BSD, and Blue Oak Model License 1.0.0 material. These dependencies remain in the upstream action distributions and are not delivered to MemberID users.

Upstream records labelled `other` were inspected individually: the reviewed `@actions/http-client`, `balanced-match`, `brace-expansion`, and `concat-map` texts contain MIT grants. This is a finding about those exact bundled versions, not a blanket acceptance of unknown licenses. Blue Oak's notice/link obligation and patent grant apply to the reviewed minimatch package; Apache-2.0 notice and patent conditions apply to the reviewed Apache components. Preserve those terms if any action material is later redistributed.

CI downloads the exact Gitleaks Linux x64 archive and verifies SHA-256 `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`. The archive contains the binary, README, and upstream MIT license; those files remain together in the runner's tool directory. Its compiled dependency versions and inspected license families are recorded in [the scanner inventory](gitleaks-components.md), including the conditions for external-tool-only MPL-2.0 usage. Review changes to the scanner and its distribution before updating this pin.

No third-party fonts, icons, browser bundles, copied UI components, or generated client libraries are included in this initial implementation.

## PostgreSQL driver and tests

The runtime uses pgx v5.11.0 (MIT), selected from its upstream stable release. Its resolved runtime dependencies are pgpassfile v1.0.0 (MIT), pgservicefile v0.0.0-20240606120523-5a60cdf6a761 (MIT), puddle/v2 v2.2.3 (MIT), golang.org/x/sync v0.25.0 (BSD-3-Clause), and golang.org/x/text v0.44.0 (BSD-3-Clause). Exact module license texts and applicable Go patent grants were reviewed and retained under `third_party/modules/`. No dependency source is modified. Built distributions include these notices.

The module checksum file also records upstream dependency-test modules that are not linked into the executable. Checksum retention does not copy their source into MemberID. Reassess the inventory when adding dependencies or distributing additional tooling.

PostgreSQL 18.6 is the current supported stable PostgreSQL line at this review, per [upstream's version table](https://www.postgresql.org/support/versioning/). Integration tests use the unmodified official image `postgres:18.6@sha256:bd5dfa494a5a259704365813dbfa5fa6b3e69be7348d43b547f540c730478583`. PostgreSQL runs as a separate process and is not linked into MemberID. Its PostgreSQL, Debian packaging, and installed system-component notices remain in the upstream image. The image is used only for disposable tests and is neither modified nor republished by this repository. PostgreSQL's own permissive license does not replace the separate BSD, MIT, Tcl, Artistic, GPL, LGPL, and other notices in its distribution. Redistributing a database or base image requires its own complete notice and source-offer review.
