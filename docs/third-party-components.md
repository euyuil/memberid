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

The administration console now includes reviewed shadcn component source, React, Base UI, Lucide icons, and generated local CSS/JavaScript. It uses system fonts. Exact frontend/toolchain versions, transitive packages, platform-specific optional packages, and distribution boundaries are recorded in [the console inventory](web-components.md). Retained browser/source notices are in `third_party/web/NOTICES.txt` and accompany every distribution.

## Local Compose development

The local Compose build uses the official Node.js 26.13.1 and Go 1.27.4 images as build stages. They provide the reviewed toolchains and system dependencies. The Node.js release includes the [Node and bundled-components license file](https://github.com/nodejs/node/blob/v26.13.1/LICENSE). Build stages stay in their upstream distributions. The final local MemberID image contains the MemberID executable, embedded console build, and repository notices.

Caddy 2.11.9 is Apache-2.0. Local development runs the unmodified [official Caddy Alpine image](https://github.com/caddyserver/caddy-docker/tree/d322e6686bbce5622d98a04c84fadd43b5eb8c58/2.11/alpine), pinned by its multi-platform digest in Compose. The [Caddy license](https://github.com/caddyserver/caddy/blob/v2.11.9/LICENSE) and [image recipe license](https://github.com/caddyserver/caddy-docker/blob/d322e6686bbce5622d98a04c84fadd43b5eb8c58/LICENSE) were reviewed. The image's Alpine system packages include GPL, MIT, MPL, BSD, Apache, curl, and other upstream license terms. Setup mounts the image's CA trust bundle as local configuration rather than copying it into the MemberID image. The proxy image and trust bundle are pulled or extracted locally and are not redistributed by MemberID.

## PostgreSQL driver and tests

The runtime uses pgx v5.11.0 (MIT), selected from its upstream stable release. Its resolved runtime dependencies are pgpassfile v1.0.0 (MIT), pgservicefile v0.0.0-20240606120523-5a60cdf6a761 (MIT), puddle/v2 v2.2.3 (MIT), golang.org/x/sync v0.25.0 (BSD-3-Clause), and golang.org/x/text v0.44.0 (BSD-3-Clause). Exact module license texts and applicable Go patent grants were reviewed and retained under `third_party/modules/`. No dependency source is modified. Built distributions include these notices.

The module checksum file also records upstream dependency-test modules that are not linked into the executable. Checksum retention does not copy their source into MemberID. Reassess the inventory when adding dependencies or distributing additional tooling.

PostgreSQL 18.6 is the current supported stable PostgreSQL line at this review, per [upstream's version table](https://www.postgresql.org/support/versioning/). Integration tests use the unmodified official image `postgres:18.6@sha256:bd5dfa494a5a259704365813dbfa5fa6b3e69be7348d43b547f540c730478583`. PostgreSQL runs as a separate process and is not linked into MemberID. Its PostgreSQL, Debian packaging, and installed system-component notices remain in the upstream image. The image is also used unmodified for local Compose development and is not republished by this repository. PostgreSQL's own permissive license does not replace the separate BSD, MIT, Tcl, Artistic, GPL, LGPL, and other notices in its distribution. Redistributing a database or base image requires its own complete notice and source-offer review.

## OIDC provider and cryptography

The current protocol implementation uses upstream stable `github.com/zitadel/oidc/v3` v3.52.0 and `github.com/go-jose/go-jose/v4` v4.1.9. Both are Apache-2.0. The provider's `NOTICE` and go-jose's nested BSD-3-Clause `json/LICENSE` were inspected and retained with their root licenses. Dependency code is used unmodified; it is linked into the executable, not copied into application source.

The following additional resolved runtime modules were reviewed from their exact downloaded module contents. Their license texts are retained under `third_party/modules/` and included by the build script.

| Module | Version | License |
| --- | --- | --- |
| github.com/bmatcuk/doublestar/v4 | v4.10.4 | MIT |
| github.com/cespare/xxhash/v2 | v2.3.0 | MIT |
| github.com/go-chi/chi/v5 | v5.5.0 | MIT |
| github.com/go-logr/logr | v1.4.4 | Apache-2.0 |
| github.com/go-logr/stdr | v1.2.2 | Apache-2.0 |
| github.com/gorilla/securecookie | v1.1.2 | BSD-3-Clause |
| github.com/google/uuid | v1.6.0 | BSD-3-Clause |
| github.com/muhlemmer/gu | v0.3.1 | Unlicense |
| github.com/muhlemmer/httpforwarded | v0.1.0 | BSD-3-Clause |
| github.com/rs/cors | v1.11.1 | MIT |
| github.com/zitadel/schema | v1.3.2 | BSD-3-Clause |
| go.opentelemetry.io/auto/sdk | v1.2.1 | Apache-2.0 |
| go.opentelemetry.io/otel | v1.47.0 | Apache-2.0 |
| go.opentelemetry.io/otel/log | v1.47.0 | Apache-2.0 |
| go.opentelemetry.io/otel/metric | v1.47.0 | Apache-2.0 |
| go.opentelemetry.io/otel/trace | v1.47.0 | Apache-2.0 |
| golang.org/x/oauth2 | v0.38.0 | BSD-3-Clause |

The existing pgx, x/sync, and x/text versions above remain part of the executable. OpenTelemetry modules are kept on the current v1.47.0 stable line. No telemetry exporter or collector is configured by MemberID.

Apache-2.0 preservation, notice, modification-marking, and patent conditions apply to distributed material. MIT and BSD notice/disclaimer conditions also apply. The exact `gu` Unlicense text grants unrestricted public-domain use with a warranty disclaimer; retain it as provenance. These reviewed components impose no application source-disclosure or commercial-use restriction. Their terms do not determine the project's own license.

The resolved module graph also includes upstream test/tool-only modules: their actual license files, including nested material, were inspected. They use MIT, BSD, ISC, and Apache terms, remain unmodified in the module cache, and are not linked into the MemberID executable or shipped in a browser. A checksum entry is not a distribution of that module. Reassess this boundary if future tests import those modules directly or if additional tooling is packaged.

The console's relying-party import also adds checksum records for upstream tests using `github.com/jeremija/gosubmit` v0.2.8 (MIT) and `golang.org/x/net` v0.55.0 (BSD-3-Clause). Their exact module license files were reviewed; these packages are not imported by MemberID or distributed in its executable. Preserve their notices if that distribution boundary changes.

## DingTalk stream transport

The stream adapter links unmodified `github.com/coder/websocket` v1.8.15, the [upstream stable release](https://github.com/coder/websocket/releases/tag/v1.8.15) at revision `9c8faadccd1b679e811a79ce506f8a10237251ad`. The exact downloaded module and its `go.mod` were inspected: it requires Go 1.23 and adds no module dependencies. Its root `LICENSE.txt` is ISC, copyright 2025 Coder; no additional LICENSE, COPYING, NOTICE, or PATENTS files were present. The retained notice is under `third_party/modules/github.com/coder/websocket@v1.8.15/` and accompanies build output.

ISC permits use, modification, and redistribution, including commercial use, with its copyright and permission notice retained. It includes a warranty disclaimer and no application source-disclosure obligation. This library is linked into the server executable and used by local WebSocket tests; it is not delivered to browsers. The official DingTalk SDK was consulted as a protocol reference, without copying its implementation or adding it as a dependency. This review does not select MemberID's own license.

## Native and container distributions

The distribution builder uses the existing Go 1.27.4 toolchain with cgo disabled. Native packages retain the complete reviewed `third_party/` directory. The Linux container copies that same statically linked executable and its notices into `FROM scratch`; no base operating-system image, libc, shell, package manager, or extra dependency is incorporated. The image retains notices under `/usr/share/memberid/third_party/` and build metadata under `/usr/share/memberid/BUILDINFO`.

Docker/BuildKit is an external build/runtime tool and is not copied into MemberID. The Dockerfile has no external frontend or base-image download. A CA bundle is a required operator-supplied runtime mount and is not copied into the image or native package. Its source, updates, and any redistribution obligations belong to the deployment's trust-store distribution. Reassess this inventory before bundling certificates, an operating-system layer, or other runtime material. No project license or public release is selected by these packaging commands.

## External GitLab acceptance fixture

The opt-in interoperability check runs unmodified `gitlab/gitlab-ce:19.5.5-ce.0` for Linux amd64, pinned to manifest `sha256:5f97f753bb3b990271c26670aa3f49fe5adf9c752ea783bf4b2c86d76b27ba4d`. The image release metadata, GitLab source license, `/opt/gitlab/LICENSE`, `/opt/gitlab/LICENSES/`, `/opt/gitlab/dependency_licenses.json`, and `/opt/gitlab/licenses/` component inventories were inspected. GitLab CE code is MIT, Linux-package source has Apache-2.0 terms, and documentation has separate Creative Commons terms. The entire image is not uniformly MIT licensed; see [GitLab's package licensing records](https://docs.gitlab.com/administration/package_information/licensing/).

The image retains bundled system, server, Ruby, JavaScript, font, and data notices. Its inventories include MIT, BSD, Apache-2.0, ISC, MPL-2.0, GPL, LGPL, Ruby/Artistic, EPL-2.0, SIL OFL, CC-BY, PostgreSQL, and other component-specific terms. The PDF gems' retained `COPYING` files permit Ruby terms or GPL alternatives. Generated metadata is not a blanket license grant: `syslog_protocol` 0.9.2 is labelled unknown in the image, while its [upstream README](https://github.com/eric/syslog_protocol) contains an MIT grant; the packaged gem omits that README. The embedded `inspec-core` 6.6.0 `Chef-EULA` file refers packaged RubyGems distributions to separate Progress Chef terms. The fixture neither invokes InSpec nor enables remote syslog. Those components are not adopted as MemberID dependencies, and their labels do not become an allowlist for future incorporation or redistribution.

This use is limited to an external, unmodified, disposable GitLab application reached through HTTP/OIDC. No GitLab code, assets, fonts, bundled libraries, or image layers are incorporated into MemberID source or distributions. This repository does not modify or republish the GitLab image. The normal upstream image retains its own notices and provides GitLab's browser assets only within the local test. MemberID's distributed executable and container remain the artifacts described above. Modification, incorporation, redistribution, or a new use of any bundled component requires a separate exact-version review, including missing notices, source-disclosure/source-offer duties, font and data attribution, patent conditions, and any separately licensed tooling. This fixture review does not choose MemberID's project license.
