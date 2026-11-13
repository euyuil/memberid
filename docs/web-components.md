# Console dependency inventory

Resolved from `web/package-lock.json`. All 403 package records, including nested versions and optional native/WASM platforms, were inspected. The frontend uses system fonts; no font binaries are bundled. This table records upstream terms, not the MemberID project license.

The UI uses shadcn 4.23.0 Base Nova components, adapted for MemberID navigation, localization and forms. The package MIT license covers the copied component source and stylesheet. Retained UI notices are in `third_party/web/NOTICES.txt`; distribution packaging includes them. Lucide includes ISC and MIT notices for inherited Feather icons.

Node.js 26.13.1 LTS and npm 11.20.0 are unmodified external build tools. The Node distribution LICENSE and npm LICENSE/third-party dependency notices were reviewed; Node includes MIT, BSD, Apache, ICU/Unicode and other bundled-component terms, and npm uses Artistic-2.0. They are not shipped in MemberID. CI checks official Node archive SHA-256 values in `scripts/ci-node.sh`.

Build-only Lightning CSS has MPL-2.0 terms. Its unmodified compiler/native bindings are not delivered in the executable or browser assets; generated CSS does not incorporate its implementation. No MPL-covered source is modified or distributed. Build-only caniuse-lite is CC-BY-4.0 data; its attribution and data license stay in the installed package. Blue Oak notice and patent provisions apply to the named tooling packages. Type-fest offers MIT or CC0; the MIT option is used. Redistribution of these tools or datasets would need their own notices and, where applicable, source provision.

Optional WASM packages are neither used by the supported native Linux/Windows x64 builds nor shipped. Some tarballs omit root licenses: the table identifies source evidence, including exact source-revision retrieval for napi-rs and the Apache humanfs monorepo. wasm-util 0.10.3 has an MIT package declaration but lacks a standalone license file in that tarball/revision; the subsequent 0.10.4 distribution supplies the author's MIT text. Do not bundle the older optional WASM toolchain as part of MemberID.

Additional bundled notices in Vite/Rolldown and package license files were reviewed. Their MIT/BSD/ISC/Apache material stays within unmodified build tools. Retain the complete upstream notices if redistributing those tools. Future dependency changes require a renewed exact-version review.

As of this implementation's audit, `npm audit --omit=dev` reports no known runtime dependency advisories. The full graph reports 15 affected package entries from two build-only issues: [minimatch pattern amplification](https://github.com/advisories/GHSA-g3hv-75wg-m249) and [deepmerge prototype poisoning](https://github.com/advisories/GHSA-gcqx-w48m-w2h4). These paths belong to ESLint/TypeScript tooling and the shadcn CLI, not the browser bundle or Go server. The current upstream dependency ranges do not select the patched minimatch major; deepmerge has no published patched version in the advisory. Keep those tools limited to reviewed source/configuration and official registry inputs. Do not apply the audit tool's proposed unrelated major downgrades. Recheck upstream fixes before updating the toolchain.

| Package | Version | Declared terms | Use | Inspected license evidence |
| --- | --- | --- | --- | --- |
| @babel/code-frame | 7.29.7 | MIT | Build/development only | LICENSE |
| @babel/compat-data | 7.29.7 | MIT | Build/development only | LICENSE |
| @babel/core | 7.29.13 | MIT | Build/development only | LICENSE |
| @babel/generator | 7.29.14 | MIT | Build/development only | LICENSE |
| @babel/helper-annotate-as-pure | 7.29.7 | MIT | Build/development only | LICENSE |
| @babel/helper-compilation-targets | 7.29.13 | MIT | Build/development only | LICENSE |
| @babel/helper-create-class-features-plugin | 7.29.13 | MIT | Build/development only | LICENSE |
| @babel/helper-globals | 7.29.7 | MIT | Build/development only | LICENSE |
| @babel/helper-member-expression-to-functions | 7.29.14 | MIT | Build/development only | LICENSE |
| @babel/helper-module-imports | 7.29.7 | MIT | Build/development only | LICENSE |
| @babel/helper-module-transforms | 7.29.14 | MIT | Build/development only | LICENSE |
| @babel/helper-optimise-call-expression | 7.29.7 | MIT | Build/development only | LICENSE |
| @babel/helper-plugin-utils | 7.29.7 | MIT | Build/development only | LICENSE |
| @babel/helper-replace-supers | 7.29.7 | MIT | Build/development only | LICENSE |
| @babel/helper-skip-transparent-expression-wrappers | 7.29.13 | MIT | Build/development only | LICENSE |
| @babel/helper-string-parser | 7.29.14 | MIT | Build/development only | LICENSE |
| @babel/helper-validator-identifier | 7.29.7 | MIT | Build/development only | LICENSE |
| @babel/helper-validator-option | 7.29.7 | MIT | Build/development only | LICENSE |
| @babel/helpers | 7.29.14 | MIT | Build/development only | LICENSE |
| @babel/parser | 7.29.14 | MIT | Build/development only | LICENSE |
| @babel/plugin-syntax-jsx | 7.29.7 | MIT | Build/development only | LICENSE |
| @babel/plugin-syntax-typescript | 7.29.7 | MIT | Build/development only | LICENSE |
| @babel/plugin-transform-modules-commonjs | 7.29.14 | MIT | Build/development only | LICENSE |
| @babel/plugin-transform-typescript | 7.29.9 | MIT | Build/development only | LICENSE |
| @babel/preset-typescript | 7.29.7 | MIT | Build/development only | LICENSE |
| @babel/runtime | 8.1.2 | MIT | UI source/style or runtime dependency | LICENSE |
| @babel/template | 7.29.7 | MIT | Build/development only | LICENSE |
| @babel/traverse | 7.29.14 | MIT | Build/development only | LICENSE |
| @babel/types | 7.29.14 | MIT | Build/development only | LICENSE |
| @base-ui/react | 1.9.0 | MIT | UI source/style or runtime dependency | LICENSE |
| @base-ui/utils | 0.5.0 | MIT | UI source/style or runtime dependency | LICENSE |
| @cacheable/memory | 2.2.0 | MIT | Build/development only | LICENSE |
| @cacheable/utils | 2.5.0 | MIT | Build/development only | LICENSE |
| @dotenvx/dotenvx | 1.75.1 | BSD-3-Clause | Build/development only | LICENSE |
| @dotenvx/primitives | 0.8.0 | BSD-3-Clause | Build/development only | LICENSE |
| @emnapi/core | 1.11.3 | MIT | Build/development only | LICENSE |
| @emnapi/core | 2.0.0-beta.2 | MIT | Build/development only | LICENSE |
| @emnapi/runtime | 1.11.3 | MIT | Build/development only | LICENSE |
| @emnapi/runtime | 2.0.0-beta.2 | MIT | Build/development only | LICENSE |
| @emnapi/wasi-threads | 1.2.3 | MIT | Build/development only | LICENSE |
| @emnapi/wasi-threads | 2.2.0 | MIT | Build/development only | LICENSE |
| @eslint-community/eslint-utils | 4.10.1 | MIT | Build/development only | LICENSE |
| @eslint-community/regexpp | 4.12.3 | MIT | Build/development only | LICENSE |
| @eslint/config-array | 0.23.5 | Apache-2.0 | Build/development only | LICENSE |
| @eslint/config-helpers | 0.7.0 | Apache-2.0 | Build/development only | LICENSE |
| @eslint/core | 1.2.1 | Apache-2.0 | Build/development only | LICENSE |
| @eslint/js | 10.0.1 | MIT | Build/development only | LICENSE |
| @eslint/object-schema | 3.0.5 | Apache-2.0 | Build/development only | LICENSE |
| @eslint/plugin-kit | 0.7.3 | Apache-2.0 | Build/development only | LICENSE |
| @floating-ui/core | 1.8.0 | MIT | UI source/style or runtime dependency | LICENSE |
| @floating-ui/dom | 1.8.0 | MIT | UI source/style or runtime dependency | LICENSE |
| @floating-ui/react-dom | 2.1.9 | MIT | UI source/style or runtime dependency | LICENSE |
| @floating-ui/utils | 0.2.12 | MIT | UI source/style or runtime dependency | LICENSE |
| @humanfs/core | 0.19.2 | Apache-2.0 | Build/development only | LICENSE |
| @humanfs/node | 0.16.8 | Apache-2.0 | Build/development only | LICENSE |
| @humanfs/types | 0.15.0 | Apache-2.0 | Build/development only | Apache-2.0 declaration; same-revision packages/core/LICENSE |
| @humanwhocodes/module-importer | 1.0.1 | Apache-2.0 | Build/development only | LICENSE |
| @humanwhocodes/retry | 0.4.3 | Apache-2.0 | Build/development only | LICENSE |
| @jridgewell/gen-mapping | 0.3.13 | MIT | Build/development only | LICENSE |
| @jridgewell/remapping | 2.3.5 | MIT | Build/development only | LICENSE |
| @jridgewell/resolve-uri | 3.1.3 | MIT | Build/development only | LICENSE |
| @jridgewell/sourcemap-codec | 1.6.0 | MIT | Build/development only | LICENSE |
| @jridgewell/trace-mapping | 0.3.31 | MIT | Build/development only | LICENSE |
| @keyv/bigmap | 1.3.1 | MIT | Build/development only | LICENSE |
| @keyv/serialize | 1.1.1 | MIT | Build/development only | LICENSE |
| @modelcontextprotocol/core | 2.4.0 | Apache-2.0 | Build/development only | LICENSE |
| @modelcontextprotocol/server | 2.4.0 | Apache-2.0 | Build/development only | LICENSE |
| @napi-rs/wasm-runtime | 1.2.2 | MIT | Build/development only | MIT; exact npm gitHead root LICENSE |
| @napi-rs/wasm-runtime | 1.2.6 | MIT | Build/development only | MIT; exact npm gitHead root LICENSE |
| @nodelib/fs.scandir | 2.1.5 | MIT | Build/development only | LICENSE |
| @nodelib/fs.stat | 2.0.5 | MIT | Build/development only | LICENSE |
| @nodelib/fs.walk | 1.2.8 | MIT | Build/development only | LICENSE |
| @oxc-project/types | 0.156.0 | MIT | Build/development only | LICENSE |
| @rolldown/binding-android-arm-eabi | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/binding-android-arm64 | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/binding-darwin-arm64 | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/binding-darwin-x64 | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/binding-freebsd-x64 | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/binding-linux-arm-gnueabihf | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/binding-linux-arm64-gnu | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/binding-linux-arm64-musl | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/binding-linux-ppc64-gnu | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/binding-linux-s390x-gnu | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/binding-linux-x64-gnu | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/binding-linux-x64-musl | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/binding-openharmony-arm64 | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/binding-wasm32-wasi | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/binding-win32-arm64-msvc | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/binding-win32-x64-msvc | 1.2.19 | MIT | Build/development only | Covered by rolldown 1.2.19 LICENSE and THIRD-PARTY-LICENSE |
| @rolldown/pluginutils | 1.1.1 | MIT | Build/development only | LICENSE |
| @sec-ant/readable-stream | 0.4.1 | MIT | Build/development only | LICENSE |
| @shadcn/registry | 0.2.1 | MIT | Build/development only | LICENSE.md |
| @sindresorhus/merge-streams | 4.0.0 | MIT | Build/development only | license |
| @tailwindcss/node | 4.3.5 | MIT | Build/development only | LICENSE |
| @tailwindcss/oxide | 4.3.5 | MIT | Build/development only | LICENSE |
| @tailwindcss/oxide-android-arm64 | 4.3.5 | MIT | Build/development only | LICENSE |
| @tailwindcss/oxide-darwin-arm64 | 4.3.5 | MIT | Build/development only | LICENSE |
| @tailwindcss/oxide-darwin-x64 | 4.3.5 | MIT | Build/development only | LICENSE |
| @tailwindcss/oxide-freebsd-x64 | 4.3.5 | MIT | Build/development only | LICENSE |
| @tailwindcss/oxide-linux-arm-gnueabihf | 4.3.5 | MIT | Build/development only | LICENSE |
| @tailwindcss/oxide-linux-arm64-gnu | 4.3.5 | MIT | Build/development only | LICENSE |
| @tailwindcss/oxide-linux-arm64-musl | 4.3.5 | MIT | Build/development only | LICENSE |
| @tailwindcss/oxide-linux-x64-gnu | 4.3.5 | MIT | Build/development only | LICENSE |
| @tailwindcss/oxide-linux-x64-musl | 4.3.5 | MIT | Build/development only | LICENSE |
| @tailwindcss/oxide-wasm32-wasi | 4.3.5 | MIT | Build/development only | Covered by @tailwindcss/oxide 4.3.5 LICENSE |
| @tailwindcss/oxide-win32-arm64-msvc | 4.3.5 | MIT | Build/development only | LICENSE |
| @tailwindcss/oxide-win32-x64-msvc | 4.3.5 | MIT | Build/development only | LICENSE |
| @tailwindcss/vite | 4.3.5 | MIT | Build/development only | LICENSE |
| @ts-morph/common | 0.27.0 | MIT | Build/development only | LICENSE |
| @tybys/wasm-util | 0.10.3 | MIT | Build/development only | 0.10.3 declares MIT; 0.10.4 includes the upstream MIT grant; optional WASM build tooling only |
| @tybys/wasm-util | 0.10.4 | MIT | Build/development only | LICENSE |
| @types/esrecurse | 4.3.1 | MIT | Build/development only | LICENSE |
| @types/estree | 1.0.10 | MIT | Build/development only | LICENSE |
| @types/json-schema | 7.0.15 | MIT | Build/development only | LICENSE |
| @types/node | 24.19.2 | MIT | Build/development only | LICENSE |
| @types/react | 19.3.0 | MIT | Build/development only | LICENSE |
| @types/react-dom | 19.3.0 | MIT | Build/development only | LICENSE |
| @types/validate-npm-package-name | 4.0.2 | MIT | Build/development only | LICENSE |
| @typescript-eslint/eslint-plugin | 8.72.2 | MIT | Build/development only | LICENSE |
| @typescript-eslint/parser | 8.72.2 | MIT | Build/development only | LICENSE |
| @typescript-eslint/project-service | 8.72.2 | MIT | Build/development only | LICENSE |
| @typescript-eslint/scope-manager | 8.72.2 | MIT | Build/development only | LICENSE |
| @typescript-eslint/tsconfig-utils | 8.72.2 | MIT | Build/development only | LICENSE |
| @typescript-eslint/type-utils | 8.72.2 | MIT | Build/development only | LICENSE |
| @typescript-eslint/types | 8.72.2 | MIT | Build/development only | LICENSE |
| @typescript-eslint/typescript-estree | 8.72.2 | MIT | Build/development only | LICENSE |
| @typescript-eslint/utils | 8.72.2 | MIT | Build/development only | LICENSE |
| @typescript-eslint/visitor-keys | 8.72.2 | MIT | Build/development only | LICENSE |
| @vitejs/plugin-react | 6.3.0 | MIT | Build/development only | LICENSE |
| acorn | 8.19.0 | MIT | Build/development only | LICENSE |
| acorn-jsx | 5.3.2 | MIT | Build/development only | LICENSE |
| ajv | 6.15.0 | MIT | Build/development only | LICENSE |
| ajv | 8.20.0 | MIT | Build/development only | LICENSE |
| ajv | 8.20.0 | MIT | Build/development only | LICENSE |
| ajv-formats | 2.1.1 | MIT | Build/development only | LICENSE |
| ansi-colors | 4.1.3 | MIT | Build/development only | LICENSE |
| ansi-regex | 5.0.1 | MIT | Build/development only | license |
| ansi-regex | 6.6.0 | MIT | Build/development only | license |
| ansi-regex | 6.6.0 | MIT | Build/development only | license |
| ast-types | 0.16.3 | MIT | Build/development only | LICENSE |
| atomically | 1.7.0 | MIT | Build/development only | LICENSE |
| balanced-match | 4.0.4 | MIT | Build/development only | LICENSE.md |
| baseline-browser-mapping | 2.11.37 | Apache-2.0 | Build/development only | LICENSE.txt |
| brace-expansion | 5.0.13 | MIT | Build/development only | LICENSE |
| braces | 3.0.3 | MIT | Build/development only | LICENSE |
| browserslist | 4.29.5 | MIT | Build/development only | LICENSE |
| bundle-name | 4.1.1 | MIT | Build/development only | license |
| cacheable | 2.5.0 | MIT | Build/development only | LICENSE |
| caniuse-lite | 1.0.30001826 | CC-BY-4.0 | Build/development only | LICENSE |
| chalk | 5.6.2 | MIT | Build/development only | license |
| class-variance-authority | 0.7.1 | Apache-2.0 | UI source/style or runtime dependency | LICENSE |
| cli-cursor | 5.0.0 | MIT | Build/development only | license |
| cli-spinners | 2.9.2 | MIT | Build/development only | license |
| clsx | 2.1.1 | MIT | UI source/style or runtime dependency | license |
| cn | 0.2.6 | MIT | Build/development only | LICENSE |
| cn | 0.2.6 | MIT | Build/development only | LICENSE |
| cn | 0.5.2 | MIT | UI source/style or runtime dependency | LICENSE |
| code-block-writer | 13.0.3 | MIT | Build/development only | LICENSE |
| commander | 11.1.0 | MIT | Build/development only | LICENSE |
| commander | 14.0.3 | MIT | Build/development only | LICENSE |
| conf | 10.2.0 | MIT | Build/development only | license |
| convert-source-map | 2.0.0 | MIT | Build/development only | LICENSE |
| cross-spawn | 7.0.6 | MIT | Build/development only | LICENSE |
| csstype | 3.2.3 | MIT | Build/development only | LICENSE |
| debounce-fn | 4.0.0 | MIT | Build/development only | license |
| debug | 4.4.3 | MIT | Build/development only | LICENSE |
| dedent | 1.7.2 | MIT | Build/development only | LICENSE.md |
| deep-is | 0.1.4 | MIT | Build/development only | LICENSE |
| deepmerge | 4.3.1 | MIT | Build/development only | license.txt |
| default-browser | 5.5.1 | MIT | Build/development only | license |
| default-browser-id | 5.0.1 | MIT | Build/development only | license |
| define-lazy-prop | 2.0.0 | MIT | Build/development only | license |
| define-lazy-prop | 3.0.0 | MIT | Build/development only | license |
| detect-libc | 2.1.2 | Apache-2.0 | Build/development only | LICENSE |
| diff | 8.0.4 | BSD-3-Clause | Build/development only | LICENSE |
| dot-prop | 6.0.1 | MIT | Build/development only | license |
| dotenv | 17.4.2 | BSD-2-Clause | Build/development only | LICENSE |
| electron-to-chromium | 1.5.485 | ISC | Build/development only | LICENSE |
| emoji-regex | 10.6.0 | MIT | Build/development only | LICENSE-MIT.txt |
| enhanced-resolve | 5.27.0 | MIT | Build/development only | LICENSE |
| enquirer | 2.4.1 | MIT | Build/development only | LICENSE |
| env-paths | 2.2.1 | MIT | Build/development only | license |
| escalade | 3.2.0 | MIT | Build/development only | license |
| escape-string-regexp | 4.0.0 | MIT | Build/development only | license |
| eslint | 10.14.0 | MIT | Build/development only | LICENSE |
| eslint-plugin-react-hooks | 7.1.1 | MIT | Build/development only | LICENSE |
| eslint-plugin-react-refresh | 0.5.7 | MIT | Build/development only | LICENSE |
| eslint-scope | 9.1.2 | BSD-2-Clause | Build/development only | LICENSE |
| eslint-visitor-keys | 3.4.3 | Apache-2.0 | Build/development only | LICENSE |
| eslint-visitor-keys | 5.0.1 | Apache-2.0 | Build/development only | LICENSE |
| espree | 11.2.0 | BSD-2-Clause | Build/development only | LICENSE |
| esprima | 4.0.1 | BSD-2-Clause | Build/development only | LICENSE.BSD |
| esquery | 1.7.0 | BSD-3-Clause | Build/development only | license.txt |
| esrecurse | 4.3.0 | BSD-2-Clause | Build/development only | BSD-2-Clause header in esrecurse.js |
| estraverse | 5.3.0 | BSD-2-Clause | Build/development only | LICENSE.BSD |
| esutils | 2.0.3 | BSD-2-Clause | Build/development only | LICENSE.BSD |
| execa | 5.1.1 | MIT | Build/development only | license |
| execa | 9.6.1 | MIT | Build/development only | license |
| fast-deep-equal | 3.1.3 | MIT | Build/development only | LICENSE |
| fast-glob | 3.3.3 | MIT | Build/development only | LICENSE |
| fast-json-stable-stringify | 2.1.0 | MIT | Build/development only | LICENSE |
| fast-levenshtein | 2.0.6 | MIT | Build/development only | LICENSE.md |
| fast-uri | 3.1.9 | BSD-3-Clause | Build/development only | LICENSE |
| fastq | 1.20.3 | ISC | Build/development only | LICENSE |
| fdir | 6.5.0 | MIT | Build/development only | LICENSE |
| figures | 6.1.0 | MIT | Build/development only | license |
| file-entry-cache | 11.1.5 | MIT | Build/development only | LICENSE |
| fill-range | 7.1.1 | MIT | Build/development only | LICENSE |
| find-up | 3.0.0 | MIT | Build/development only | license |
| find-up | 5.0.0 | MIT | Build/development only | license |
| flat-cache | 6.1.23 | MIT | Build/development only | LICENSE |
| flatted | 3.4.4 | ISC | Build/development only | LICENSE |
| fs-extra | 11.4.1 | MIT | Build/development only | LICENSE |
| fsevents | 2.3.3 | MIT | Build/development only | LICENSE |
| fuzzysort | 3.1.0 | MIT | Build/development only | LICENSE |
| gensync | 1.0.0-beta.2 | MIT | Build/development only | LICENSE |
| get-east-asian-width | 1.7.0 | MIT | Build/development only | license |
| get-own-enumerable-keys | 1.0.0 | MIT | Build/development only | license |
| get-stream | 6.0.1 | MIT | Build/development only | license |
| get-stream | 9.0.1 | MIT | Build/development only | license |
| glob-parent | 5.1.2 | ISC | Build/development only | LICENSE |
| glob-parent | 6.0.2 | ISC | Build/development only | LICENSE |
| globals | 17.14.0 | MIT | Build/development only | license |
| graceful-fs | 4.2.12 | BlueOak-1.0.0 | Build/development only | LICENSE.md |
| hashery | 1.5.1 | MIT | Build/development only | LICENSE |
| hermes-estree | 0.25.1 | MIT | Build/development only | LICENSE |
| hermes-parser | 0.25.1 | MIT | Build/development only | LICENSE |
| hookified | 1.15.1 | MIT | Build/development only | LICENSE |
| hookified | 2.2.0 | MIT | Build/development only | LICENSE |
| human-signals | 2.1.0 | Apache-2.0 | Build/development only | LICENSE |
| human-signals | 8.0.1 | Apache-2.0 | Build/development only | LICENSE |
| ignore | 5.3.2 | MIT | Build/development only | LICENSE-MIT |
| ignore | 7.0.14 | MIT | Build/development only | LICENSE-MIT |
| imurmurhash | 0.1.4 | MIT | Build/development only | MIT grant in README.md |
| ip-address | 10.7.6 | MIT | Build/development only | LICENSE |
| is-docker | 2.2.1 | MIT | Build/development only | license |
| is-docker | 3.0.0 | MIT | Build/development only | license |
| is-extglob | 2.1.1 | MIT | Build/development only | LICENSE |
| is-glob | 4.0.3 | MIT | Build/development only | LICENSE |
| is-in-ssh | 1.0.0 | MIT | Build/development only | license |
| is-inside-container | 1.0.0 | MIT | Build/development only | license |
| is-interactive | 2.0.0 | MIT | Build/development only | license |
| is-number | 7.0.0 | MIT | Build/development only | LICENSE |
| is-obj | 2.0.0 | MIT | Build/development only | license |
| is-obj | 3.0.0 | MIT | Build/development only | license |
| is-plain-obj | 4.1.0 | MIT | Build/development only | license |
| is-regexp | 3.1.0 | MIT | Build/development only | license |
| is-stream | 2.0.1 | MIT | Build/development only | license |
| is-stream | 4.0.1 | MIT | Build/development only | license |
| is-unicode-supported | 1.3.0 | MIT | Build/development only | license |
| is-unicode-supported | 2.1.0 | MIT | Build/development only | license |
| is-wsl | 2.2.0 | MIT | Build/development only | license |
| is-wsl | 3.1.1 | MIT | Build/development only | license |
| isexe | 2.0.0 | ISC | Build/development only | LICENSE |
| isexe | 3.1.5 | BlueOak-1.0.0 | Build/development only | LICENSE.md |
| jiti | 2.7.0 | MIT | Build/development only | LICENSE |
| js-tokens | 4.0.0 | MIT | Build/development only | LICENSE |
| jsesc | 3.1.0 | MIT | Build/development only | LICENSE-MIT.txt |
| json-schema-traverse | 0.4.1 | MIT | Build/development only | LICENSE |
| json-schema-traverse | 1.0.0 | MIT | Build/development only | LICENSE |
| json-schema-traverse | 1.0.0 | MIT | Build/development only | LICENSE |
| json-schema-typed | 7.0.3 | BSD-2-Clause | Build/development only | LICENSE |
| json-stable-stringify-without-jsonify | 1.0.1 | MIT | Build/development only | LICENSE |
| json5 | 2.2.3 | MIT | Build/development only | LICENSE.md |
| jsonfile | 6.2.1 | MIT | Build/development only | LICENSE |
| keyv | 5.6.0 | MIT | Build/development only | LICENSE |
| kleur | 3.0.3 | MIT | Build/development only | license |
| kleur | 4.1.5 | MIT | Build/development only | license |
| levn | 0.4.1 | MIT | Build/development only | LICENSE |
| lightningcss | 1.33.0 | MPL-2.0 | Build/development only | LICENSE |
| lightningcss-android-arm64 | 1.33.0 | MPL-2.0 | Build/development only | LICENSE |
| lightningcss-darwin-arm64 | 1.33.0 | MPL-2.0 | Build/development only | LICENSE |
| lightningcss-darwin-x64 | 1.33.0 | MPL-2.0 | Build/development only | LICENSE |
| lightningcss-freebsd-x64 | 1.33.0 | MPL-2.0 | Build/development only | LICENSE |
| lightningcss-linux-arm-gnueabihf | 1.33.0 | MPL-2.0 | Build/development only | LICENSE |
| lightningcss-linux-arm64-gnu | 1.33.0 | MPL-2.0 | Build/development only | LICENSE |
| lightningcss-linux-arm64-musl | 1.33.0 | MPL-2.0 | Build/development only | LICENSE |
| lightningcss-linux-x64-gnu | 1.33.0 | MPL-2.0 | Build/development only | LICENSE |
| lightningcss-linux-x64-musl | 1.33.0 | MPL-2.0 | Build/development only | LICENSE |
| lightningcss-win32-arm64-msvc | 1.33.0 | MPL-2.0 | Build/development only | LICENSE |
| lightningcss-win32-x64-msvc | 1.33.0 | MPL-2.0 | Build/development only | LICENSE |
| locate-path | 3.0.0 | MIT | Build/development only | license |
| locate-path | 6.0.0 | MIT | Build/development only | license |
| log-symbols | 6.0.0 | MIT | Build/development only | license |
| lru-cache | 5.1.1 | ISC | Build/development only | LICENSE |
| lucide-react | 1.72.0 | ISC | UI source/style or runtime dependency | LICENSE |
| magic-string | 1.4.5 | MIT | Build/development only | LICENSE |
| merge-stream | 2.0.0 | MIT | Build/development only | LICENSE |
| merge2 | 1.4.1 | MIT | Build/development only | LICENSE |
| micromatch | 4.0.8 | MIT | Build/development only | LICENSE |
| mimic-fn | 2.1.0 | MIT | Build/development only | license |
| mimic-fn | 3.1.0 | MIT | Build/development only | license |
| mimic-function | 5.0.1 | MIT | Build/development only | license |
| minimatch | 10.2.6 | BlueOak-1.0.0 | Build/development only | LICENSE.md |
| minimist | 1.2.8 | MIT | Build/development only | LICENSE |
| ms | 2.1.3 | MIT | Build/development only | license.md |
| nanoid | 3.3.20 | MIT | Build/development only | LICENSE |
| natural-compare | 1.4.0 | MIT | Build/development only | MIT grant linked by exact-version README |
| node-releases | 2.0.64 | MIT | Build/development only | LICENSE |
| npm-run-path | 4.0.1 | MIT | Build/development only | license |
| npm-run-path | 6.0.0 | MIT | Build/development only | license |
| object-treeify | 1.1.33 | MIT | Build/development only | LICENSE |
| onetime | 5.1.2 | MIT | Build/development only | license |
| onetime | 7.0.0 | MIT | Build/development only | license |
| open | 11.0.4 | MIT | Build/development only | license |
| open | 8.4.2 | MIT | Build/development only | license |
| optionator | 0.9.4 | MIT | Build/development only | LICENSE |
| ora | 8.2.0 | MIT | Build/development only | license |
| p-limit | 2.3.0 | MIT | Build/development only | license |
| p-limit | 3.1.0 | MIT | Build/development only | license |
| p-locate | 3.0.0 | MIT | Build/development only | license |
| p-locate | 5.0.0 | MIT | Build/development only | license |
| p-try | 2.2.0 | MIT | Build/development only | license |
| parse-ms | 4.0.0 | MIT | Build/development only | license |
| path-browserify | 1.0.1 | MIT | Build/development only | LICENSE |
| path-exists | 3.0.0 | MIT | Build/development only | license |
| path-exists | 4.0.0 | MIT | Build/development only | license |
| path-key | 3.1.1 | MIT | Build/development only | license |
| path-key | 4.0.0 | MIT | Build/development only | license |
| picocolors | 1.1.1 | ISC | Build/development only | LICENSE |
| picomatch | 2.3.2 | MIT | Build/development only | LICENSE |
| picomatch | 4.0.7 | MIT | Build/development only | LICENSE |
| pkg-up | 3.1.0 | MIT | Build/development only | license |
| postcss | 8.5.32 | MIT | Build/development only | LICENSE |
| postcss-selector-parser | 7.2.1 | MIT | Build/development only | LICENSE-MIT |
| powershell-utils | 0.2.1 | MIT | Build/development only | license |
| prelude-ls | 1.2.1 | MIT | Build/development only | LICENSE |
| prettier | 3.10.1 | MIT | Build/development only | LICENSE |
| prettier-plugin-tailwindcss | 0.8.1 | MIT | Build/development only | dist/licenses/@babel/types/LICENSE, dist/licenses/@ianvs/prettier-plugin-sort-imports/LICENSE, dist/licenses/@prettier/plugin-hermes/LICENSE, dist/licenses/@prettier/plugin-oxc/LICENSE, dist/licenses/@prettier/plugin-pug/LICENSE, dist/licenses/@trivago/prettier-plugin-sort-imports/LICENSE, dist/licenses/@types/node/LICENSE, dist/licenses/@zackad/prettier-plugin-twig/LICENSE, dist/licenses/clear-module/license, dist/licenses/dedent/LICENSE.md, dist/licenses/enhanced-resolve/LICENSE, dist/licenses/escalade/license, dist/licenses/fast-glob/LICENSE, dist/licenses/import-sort-style-module/LICENSE, dist/licenses/jiti/LICENSE, dist/licenses/line-column/LICENSE, dist/licenses/oxlint/LICENSE, dist/licenses/oxlint-tsgolint/LICENSE, dist/licenses/postcss/LICENSE, dist/licenses/postcss-import/LICENSE, dist/licenses/prettier-plugin-astro/LICENSE, dist/licenses/prettier-plugin-css-order/license.md, dist/licenses/prettier-plugin-jsdoc/LICENSE, dist/licenses/prettier-plugin-marko/LICENSE, dist/licenses/prettier-plugin-multiline-arrays/LICENSE-CC0, dist/licenses/prettier-plugin-organize-attributes/LICENSE, dist/licenses/prettier-plugin-organize-imports/license, dist/licenses/prettier-plugin-svelte/LICENSE, dist/licenses/pug-lexer/LICENSE, dist/licenses/tsdown/LICENSE, LICENSE |
| pretty-ms | 9.3.1 | MIT | Build/development only | license |
| prompts | 2.4.2 | MIT | Build/development only | license |
| punycode | 2.3.1 | MIT | Build/development only | LICENSE-MIT.txt |
| qified | 0.10.1 | MIT | Build/development only | LICENSE |
| queue-microtask | 1.2.3 | MIT | Build/development only | LICENSE |
| react | 19.3.1 | MIT | UI source/style or runtime dependency | LICENSE |
| react-dom | 19.3.1 | MIT | UI source/style or runtime dependency | LICENSE |
| recast | 0.23.21 | MIT | Build/development only | LICENSE |
| require-from-string | 2.0.2 | MIT | Build/development only | license |
| reselect | 5.3.0 | MIT | UI source/style or runtime dependency | LICENSE |
| restore-cursor | 5.1.0 | MIT | Build/development only | license |
| reusify | 1.1.0 | MIT | Build/development only | LICENSE |
| rolldown | 1.2.19 | MIT | Build/development only | LICENSE |
| run-applescript | 7.1.0 | MIT | Build/development only | license |
| run-parallel | 1.2.0 | MIT | Build/development only | LICENSE |
| scheduler | 0.28.0 | MIT | UI source/style or runtime dependency | LICENSE |
| semver | 6.3.2 | ISC | Build/development only | LICENSE |
| semver | 7.8.6 | ISC | Build/development only | LICENSE |
| semver | 7.8.6 | ISC | Build/development only | LICENSE |
| shadcn | 4.23.0 | MIT | UI source/style or runtime dependency | LICENSE.md |
| shebang-command | 2.0.0 | MIT | Build/development only | license |
| shebang-regex | 3.0.0 | MIT | Build/development only | license |
| signal-exit | 3.0.7 | ISC | Build/development only | LICENSE.txt |
| signal-exit | 4.1.0 | ISC | Build/development only | LICENSE.txt |
| sisteransi | 1.0.5 | MIT | Build/development only | license |
| smart-buffer | 4.2.0 | MIT | Build/development only | LICENSE |
| socks | 2.8.10 | MIT | Build/development only | LICENSE |
| source-map | 0.6.1 | BSD-3-Clause | Build/development only | LICENSE |
| source-map-js | 1.2.2 | BSD-3-Clause | Build/development only | LICENSE |
| stdin-discarder | 0.2.2 | MIT | Build/development only | license |
| string-width | 7.2.0 | MIT | Build/development only | license |
| stringify-object | 5.0.0 | BSD-2-Clause | Build/development only | LICENSE |
| strip-ansi | 6.0.1 | MIT | Build/development only | license |
| strip-ansi | 7.2.0 | MIT | Build/development only | license |
| strip-ansi | 7.2.0 | MIT | Build/development only | license |
| strip-bom | 3.0.0 | MIT | Build/development only | license |
| strip-final-newline | 2.0.0 | MIT | Build/development only | license |
| strip-final-newline | 4.0.0 | MIT | Build/development only | license |
| systeminformation | 5.33.21 | MIT | Build/development only | LICENSE |
| tailwindcss | 4.3.5 | MIT | UI source/style or runtime dependency | LICENSE |
| tapable | 2.3.3 | MIT | Build/development only | LICENSE |
| tiny-invariant | 1.3.3 | MIT | Build/development only | LICENSE |
| tinyglobby | 0.2.17 | MIT | Build/development only | LICENSE |
| to-regex-range | 5.0.1 | MIT | Build/development only | LICENSE |
| ts-api-utils | 2.5.0 | MIT | Build/development only | LICENSE.md |
| ts-morph | 26.0.0 | MIT | Build/development only | LICENSE |
| tsconfig-paths | 4.2.0 | MIT | Build/development only | LICENSE |
| tslib | 2.8.1 | 0BSD | Build/development only | LICENSE.txt |
| tslib | 2.9.1 | 0BSD | Build/development only | LICENSE.txt |
| tw-animate-css | 1.4.0 | MIT | UI source/style or runtime dependency | LICENSE |
| type-check | 0.4.0 | MIT | Build/development only | LICENSE |
| type-fest | 4.41.0 | (MIT OR CC0-1.0) | Build/development only | license-cc0, license-mit |
| typescript | 6.0.3 | Apache-2.0 | Build/development only | LICENSE.txt |
| typescript-eslint | 8.72.2 | MIT | Build/development only | LICENSE |
| undici | 7.30.2 | MIT | Build/development only | lib/web/fetch/LICENSE, LICENSE |
| undici-types | 7.24.6 | MIT | Build/development only | LICENSE |
| unicorn-magic | 0.3.0 | MIT | Build/development only | license |
| universalify | 2.0.1 | MIT | Build/development only | LICENSE |
| update-browserslist-db | 1.3.4 | MIT | Build/development only | LICENSE |
| uri-js | 4.4.1 | BSD-2-Clause | Build/development only | LICENSE |
| use-sync-external-store | 1.7.0 | MIT | UI source/style or runtime dependency | LICENSE |
| util-deprecate | 1.0.2 | MIT | Build/development only | LICENSE |
| validate-npm-package-name | 7.0.2 | ISC | Build/development only | LICENSE |
| vite | 8.3.8 | MIT | Build/development only | LICENSE.md |
| which | 2.0.2 | ISC | Build/development only | LICENSE |
| which | 4.0.0 | ISC | Build/development only | LICENSE |
| word-wrap | 1.2.5 | MIT | Build/development only | LICENSE |
| wsl-utils | 1.0.1 | MIT | Build/development only | license |
| yallist | 3.1.1 | ISC | Build/development only | LICENSE |
| yocto-queue | 0.1.0 | MIT | Build/development only | license |
| yocto-spinner | 1.2.2 | MIT | Build/development only | license |
| yoctocolors | 2.2.0 | MIT | Build/development only | license |
| zod | 4.6.7 | MIT | Build/development only | LICENSE |
| zod-validation-error | 4.0.2 | MIT | Build/development only | LICENSE |
