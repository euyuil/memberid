# Container publication action dependencies

Reviewed upstream releases: `actions/upload-artifact` v7.0.2 at
`cf430e030ddbb5b0abf93d22962f4752f3646cd9` and `actions/download-artifact`
v8.0.2 at `9000827ccba6bdab643e8b6fd33ac0654aef8333`. Both actions use MIT
licenses and the runner's Node 24 runtime. Root licenses, bundled license
records, lockfiles, and integrity-verified runtime dependency archives were
inspected. These unmodified actions run only in CI; none of their code or
licenses is copied into the MemberID executable, image, or browser assets.

The table combines identical package versions across the two lockfiles. `U`
means upload and `D` means download. The source links identify the exact npm
archive reviewed, not an unpinned latest package. Upstream action distributions
retain their own notices. MIT/ISC/BSD notices and disclaimers, Apache-2.0 notices
and patent conditions, and Blue Oak license/link and patent conditions apply if
this material is redistributed. No application source-disclosure or
commercial-use restriction is introduced by this external-tool use.

License metadata alone was not treated as the license text:

- `buffers` 0.1.1 omits its license in npm. Its `index.js` was compared byte-for-byte
  with the original author's [MIT/X11 declaration commit](https://github.com/bitpay/node-buffers/commit/1b745ee35d33eb166e15ef1866073a07c6d7de87), preserved in a fork. It is identical. This finding is specific to that version.
- `binary` declares MIT in its packaged README. `chainsaw` declares MIT/X11;
  the download action retains its complete MIT notice.
- `eastasianwidth` 0.2.0 omits its notice from npm. The maintainer's
  [complete MIT notice](https://github.com/komagata/eastasianwidth/blob/1d41951a59d63fb2d77cda021050fc070cae424a/MIT-LICENSE.txt)
  and [historical licensing clarification](https://github.com/komagata/eastasianwidth/blob/master/LICENSE-NOTES.md)
  cover this version. Do not substitute an automatically generated notice for
  that provenance if redistributing it.
- `package-json-from-dist` carries a Blue Oak root notice despite MIT package
  metadata. `@protobuf-ts/runtime` includes BSD-3-Clause material alongside
  Apache-2.0. Lodash's runtime grant is MIT; its documentation samples use CC0.
- Other action records classified as `other` were checked against their actual
  texts, including Node-derived stream/string-decoder MIT notices, `traverse`
  MIT/X11, `ieee754` BSD-3-Clause, and `@pkgjs/parseargs` Apache-2.0.

MemberID's own license remains undecided. Reassess these exact versions and
missing-notice provenance before changing the actions or distribution boundary.

| Package | Version | Action | Reviewed terms | Archive |
| --- | --- | --- | --- | --- |
| `@actions/artifact` | 6.3.1 | U, D | MIT | [Source](https://registry.npmjs.org/@actions/artifact/-/artifact-6.3.1.tgz) |
| `@actions/core` | 3.0.1 | U, D | MIT | [Source](https://registry.npmjs.org/@actions/core/-/core-3.0.1.tgz) |
| `@actions/exec` | 3.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/@actions/exec/-/exec-3.0.0.tgz) |
| `@actions/github` | 9.1.1 | U, D | MIT | [Source](https://registry.npmjs.org/@actions/github/-/github-9.1.1.tgz) |
| `@actions/glob` | 0.6.1 | U | MIT | [Source](https://registry.npmjs.org/@actions/glob/-/glob-0.6.1.tgz) |
| `@actions/http-client` | 3.0.2 | U, D | MIT | [Source](https://registry.npmjs.org/@actions/http-client/-/http-client-3.0.2.tgz) |
| `@actions/http-client` | 4.0.1 | U, D | MIT | [Source](https://registry.npmjs.org/@actions/http-client/-/http-client-4.0.1.tgz) |
| `@actions/io` | 3.0.2 | U, D | MIT | [Source](https://registry.npmjs.org/@actions/io/-/io-3.0.2.tgz) |
| `@azure/abort-controller` | 2.1.2 | U, D | MIT | [Source](https://registry.npmjs.org/@azure/abort-controller/-/abort-controller-2.1.2.tgz) |
| `@azure/core-auth` | 1.10.1 | U, D | MIT | [Source](https://registry.npmjs.org/@azure/core-auth/-/core-auth-1.10.1.tgz) |
| `@azure/core-client` | 1.10.1 | U, D | MIT | [Source](https://registry.npmjs.org/@azure/core-client/-/core-client-1.10.1.tgz) |
| `@azure/core-http-compat` | 2.3.1 | D | MIT | [Source](https://registry.npmjs.org/@azure/core-http-compat/-/core-http-compat-2.3.1.tgz) |
| `@azure/core-http-compat` | 2.3.2 | U | MIT | [Source](https://registry.npmjs.org/@azure/core-http-compat/-/core-http-compat-2.3.2.tgz) |
| `@azure/core-lro` | 2.7.2 | U, D | MIT | [Source](https://registry.npmjs.org/@azure/core-lro/-/core-lro-2.7.2.tgz) |
| `@azure/core-paging` | 1.6.2 | U, D | MIT | [Source](https://registry.npmjs.org/@azure/core-paging/-/core-paging-1.6.2.tgz) |
| `@azure/core-rest-pipeline` | 1.22.2 | U, D | MIT | [Source](https://registry.npmjs.org/@azure/core-rest-pipeline/-/core-rest-pipeline-1.22.2.tgz) |
| `@azure/core-tracing` | 1.3.1 | U, D | MIT | [Source](https://registry.npmjs.org/@azure/core-tracing/-/core-tracing-1.3.1.tgz) |
| `@azure/core-util` | 1.13.1 | U, D | MIT | [Source](https://registry.npmjs.org/@azure/core-util/-/core-util-1.13.1.tgz) |
| `@azure/core-xml` | 1.5.0 | U, D | MIT | [Source](https://registry.npmjs.org/@azure/core-xml/-/core-xml-1.5.0.tgz) |
| `@azure/logger` | 1.3.0 | U, D | MIT | [Source](https://registry.npmjs.org/@azure/logger/-/logger-1.3.0.tgz) |
| `@azure/storage-blob` | 12.31.0 | U, D | MIT | [Source](https://registry.npmjs.org/@azure/storage-blob/-/storage-blob-12.31.0.tgz) |
| `@azure/storage-common` | 12.3.0 | U, D | MIT | [Source](https://registry.npmjs.org/@azure/storage-common/-/storage-common-12.3.0.tgz) |
| `@isaacs/balanced-match` | 4.0.1 | D | MIT | [Source](https://registry.npmjs.org/@isaacs/balanced-match/-/balanced-match-4.0.1.tgz) |
| `@isaacs/brace-expansion` | 5.0.0 | D | MIT | [Source](https://registry.npmjs.org/@isaacs/brace-expansion/-/brace-expansion-5.0.0.tgz) |
| `@isaacs/cliui` | 8.0.2 | U, D | ISC | [Source](https://registry.npmjs.org/@isaacs/cliui/-/cliui-8.0.2.tgz) |
| `@octokit/auth-token` | 6.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/@octokit/auth-token/-/auth-token-6.0.0.tgz) |
| `@octokit/core` | 7.0.6 | U, D | MIT | [Source](https://registry.npmjs.org/@octokit/core/-/core-7.0.6.tgz) |
| `@octokit/endpoint` | 11.0.3 | U, D | MIT | [Source](https://registry.npmjs.org/@octokit/endpoint/-/endpoint-11.0.3.tgz) |
| `@octokit/graphql` | 9.0.3 | U, D | MIT | [Source](https://registry.npmjs.org/@octokit/graphql/-/graphql-9.0.3.tgz) |
| `@octokit/openapi-types` | 27.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/@octokit/openapi-types/-/openapi-types-27.0.0.tgz) |
| `@octokit/plugin-paginate-rest` | 14.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/@octokit/plugin-paginate-rest/-/plugin-paginate-rest-14.0.0.tgz) |
| `@octokit/plugin-request-log` | 6.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/@octokit/plugin-request-log/-/plugin-request-log-6.0.0.tgz) |
| `@octokit/plugin-rest-endpoint-methods` | 17.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/@octokit/plugin-rest-endpoint-methods/-/plugin-rest-endpoint-methods-17.0.0.tgz) |
| `@octokit/plugin-retry` | 8.1.0 | U, D | MIT | [Source](https://registry.npmjs.org/@octokit/plugin-retry/-/plugin-retry-8.1.0.tgz) |
| `@octokit/request` | 10.0.8 | U, D | MIT | [Source](https://registry.npmjs.org/@octokit/request/-/request-10.0.8.tgz) |
| `@octokit/request-error` | 7.1.0 | U, D | MIT | [Source](https://registry.npmjs.org/@octokit/request-error/-/request-error-7.1.0.tgz) |
| `@octokit/types` | 16.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/@octokit/types/-/types-16.0.0.tgz) |
| `@pkgjs/parseargs` | 0.11.0 | U, D | Apache-2.0 (license text) | [Source](https://registry.npmjs.org/@pkgjs/parseargs/-/parseargs-0.11.0.tgz) |
| `@protobuf-ts/runtime` | 2.11.1 | U, D | (Apache-2.0 AND BSD-3-Clause) | [Source](https://registry.npmjs.org/@protobuf-ts/runtime/-/runtime-2.11.1.tgz) |
| `@protobuf-ts/runtime-rpc` | 2.11.1 | U, D | Apache-2.0 | [Source](https://registry.npmjs.org/@protobuf-ts/runtime-rpc/-/runtime-rpc-2.11.1.tgz) |
| `@typespec/ts-http-runtime` | 0.3.2 | D | MIT | [Source](https://registry.npmjs.org/@typespec/ts-http-runtime/-/ts-http-runtime-0.3.2.tgz) |
| `@typespec/ts-http-runtime` | 0.3.5 | U | MIT | [Source](https://registry.npmjs.org/@typespec/ts-http-runtime/-/ts-http-runtime-0.3.5.tgz) |
| `abort-controller` | 3.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/abort-controller/-/abort-controller-3.0.0.tgz) |
| `agent-base` | 7.1.4 | U, D | MIT | [Source](https://registry.npmjs.org/agent-base/-/agent-base-7.1.4.tgz) |
| `ansi-regex` | 5.0.1 | U, D | MIT | [Source](https://registry.npmjs.org/ansi-regex/-/ansi-regex-5.0.1.tgz) |
| `ansi-regex` | 6.2.2 | U, D | MIT | [Source](https://registry.npmjs.org/ansi-regex/-/ansi-regex-6.2.2.tgz) |
| `ansi-styles` | 4.3.0 | U, D | MIT | [Source](https://registry.npmjs.org/ansi-styles/-/ansi-styles-4.3.0.tgz) |
| `ansi-styles` | 6.2.3 | U, D | MIT | [Source](https://registry.npmjs.org/ansi-styles/-/ansi-styles-6.2.3.tgz) |
| `archiver` | 7.0.1 | U, D | MIT | [Source](https://registry.npmjs.org/archiver/-/archiver-7.0.1.tgz) |
| `archiver-utils` | 5.0.2 | U, D | MIT | [Source](https://registry.npmjs.org/archiver-utils/-/archiver-utils-5.0.2.tgz) |
| `async` | 3.2.6 | U, D | MIT | [Source](https://registry.npmjs.org/async/-/async-3.2.6.tgz) |
| `b4a` | 1.7.3 | D | Apache-2.0 | [Source](https://registry.npmjs.org/b4a/-/b4a-1.7.3.tgz) |
| `b4a` | 1.8.0 | U | Apache-2.0 | [Source](https://registry.npmjs.org/b4a/-/b4a-1.8.0.tgz) |
| `balanced-match` | 1.0.2 | U, D | MIT | [Source](https://registry.npmjs.org/balanced-match/-/balanced-match-1.0.2.tgz) |
| `balanced-match` | 4.0.4 | U | MIT | [Source](https://registry.npmjs.org/balanced-match/-/balanced-match-4.0.4.tgz) |
| `bare-events` | 2.8.2 | U, D | Apache-2.0 | [Source](https://registry.npmjs.org/bare-events/-/bare-events-2.8.2.tgz) |
| `base64-js` | 1.5.1 | U, D | MIT | [Source](https://registry.npmjs.org/base64-js/-/base64-js-1.5.1.tgz) |
| `before-after-hook` | 4.0.0 | U, D | Apache-2.0 | [Source](https://registry.npmjs.org/before-after-hook/-/before-after-hook-4.0.0.tgz) |
| `binary` | 0.3.0 | U, D | MIT | [Source](https://registry.npmjs.org/binary/-/binary-0.3.0.tgz) |
| `bottleneck` | 2.19.5 | U, D | MIT | [Source](https://registry.npmjs.org/bottleneck/-/bottleneck-2.19.5.tgz) |
| `brace-expansion` | 1.1.12 | U | MIT | [Source](https://registry.npmjs.org/brace-expansion/-/brace-expansion-1.1.12.tgz) |
| `brace-expansion` | 2.0.2 | U, D | MIT | [Source](https://registry.npmjs.org/brace-expansion/-/brace-expansion-2.0.2.tgz) |
| `brace-expansion` | 5.0.3 | U | MIT | [Source](https://registry.npmjs.org/brace-expansion/-/brace-expansion-5.0.3.tgz) |
| `buffer` | 6.0.3 | U, D | MIT | [Source](https://registry.npmjs.org/buffer/-/buffer-6.0.3.tgz) |
| `buffer-crc32` | 1.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/buffer-crc32/-/buffer-crc32-1.0.0.tgz) |
| `buffers` | 0.1.1 | U, D | MIT/X11 | [Source](https://registry.npmjs.org/buffers/-/buffers-0.1.1.tgz) |
| `chainsaw` | 0.1.0 | U, D | MIT/X11 | [Source](https://registry.npmjs.org/chainsaw/-/chainsaw-0.1.0.tgz) |
| `color-convert` | 2.0.1 | U, D | MIT | [Source](https://registry.npmjs.org/color-convert/-/color-convert-2.0.1.tgz) |
| `color-name` | 1.1.4 | U, D | MIT | [Source](https://registry.npmjs.org/color-name/-/color-name-1.1.4.tgz) |
| `compress-commons` | 6.0.2 | U, D | MIT | [Source](https://registry.npmjs.org/compress-commons/-/compress-commons-6.0.2.tgz) |
| `concat-map` | 0.0.1 | U | MIT | [Source](https://registry.npmjs.org/concat-map/-/concat-map-0.0.1.tgz) |
| `core-util-is` | 1.0.3 | U, D | MIT | [Source](https://registry.npmjs.org/core-util-is/-/core-util-is-1.0.3.tgz) |
| `crc-32` | 1.2.2 | U, D | Apache-2.0 | [Source](https://registry.npmjs.org/crc-32/-/crc-32-1.2.2.tgz) |
| `crc32-stream` | 6.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/crc32-stream/-/crc32-stream-6.0.0.tgz) |
| `cross-spawn` | 7.0.6 | U, D | MIT | [Source](https://registry.npmjs.org/cross-spawn/-/cross-spawn-7.0.6.tgz) |
| `debug` | 4.4.3 | U, D | MIT | [Source](https://registry.npmjs.org/debug/-/debug-4.4.3.tgz) |
| `eastasianwidth` | 0.2.0 | U, D | MIT | [Source](https://registry.npmjs.org/eastasianwidth/-/eastasianwidth-0.2.0.tgz) |
| `emoji-regex` | 8.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/emoji-regex/-/emoji-regex-8.0.0.tgz) |
| `emoji-regex` | 9.2.2 | U, D | MIT | [Source](https://registry.npmjs.org/emoji-regex/-/emoji-regex-9.2.2.tgz) |
| `event-target-shim` | 5.0.1 | U, D | MIT | [Source](https://registry.npmjs.org/event-target-shim/-/event-target-shim-5.0.1.tgz) |
| `events` | 3.3.0 | U, D | MIT | [Source](https://registry.npmjs.org/events/-/events-3.3.0.tgz) |
| `events-universal` | 1.0.1 | U, D | Apache-2.0 | [Source](https://registry.npmjs.org/events-universal/-/events-universal-1.0.1.tgz) |
| `fast-content-type-parse` | 3.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/fast-content-type-parse/-/fast-content-type-parse-3.0.0.tgz) |
| `fast-fifo` | 1.3.2 | U, D | MIT | [Source](https://registry.npmjs.org/fast-fifo/-/fast-fifo-1.3.2.tgz) |
| `fast-xml-builder` | 1.0.0 | U | MIT | [Source](https://registry.npmjs.org/fast-xml-builder/-/fast-xml-builder-1.0.0.tgz) |
| `fast-xml-parser` | 5.3.4 | D | MIT | [Source](https://registry.npmjs.org/fast-xml-parser/-/fast-xml-parser-5.3.4.tgz) |
| `fast-xml-parser` | 5.4.1 | U | MIT | [Source](https://registry.npmjs.org/fast-xml-parser/-/fast-xml-parser-5.4.1.tgz) |
| `foreground-child` | 3.3.1 | U, D | ISC | [Source](https://registry.npmjs.org/foreground-child/-/foreground-child-3.3.1.tgz) |
| `glob` | 10.5.0 | U, D | ISC | [Source](https://registry.npmjs.org/glob/-/glob-10.5.0.tgz) |
| `graceful-fs` | 4.2.11 | U, D | ISC | [Source](https://registry.npmjs.org/graceful-fs/-/graceful-fs-4.2.11.tgz) |
| `http-proxy-agent` | 7.0.2 | U, D | MIT | [Source](https://registry.npmjs.org/http-proxy-agent/-/http-proxy-agent-7.0.2.tgz) |
| `https-proxy-agent` | 7.0.6 | U, D | MIT | [Source](https://registry.npmjs.org/https-proxy-agent/-/https-proxy-agent-7.0.6.tgz) |
| `ieee754` | 1.2.1 | U, D | BSD-3-Clause | [Source](https://registry.npmjs.org/ieee754/-/ieee754-1.2.1.tgz) |
| `inherits` | 2.0.4 | U, D | ISC | [Source](https://registry.npmjs.org/inherits/-/inherits-2.0.4.tgz) |
| `is-fullwidth-code-point` | 3.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/is-fullwidth-code-point/-/is-fullwidth-code-point-3.0.0.tgz) |
| `is-stream` | 2.0.1 | U, D | MIT | [Source](https://registry.npmjs.org/is-stream/-/is-stream-2.0.1.tgz) |
| `isarray` | 1.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/isarray/-/isarray-1.0.0.tgz) |
| `isexe` | 2.0.0 | U, D | ISC | [Source](https://registry.npmjs.org/isexe/-/isexe-2.0.0.tgz) |
| `jackspeak` | 3.4.3 | U, D | BlueOak-1.0.0 | [Source](https://registry.npmjs.org/jackspeak/-/jackspeak-3.4.3.tgz) |
| `json-with-bigint` | 3.5.3 | U, D | MIT | [Source](https://registry.npmjs.org/json-with-bigint/-/json-with-bigint-3.5.3.tgz) |
| `jwt-decode` | 4.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/jwt-decode/-/jwt-decode-4.0.0.tgz) |
| `lazystream` | 1.0.1 | U, D | MIT | [Source](https://registry.npmjs.org/lazystream/-/lazystream-1.0.1.tgz) |
| `lodash` | 4.17.23 | U, D | MIT | [Source](https://registry.npmjs.org/lodash/-/lodash-4.17.23.tgz) |
| `lru-cache` | 10.4.3 | U, D | ISC | [Source](https://registry.npmjs.org/lru-cache/-/lru-cache-10.4.3.tgz) |
| `minimatch` | 10.1.1 | D | BlueOak-1.0.0 | [Source](https://registry.npmjs.org/minimatch/-/minimatch-10.1.1.tgz) |
| `minimatch` | 10.2.4 | U | BlueOak-1.0.0 | [Source](https://registry.npmjs.org/minimatch/-/minimatch-10.2.4.tgz) |
| `minimatch` | 3.1.5 | U | ISC | [Source](https://registry.npmjs.org/minimatch/-/minimatch-3.1.5.tgz) |
| `minimatch` | 5.1.6 | D | ISC | [Source](https://registry.npmjs.org/minimatch/-/minimatch-5.1.6.tgz) |
| `minimatch` | 5.1.8 | U | ISC | [Source](https://registry.npmjs.org/minimatch/-/minimatch-5.1.8.tgz) |
| `minimatch` | 9.0.5 | D | ISC | [Source](https://registry.npmjs.org/minimatch/-/minimatch-9.0.5.tgz) |
| `minimatch` | 9.0.8 | U | ISC | [Source](https://registry.npmjs.org/minimatch/-/minimatch-9.0.8.tgz) |
| `minimist` | 1.2.8 | U, D | MIT | [Source](https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz) |
| `minipass` | 7.1.2 | D | ISC | [Source](https://registry.npmjs.org/minipass/-/minipass-7.1.2.tgz) |
| `minipass` | 7.1.3 | U | BlueOak-1.0.0 | [Source](https://registry.npmjs.org/minipass/-/minipass-7.1.3.tgz) |
| `mkdirp` | 0.5.6 | U, D | MIT | [Source](https://registry.npmjs.org/mkdirp/-/mkdirp-0.5.6.tgz) |
| `ms` | 2.1.3 | U, D | MIT | [Source](https://registry.npmjs.org/ms/-/ms-2.1.3.tgz) |
| `normalize-path` | 3.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/normalize-path/-/normalize-path-3.0.0.tgz) |
| `package-json-from-dist` | 1.0.1 | U, D | BlueOak-1.0.0 (root notice) | [Source](https://registry.npmjs.org/package-json-from-dist/-/package-json-from-dist-1.0.1.tgz) |
| `path-key` | 3.1.1 | U, D | MIT | [Source](https://registry.npmjs.org/path-key/-/path-key-3.1.1.tgz) |
| `path-scurry` | 1.11.1 | U, D | BlueOak-1.0.0 | [Source](https://registry.npmjs.org/path-scurry/-/path-scurry-1.11.1.tgz) |
| `process` | 0.11.10 | U, D | MIT | [Source](https://registry.npmjs.org/process/-/process-0.11.10.tgz) |
| `process-nextick-args` | 2.0.1 | U, D | MIT | [Source](https://registry.npmjs.org/process-nextick-args/-/process-nextick-args-2.0.1.tgz) |
| `readable-stream` | 2.3.8 | U, D | MIT | [Source](https://registry.npmjs.org/readable-stream/-/readable-stream-2.3.8.tgz) |
| `readable-stream` | 4.7.0 | U, D | MIT | [Source](https://registry.npmjs.org/readable-stream/-/readable-stream-4.7.0.tgz) |
| `readdir-glob` | 1.1.3 | U, D | Apache-2.0 | [Source](https://registry.npmjs.org/readdir-glob/-/readdir-glob-1.1.3.tgz) |
| `safe-buffer` | 5.1.2 | U, D | MIT | [Source](https://registry.npmjs.org/safe-buffer/-/safe-buffer-5.1.2.tgz) |
| `safe-buffer` | 5.2.1 | U, D | MIT | [Source](https://registry.npmjs.org/safe-buffer/-/safe-buffer-5.2.1.tgz) |
| `shebang-command` | 2.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/shebang-command/-/shebang-command-2.0.0.tgz) |
| `shebang-regex` | 3.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/shebang-regex/-/shebang-regex-3.0.0.tgz) |
| `signal-exit` | 4.1.0 | U, D | ISC | [Source](https://registry.npmjs.org/signal-exit/-/signal-exit-4.1.0.tgz) |
| `streamx` | 2.23.0 | U, D | MIT | [Source](https://registry.npmjs.org/streamx/-/streamx-2.23.0.tgz) |
| `string-width` | 4.2.3 | U, D | MIT | [Source](https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz) |
| `string-width` | 5.1.2 | U, D | MIT | [Source](https://registry.npmjs.org/string-width/-/string-width-5.1.2.tgz) |
| `string_decoder` | 1.1.1 | U, D | MIT | [Source](https://registry.npmjs.org/string_decoder/-/string_decoder-1.1.1.tgz) |
| `string_decoder` | 1.3.0 | U, D | MIT | [Source](https://registry.npmjs.org/string_decoder/-/string_decoder-1.3.0.tgz) |
| `strip-ansi` | 6.0.1 | U, D | MIT | [Source](https://registry.npmjs.org/strip-ansi/-/strip-ansi-6.0.1.tgz) |
| `strip-ansi` | 7.1.2 | U, D | MIT | [Source](https://registry.npmjs.org/strip-ansi/-/strip-ansi-7.1.2.tgz) |
| `strnum` | 2.1.2 | U, D | MIT | [Source](https://registry.npmjs.org/strnum/-/strnum-2.1.2.tgz) |
| `tar-stream` | 3.1.7 | U, D | MIT | [Source](https://registry.npmjs.org/tar-stream/-/tar-stream-3.1.7.tgz) |
| `text-decoder` | 1.2.3 | D | Apache-2.0 | [Source](https://registry.npmjs.org/text-decoder/-/text-decoder-1.2.3.tgz) |
| `text-decoder` | 1.2.7 | U | Apache-2.0 | [Source](https://registry.npmjs.org/text-decoder/-/text-decoder-1.2.7.tgz) |
| `traverse` | 0.3.9 | U, D | MIT/X11 | [Source](https://registry.npmjs.org/traverse/-/traverse-0.3.9.tgz) |
| `tslib` | 2.8.1 | U, D | 0BSD | [Source](https://registry.npmjs.org/tslib/-/tslib-2.8.1.tgz) |
| `tunnel` | 0.0.6 | U, D | MIT | [Source](https://registry.npmjs.org/tunnel/-/tunnel-0.0.6.tgz) |
| `undici` | 6.23.0 | U, D | MIT | [Source](https://registry.npmjs.org/undici/-/undici-6.23.0.tgz) |
| `universal-user-agent` | 7.0.3 | U, D | ISC | [Source](https://registry.npmjs.org/universal-user-agent/-/universal-user-agent-7.0.3.tgz) |
| `unzip-stream` | 0.3.4 | U, D | MIT | [Source](https://registry.npmjs.org/unzip-stream/-/unzip-stream-0.3.4.tgz) |
| `util-deprecate` | 1.0.2 | U, D | MIT | [Source](https://registry.npmjs.org/util-deprecate/-/util-deprecate-1.0.2.tgz) |
| `which` | 2.0.2 | U, D | ISC | [Source](https://registry.npmjs.org/which/-/which-2.0.2.tgz) |
| `wrap-ansi` | 7.0.0 | U, D | MIT | [Source](https://registry.npmjs.org/wrap-ansi/-/wrap-ansi-7.0.0.tgz) |
| `wrap-ansi` | 8.1.0 | U, D | MIT | [Source](https://registry.npmjs.org/wrap-ansi/-/wrap-ansi-8.1.0.tgz) |
| `zip-stream` | 6.0.1 | U, D | MIT | [Source](https://registry.npmjs.org/zip-stream/-/zip-stream-6.0.1.tgz) |
