# Gitleaks binary dependency review

These versions come from the compiled Go build information in the checksum-verified Gitleaks 8.30.1 Linux x64 archive. Their exact module archives and license, notice, and patent files were inspected. Gitleaks runs as an unmodified development/CI tool and is not included in MemberID binaries or images.

MPL-2.0 components are confined to the external scanner executable. Their file-level source obligations do not grant permission to incorporate them into MemberID; any future modification or redistribution of the scanner requires a separate notice and source-availability review. No scanner source or binary is redistributed by this repository.

| Module | Version | Reviewed license files |
| --- | --- | --- |
| dario.cat/mergo | v1.0.1 | BSD |
| github.com/BobuSumisu/aho-corasick | v1.0.3 | MIT |
| github.com/Masterminds/goutils | v1.1.1 | Apache-2.0 |
| github.com/Masterminds/semver/v3 | v3.3.0 | MIT |
| github.com/Masterminds/sprig/v3 | v3.3.0 | MIT |
| github.com/STARRY-S/zip | v0.2.1 | BSD |
| github.com/andybalholm/brotli | v1.1.2-0.20250424173009-453214e765f3 | MIT |
| github.com/aymanbagabas/go-osc52/v2 | v2.0.1 | MIT |
| github.com/bodgit/plumbing | v1.3.0 | BSD |
| github.com/bodgit/sevenzip | v1.6.0 | BSD |
| github.com/bodgit/windows | v1.0.1 | BSD |
| github.com/charmbracelet/lipgloss | v0.5.0 | MIT |
| github.com/dsnet/compress | v0.0.2-0.20230904184137-39efe44ab707 | BSD |
| github.com/fatih/semgroup | v1.2.0 | BSD |
| github.com/fsnotify/fsnotify | v1.8.0 | BSD |
| github.com/gitleaks/go-gitdiff | v0.9.1 | MIT |
| github.com/google/uuid | v1.6.0 | BSD |
| github.com/h2non/filetype | v1.1.3 | MIT |
| github.com/hashicorp/errwrap | v1.1.0 | MPL-2.0 |
| github.com/hashicorp/go-multierror | v1.1.1 | MPL-2.0 |
| github.com/hashicorp/go-version | v1.7.0 | MPL-2.0 |
| github.com/hashicorp/golang-lru/v2 | v2.0.7 | BSD, MPL-2.0 |
| github.com/hashicorp/hcl | v1.0.0 | MPL-2.0 |
| github.com/huandu/xstrings | v1.5.0 | MIT |
| github.com/klauspost/compress | v1.17.11 | Apache-2.0, BSD, MIT |
| github.com/klauspost/pgzip | v1.2.6 | MIT |
| github.com/lucasb-eyer/go-colorful | v1.2.0 | MIT |
| github.com/magiconair/properties | v1.8.9 | BSD |
| github.com/mattn/go-colorable | v0.1.14 | MIT |
| github.com/mattn/go-isatty | v0.0.20 | MIT |
| github.com/mattn/go-runewidth | v0.0.14 | MIT |
| github.com/mholt/archives | v0.1.2 | MIT |
| github.com/minio/minlz | v1.0.0 | Apache-2.0, BSD, MIT |
| github.com/mitchellh/copystructure | v1.2.0 | MIT |
| github.com/mitchellh/mapstructure | v1.5.0 | MIT |
| github.com/mitchellh/reflectwalk | v1.0.2 | MIT |
| github.com/muesli/reflow | v0.2.1-0.20210115123740-9e1d0d53df68 | MIT |
| github.com/muesli/termenv | v0.15.1 | MIT |
| github.com/nwaples/rardecode/v2 | v2.1.0 | BSD |
| github.com/pelletier/go-toml/v2 | v2.2.3 | MIT |
| github.com/pierrec/lz4/v4 | v4.1.21 | BSD |
| github.com/rivo/uniseg | v0.2.0 | MIT |
| github.com/rs/zerolog | v1.33.0 | MIT |
| github.com/sagikazarmark/slog-shim | v0.1.0 | BSD |
| github.com/shopspring/decimal | v1.4.0 | MIT |
| github.com/sorairolake/lzip-go | v0.3.5 | Apache-2.0 |
| github.com/spf13/afero | v1.12.0 | Apache-2.0 |
| github.com/spf13/cast | v1.7.1 | MIT |
| github.com/spf13/cobra | v1.9.1 | Apache-2.0 |
| github.com/spf13/pflag | v1.0.6 | BSD |
| github.com/spf13/viper | v1.19.0 | MIT |
| github.com/subosito/gotenv | v1.6.0 | MIT |
| github.com/tetratelabs/wazero | v1.9.0 | Apache-2.0, Notice |
| github.com/therootcompany/xz | v1.0.1 | CC0-1.0 |
| github.com/ulikunitz/xz | v0.5.12 | BSD |
| github.com/wasilibs/go-re2 | v1.9.0 | BSD, MIT, Notice |
| github.com/wasilibs/wazero-helpers | v0.0.0-20240620070341-3dff1577cd52 | MIT |
| go4.org | v0.0.0-20230225012048-214862532bf5 | Apache-2.0 |
| golang.org/x/crypto | v0.35.0 | BSD, Go patent grant |
| golang.org/x/exp | v0.0.0-20250218142911-aa4b98e5adaa | BSD, Go patent grant |
| golang.org/x/sync | v0.11.0 | BSD, Go patent grant |
| golang.org/x/sys | v0.30.0 | BSD, Go patent grant |
| golang.org/x/text | v0.22.0 | BSD, Go patent grant |
| gopkg.in/ini.v1 | v1.67.0 | Apache-2.0 |
| gopkg.in/yaml.v3 | v3.0.1 | Apache-2.0 |

The CC0-1.0 text for the reviewed xz wrapper includes a public-domain waiver and fallback copyright license; it does not grant patent or trademark rights. The mergo test fixture named testdata/license.yml is YAML test data, not a license grant, and is excluded from license classification.
