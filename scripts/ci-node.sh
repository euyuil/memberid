#!/bin/sh
set -eu
# CI-only installation in the runner's tool directory. Local work reuses Node.
case "${RUNNER_OS:-}" in
  Linux) archive=node-v26.13.1-linux-x64.tar.xz; digest=5c063e46bab0fbc1c17cc445d7ff129cbdcd0471be6ed83b6ab864f8143bc864 ;;
  Windows) archive=node-v26.13.1-win-x64.zip; digest=e2edda75bfb089654705cf65a13b58933bfd5f57148e8ebda916f58a2474f1f7 ;;
  *) printf 'This installer is for Linux and Windows CI runners.\n' >&2; exit 2 ;;
esac
destination="$RUNNER_TEMP/memberid-node"
mkdir "$destination"
curl --fail --silent --show-error --location "https://nodejs.org/dist/v26.13.1/$archive" --output "$destination/$archive"
printf '%s  %s\n' "$digest" "$destination/$archive" | sha256sum --check
if [ "$RUNNER_OS" = Windows ]; then
  unzip -q "$destination/$archive" -d "$destination"
  cygpath -w "$destination/node-v26.13.1-win-x64" >> "$GITHUB_PATH"
else
  tar -xJf "$destination/$archive" -C "$destination"
  printf '%s\n' "$destination/node-v26.13.1-linux-x64/bin" >> "$GITHUB_PATH"
fi
