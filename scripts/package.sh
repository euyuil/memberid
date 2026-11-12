#!/bin/sh
set -eu
export GOWORK=off CGO_ENABLED=0
if [ "$#" -ne 2 ]; then
  printf 'Usage: sh scripts/package.sh VERSION NEW_OUTPUT_DIRECTORY\n' >&2
  exit 2
fi
version=$1
output=$2
case "$version" in
  ''|*[!A-Za-z0-9.+_-]*) printf 'Version must contain only letters, digits, dots, plus, underscore, and hyphen.\n' >&2; exit 2 ;;
esac
if [ ! -f go.mod ] || [ ! -d packaging ] || [ ! -d third_party ]; then
  printf 'Run from the MemberID repository root.\n' >&2
  exit 2
fi
goos=$(go env GOOS)
goarch=$(go env GOARCH)
case "$goos/$goarch" in
  linux/amd64) binary=memberid ;;
  windows/amd64) binary=memberid.exe ;;
  *) printf 'Packaging currently supports linux/amd64 and windows/amd64.\n' >&2; exit 2 ;;
esac
# Refuse an existing destination, including an incomplete earlier build.
# The caller chooses an existing parent directory; no data is removed on failure.
mkdir -- "$output"
output=$(cd "$output" && pwd)
go build -mod=readonly -trimpath -buildvcs=false -ldflags "-X main.version=$version" -o "$output/$binary" ./cmd/memberid
cp -R third_party "$output/third_party"
cp -R docs "$output/docs"
cp packaging/README.md "$output/README.md"
cp CONTRIBUTING.md "$output/CONTRIBUTING.md"
printf 'version=%s\ngoos=%s\ngoarch=%s\ngo=%s\ncgo=0\n' "$version" "$goos" "$goarch" "$(go env GOVERSION)" > "$output/BUILDINFO"
if [ "$goos" = linux ]; then
  cp packaging/Dockerfile "$output/Dockerfile"
  cp packaging/dockerignore "$output/.dockerignore"
fi
(cd "$output" && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS)
printf 'MemberID %s packaged for %s/%s. Verify SHA256SUMS before use.\n' "$version" "$goos" "$goarch"
