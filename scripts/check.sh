#!/bin/sh
set -eu
export GOWORK=off
unformatted=$(gofmt -l cmd internal)
if [ -n "$unformatted" ]; then
  printf 'Run gofmt on:\n%s\n' "$unformatted" >&2
  exit 1
fi
go vet ./...
go test ./...
go build -trimpath -buildvcs=false -o dist/ ./cmd/memberid
mkdir -p dist/third_party
cp -R third_party/. dist/third_party/
