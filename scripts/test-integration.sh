#!/bin/sh
set -eu
export GOWORK=off
image=postgres:18.6@sha256:bd5dfa494a5a259704365813dbfa5fa6b3e69be7348d43b547f540c730478583
owner="memberid-integration-$$-$(date +%s)"
created=0
cleanup() {
  if [ "$created" -eq 1 ]; then
    actual=$(docker inspect --format '{{index .Config.Labels "memberid.integration"}}' "$owner")
    if [ "$actual" != "$owner" ]; then
      printf 'Test container ownership changed; cleanup refused.\n' >&2
      return 1
    fi
    docker rm --force --volumes "$owner" >/dev/null
  fi
}
trap cleanup EXIT HUP INT TERM
set --
if [ "${MEMBERID_TEST_QUERY_PROFILE:-}" = 1 ]; then
  set -- -c shared_preload_libraries=pg_stat_statements
fi
docker run --detach --name "$owner" --label "memberid.integration=$owner" \
  --tmpfs /var/lib/postgresql --publish 127.0.0.1::5432 \
  --env POSTGRES_HOST_AUTH_METHOD=trust "$image" "$@" >/dev/null
created=1
attempt=0
until docker exec "$owner" pg_isready --username postgres >/dev/null 2>&1; do
  attempt=$((attempt+1))
  if [ "$attempt" -ge 60 ]; then printf 'PostgreSQL did not become ready.\n' >&2; exit 1; fi
  sleep 1
done
binding=$(docker port "$owner" 5432/tcp)
port=${binding##*:}
export MEMBERID_TEST_DATABASE_URL="postgres://postgres@127.0.0.1:$port/postgres?sslmode=disable"
if [ "${MEMBERID_TEST_QUERY_PROFILE:-}" = 1 ]; then
  go test -tags=integration -timeout=5m -run '^TestConsoleQueryProfile$' -count=1 -v ./internal/oidcprovider
else
  # The combined OIDC/SAML suite includes real password hashing under -race.
  # Allow the full package to finish while keeping a finite hang deadline.
  go test -race -tags=integration -timeout=10m ./...
fi
