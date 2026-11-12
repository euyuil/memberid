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
docker run --detach --name "$owner" --label "memberid.integration=$owner" \
  --tmpfs /var/lib/postgresql --publish 127.0.0.1::5432 \
  --env POSTGRES_HOST_AUTH_METHOD=trust "$image" >/dev/null
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
go test -race -tags=integration -timeout=5m ./...
