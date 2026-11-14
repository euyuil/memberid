#!/bin/sh
set -eu
umask 077
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' LC_ALL=C

usage() {
  printf 'Usage: sh dev/setup.sh [--name ENVIRONMENT --port HTTPS_PORT]\n'
}

environment=
https_port=
if [ "$#" -ne 0 ]; then
  if [ "$#" -eq 1 ] && [ "$1" = "--help" ]; then
    usage
    exit 0
  fi
  if [ "$#" -ne 4 ]; then
    usage >&2
    exit 2
  fi
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --name) environment=$2 ;;
      --port) https_port=$2 ;;
      *) usage >&2; exit 2 ;;
    esac
    shift 2
  done
  case "$environment" in
    ''|[!a-z0-9]*|*[!a-z0-9-]*|*-)
      printf 'Use lowercase letters, digits, and internal hyphens for the environment name.\n' >&2
      exit 2
      ;;
  esac
  if [ "${#environment}" -gt 57 ]; then
    printf 'The environment name must be at most 57 characters.\n' >&2
    exit 2
  fi
  case "$https_port" in
    ''|0*|*[!0-9]*)
      printf 'Choose an HTTPS port between 1 and 65535, without leading zeros.\n' >&2
      exit 2
      ;;
  esac
  if [ "${#https_port}" -gt 5 ] || [ "$https_port" -gt 65535 ]; then
    printf 'Choose an HTTPS port between 1 and 65535.\n' >&2
    exit 2
  fi
fi

https_port=${https_port:-8443}
auth_host=auth${environment:+-$environment}.memberid.localhost
admin_host=admin${environment:+-$environment}.memberid.localhost
origin_port=:$https_port
if [ "$https_port" = 443 ]; then
  origin_port=
fi
issuer=https://$auth_host$origin_port
console_origin=https://$admin_host$origin_port

if [ ! -f compose.yaml ] || [ ! -f dev/Caddyfile ]; then
  printf 'Run from the MemberID repository root.\n' >&2
  exit 2
fi

state=.local/compose
if ! mkdir -p .local || ! mkdir "$state"; then
  printf 'Keep any existing %s directory. Setup requires a new one.\n' "$state" >&2
  exit 1
fi
trap 'printf "Setup incomplete. Inspect %s before retrying.\n" "$state" >&2' EXIT

# Keep the editable configuration readable by the host user and the serving processes.
uid=$(id -u)
gid=$(id -g)
project=memberid-local-$(openssl rand -hex 6)
printf 'MEMBERID_LOCAL_PROJECT=%s\nMEMBERID_LOCAL_UID=%s\nMEMBERID_LOCAL_GID=%s\n' \
  "$project" "$uid" "$gid" > "$state/compose.env"
printf 'MEMBERID_LOCAL_AUTH_HOST=%s\nMEMBERID_LOCAL_ADMIN_HOST=%s\nMEMBERID_LOCAL_HTTPS_PORT=%s\n' \
  "$auth_host" "$admin_host" "$https_port" >> "$state/compose.env"
password=$(openssl rand -hex 24)
printf 'POSTGRES_USER=memberid\nPOSTGRES_DB=memberid\nPOSTGRES_PASSWORD=%s\n' "$password" > "$state/postgres.env"
printf 'MEMBERID_DATABASE_URL=postgres://memberid:%s@postgres:5432/memberid?sslmode=disable\n' "$password" > "$state/memberid.env"
printf 'MEMBERID_DINGTALK_ENABLED=true\n' > "$state/auth.env"

mkdir "$state/tls"
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 \
  -subj '/CN=MemberID Local Development CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$state/tls/ca-key.pem" -out "$state/tls/ca.pem" 2>"$state/tls/generation.log"
openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=${auth_host%%.*}" \
  -keyout "$state/tls/server-key.pem" -out "$state/tls/server.csr" 2>>"$state/tls/generation.log"
cat > "$state/tls/server.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$auth_host,DNS:$admin_host
EXT
openssl x509 -req -sha256 -days 365 -in "$state/tls/server.csr" \
  -CA "$state/tls/ca.pem" -CAkey "$state/tls/ca-key.pem" \
  -CAcreateserial -extfile "$state/tls/server.ext" -out "$state/tls/server.pem" 2>>"$state/tls/generation.log"
# Finished public material and leaf key are the only TLS inputs used by the stack.
rm "$state/tls/ca-key.pem" "$state/tls/ca.srl" "$state/tls/server.csr" "$state/tls/server.ext" "$state/tls/generation.log"

docker compose --env-file "$state/compose.env" run --no-deps --rm --entrypoint cat \
  proxy /etc/ssl/certs/ca-certificates.crt > "$state/tls/system-ca.pem"
test -s "$state/tls/system-ca.pem"
docker compose --env-file "$state/compose.env" build auth

absolute_state=$(cd "$state" && pwd -P)
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) absolute_state=$(cygpath -am "$absolute_state") ;;
esac
operator() {
  docker run --rm --network none --user "$uid:$gid" \
    --mount "type=bind,source=$absolute_state,target=/setup" \
    "memberid:$project" "$@"
}

operator config init --directory /setup/installation --issuer "$issuer"
operator client add --directory /setup/installation --id memberid-console \
  --redirect "$console_origin/auth/callback" --preauthorized > "$state/console-client.json"
python3 - "$state" "$console_origin" <<'PY'
import json
from pathlib import Path
import sys

state = Path(sys.argv[1])
installation = state / "installation"
with (state / "console-client.json").open(encoding="utf-8") as source:
    secret = json.load(source)["client_secret"]
with (installation / "console-client-secret").open("x", encoding="utf-8") as output:
    output.write(secret + "\n")
with (installation / "console.json").open("x", encoding="utf-8") as output:
    json.dump(
        {
            "origin": sys.argv[2],
            "clientId": "memberid-console",
            "clientSecretFile": "console-client-secret",
        },
        output,
        indent=2,
    )
    output.write("\n")
(state / "console-client.json").unlink()
PY

docker compose --env-file "$state/compose.env" up -d --wait postgres
docker compose --env-file "$state/compose.env" run --rm --no-deps auth database init
trap - EXIT
printf 'Local installation ready. Review %s/auth.env, then start the Compose stack.\n' "$state"
printf 'OIDC issuer: %s\nAdministration console: %s\n' "$issuer" "$console_origin"
