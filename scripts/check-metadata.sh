#!/bin/sh
set -eu

check_branch() {
  branch=${1#refs/heads/}
  case "$branch" in
    codex/*|claude/*|copilot/*|cursor/*)
      printf 'Agent-branded branch names are prohibited.\n' >&2
      exit 1
      ;;
  esac
}

check_text() {
  if printf '%s\n' "$1" | grep -Ei '(^|[[:space:]])(co-authored-by|assisted-by|generated-by|committed-by-agent|signed-off-by|reviewed-by):.*(claude|codex|copilot|cursor|chatgpt|gemini)|generated (with|by) (claude|codex|copilot|cursor|chatgpt|gemini)|claude-session:|^(author|committer):[[:space:]]*(claude([[:space:]]+code)?|codex|copilot|cursor|chatgpt|gemini)[[:space:]]*<' >/dev/null; then
    printf 'Coding-agent attribution is prohibited.\n' >&2
    exit 1
  fi
}

case "${1-}" in
  branch) check_branch "$2" ;;
  message)
    check_branch "$(git symbolic-ref --quiet --short HEAD || true)"
    check_text "$(cat "$2")"
    ;;
  history)
    commits=$(git rev-list "$2")
    for commit in $commits; do
      check_text "$(git show -s --format='Author: %an <%ae>%nCommitter: %cn <%ce>%n%B' "$commit")"
    done
    ;;
  *) printf 'Usage: check-metadata.sh <branch|message|history> VALUE\n' >&2; exit 2 ;;
esac
