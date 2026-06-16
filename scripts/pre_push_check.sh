#!/usr/bin/env bash
set -euo pipefail

MAX_BYTES="${MAX_BYTES:-5242880}"
HARD_MAX_BYTES="${HARD_MAX_BYTES:-26214400}"

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

fail() {
  printf 'pre-push check failed: %s\n' "$*" >&2
  exit 1
}

info() {
  printf '[pre-push] %s\n' "$*"
}

tracked_and_untracked_files() {
  {
    git ls-files
    git ls-files --others --exclude-standard
  } | sort -u
}

file_size() {
  if command -v stat >/dev/null 2>&1; then
    stat -c '%s' "$1" 2>/dev/null || stat -f '%z' "$1" 2>/dev/null || wc -c <"$1"
  else
    wc -c <"$1"
  fi
}

is_existing_large_exception() {
  case "$1" in
    data/journal_results/enterprise-attack.json)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

info "checking file sizes"
while IFS= read -r path; do
  [ -f "$path" ] || continue
  size="$(file_size "$path" | tr -d '[:space:]')"
  [ -n "$size" ] || continue

  if [ "$size" -gt "$HARD_MAX_BYTES" ] && ! is_existing_large_exception "$path"; then
    fail "$path is ${size} bytes, above hard limit ${HARD_MAX_BYTES}"
  fi

  if [ "$size" -gt "$MAX_BYTES" ] && ! is_existing_large_exception "$path"; then
    fail "$path is ${size} bytes, above soft limit ${MAX_BYTES}"
  fi
done < <(tracked_and_untracked_files)

info "checking sensitive file names"
if tracked_and_untracked_files | grep -E '(^|/)(\.env(\..*)?|.*\.(key|pem|p12|pfx|jks|keystore))$' >/dev/null; then
  tracked_and_untracked_files | grep -E '(^|/)(\.env(\..*)?|.*\.(key|pem|p12|pfx|jks|keystore))$' >&2
  fail "sensitive file name detected"
fi

info "checking secrets"
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source "$ROOT" --no-banner --redact --verbose
elif command -v trufflehog >/dev/null 2>&1; then
  trufflehog filesystem "$ROOT" --fail --no-update
else
  secret_pattern='(sk-[A-Za-z0-9_-]{20,}|OPENAI_API_KEY[[:space:]]*=[[:space:]]*sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)'
  while IFS= read -r path; do
    [ -f "$path" ] || continue
    case "$path" in
      .git/*|venv/*|.venv/*|*.png|*.jpg|*.jpeg|*.gif|*.pdf|*.zip|*.gz|*.dll|*.pyd|*.pyc)
        continue
        ;;
      data/journal_results/enterprise-attack.json)
        continue
        ;;
    esac
    if grep -I -n -E "$secret_pattern" "$path" >/tmp/adversim_secret_hits.$$ 2>/dev/null; then
      cat /tmp/adversim_secret_hits.$$ >&2
      rm -f /tmp/adversim_secret_hits.$$
      fail "secret-like value detected in $path"
    fi
  done < <(tracked_and_untracked_files)
  rm -f /tmp/adversim_secret_hits.$$
fi

info "ok"
