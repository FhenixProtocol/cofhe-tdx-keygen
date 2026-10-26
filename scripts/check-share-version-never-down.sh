#!/usr/bin/env bash
# Fails when a baked env's share_version is lower than on the base ref.
# CI has no GCP access; the keygen's own precheck checks the live versions.
#   check-share-version-never-down.sh <base-ref>          compare base vs HEAD
#   check-share-version-never-down.sh --files <old> <new> compare two emit outputs
set -euo pipefail

compare() {  # <old file> <new file>, lines "<env> <n>"
  local fail=0 env new old
  while read -r env new; do
    old="$(awk -v e="$env" '$1 == e { print $2 }' "$1")"
    [ -z "$old" ] && continue
    if [ "$new" -lt "$old" ]; then
      echo "share_version for $env went down: $old -> $new" >&2
      fail=1
    fi
  done < "$2"
  return "$fail"
}

emit() {  # <dir>
  (cd "$1" && cargo run --quiet -p cofhe-keys --no-default-features --example emit_share_versions)
}

if [ "${1:-}" = "--files" ]; then compare "$2" "$3"; exit $?; fi

base="${1:?usage: $0 <base-ref>}"
work="$(mktemp -d)"
trap 'git worktree remove --force "$work/base" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
git worktree add --detach "$work/base" "$base" >/dev/null
if [ ! -f "$work/base/crates/cofhe-keys/examples/emit_share_versions.rs" ]; then
  echo "base $base has no baked share versions yet; nothing to compare"
  exit 0
fi
emit "$work/base" > "$work/old"
emit . > "$work/new"
compare "$work/old" "$work/new"
