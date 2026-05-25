#!/usr/bin/env bash
# Build every binary under cmd/*/ into the repo-root bin/ directory.
# Extra args are forwarded to `go build` (e.g. -race, -tags=integration).

set -euo pipefail

# Silence `cd` (it echoes the target when resolving via CDPATH) so $ROOT
# stays a single clean path.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null && pwd)"
BIN="$ROOT/bin"
mkdir -p "$BIN"

shopt -s nullglob
cmds=("$ROOT"/cmd/*/)
if [[ ${#cmds[@]} -eq 0 ]]; then
  echo "no cmd/*/ directories under $ROOT" >&2
  exit 1
fi

for dir in "${cmds[@]}"; do
  name="$(basename "$dir")"
  echo "building $name → bin/$name"
  (cd "$ROOT" && go build "$@" -o "$BIN/$name" "./cmd/$name")
done
