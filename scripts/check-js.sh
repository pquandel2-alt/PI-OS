#!/usr/bin/env bash
# Syntax-check every shipped JavaScript file (ES modules and classic scripts).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
n=0
while IFS= read -r f; do
  cp "$f" "$tmp/check.mjs"
  node --check "$tmp/check.mjs" || { echo "syntax error in $f" >&2; exit 1; }
  n=$((n + 1))
done < <(find web apps -name '*.js')
echo "checked $n JavaScript files"
