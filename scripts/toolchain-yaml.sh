#!/usr/bin/env bash
# Print a component-mode copy of a daml.yaml: the `sdk-version:` line is dropped and a `components:` block with the
# digest-pinned components from docker/toolchain-components.tsv is appended. dpm refuses a project that has both an
# SDK version and opt-in components, and there is no Daml SDK 3.7.2.
#   scripts/toolchain-yaml.sh tests/oracle/tx-corpus/daml.yaml > /tmp/work/daml.yaml
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PINS="${PINS:-$ROOT_DIR/docker/toolchain-components.tsv}"
src="${1:?usage: toolchain-yaml.sh <daml.yaml>}"
[ -f "$src" ] || { echo "ERROR: $src not found" >&2; exit 1; }
if grep -q '^components:' "$src"; then echo "ERROR: $src already has a components: block" >&2; exit 1; fi
n="$(awk -F'\t' '$1=="component"' "$PINS" | wc -l | tr -d '[:space:]')"
[ "$n" -gt 0 ] || { echo "ERROR: no component rows in $PINS" >&2; exit 1; }
grep -v '^sdk-version:' "$src"
printf 'components:\n'
awk -F'\t' '$1=="component" {printf "  - %s@%s # %s %s\n", $5, $6, $2, $3}' "$PINS"
