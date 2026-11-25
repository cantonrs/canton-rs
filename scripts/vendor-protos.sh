#!/usr/bin/env bash
# Copy the official Canton 3.7.2 .proto files into crates/protocol/canton-proto/proto/ and record each file's
# SHA-256 in proto/SOURCES.tsv. The eleven roots of the release's protobuf/ folder have no overlapping relative
# paths, so they are flattened into one include root. Files are copied byte for byte.
#
#   scripts/vendor-protos.sh            (re)create proto/ from the pinned 3.7.2 zip under references/
#   scripts/vendor-protos.sh --check    compare proto/ and SOURCES.tsv with references/ without writing
#
# Exit codes: 0 ok / identical; 1 mismatch or unsafe input; 3 NOT_RUN (references/ is missing the pinned zip).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REFS="${REFERENCES_DIR:-$ROOT_DIR/references}"
SRC="$REFS/canton-3.7.2/dist/protobuf"
OUT="${PROTO_VENDOR_DIR:-$ROOT_DIR/crates/protocol/canton-proto/proto}"
CHECK=0; [ "${1:-}" = "--check" ] && CHECK=1

"$ROOT_DIR/scripts/fetch-references.sh" --check --only canton-3.7.2-zip >/dev/null 2>&1 \
  || { echo "NOT_RUN pinned Canton 3.7.2 zip is not fetched and verified (run: make fetch-references)" >&2; exit 3; }
[ -d "$SRC" ] || { echo "NOT_RUN $SRC not found" >&2; exit 3; }

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
list="$(mktemp "${TMPDIR:-/tmp}/vendorlist.XXXXXX")"; trap 'rm -f "$list" "$list.new"' EXIT
# "<root>\t<relative path>\t<sha256>" for every .proto, sorted by relative path
( cd "$SRC" && for d in */; do d="${d%/}"; ( cd "$d" && find . -type f -name '*.proto' | sed 's|^\./||' | while IFS= read -r f; do printf '%s\t%s\t%s\n' "$d" "$f" "$(sha "$f")"; done ); done ) | LC_ALL=C sort -t$'\t' -k2,2 > "$list"

dups="$(cut -f2 "$list" | uniq -d)"
[ -z "$dups" ] || { echo "FAIL relative paths appear in more than one root: $dups" >&2; exit 1; }
unsafe="$(cut -f2 "$list" | grep -E '(^/|(^|/)\.\.(/|$))' || true)"
[ -z "$unsafe" ] || { echo "FAIL unsafe proto path: $unsafe" >&2; exit 1; }
n="$(wc -l < "$list" | tr -d '[:space:]')"

{ printf '# relative_path\tsha256\torigin_root\n# Source: references-manifest.tsv id canton-3.7.2-zip (protobuf/<origin_root>/<relative_path>). Regenerate with scripts/vendor-protos.sh.\n'
  awk -F'\t' '{print $2"\t"$3"\t"$1}' "$list"; } > "$list.new"

if [ "$CHECK" -eq 1 ]; then
  bad=0
  [ -f "$OUT/SOURCES.tsv" ] && cmp -s "$list.new" "$OUT/SOURCES.tsv" || { echo "FAIL SOURCES.tsv differs from the pinned zip"; bad=1; }
  while IFS=$'\t' read -r root rel hash; do
    [ -f "$OUT/$rel" ] && [ "$(sha "$OUT/$rel")" = "$hash" ] || { echo "FAIL $rel missing or different"; bad=1; }
  done < "$list"
  extra="$(cd "$OUT" 2>/dev/null && find . -type f -name '*.proto' | sed 's|^\./||' | LC_ALL=C sort | comm -13 <(cut -f2 "$list" | LC_ALL=C sort) - || true)"
  [ -z "$extra" ] || { echo "FAIL vendored files that are not in the zip: $extra"; bad=1; }
  [ "$bad" -eq 0 ] && { echo "PASS $n vendored .proto files are byte-identical to the pinned 3.7.2 zip"; exit 0; }
  exit 1
fi

rm -rf "$OUT"; mkdir -p "$OUT"
while IFS=$'\t' read -r root rel hash; do
  mkdir -p "$OUT/$(dirname "$rel")"; cp "$SRC/$root/$rel" "$OUT/$rel"
done < "$list"
cp "$list.new" "$OUT/SOURCES.tsv"
cp "$REFS/canton-3.7.2/dist/LICENSE.txt" "$OUT/LICENSE.txt"
echo "vendored $n .proto files into $OUT"
