#!/usr/bin/env bash
# Build the DAR of a test fixture directory (contracts/fixtures/*) in the pinned toolchain image into <dir>/target/.
#   scripts/build-fixture.sh contracts/fixtures/depth
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${TOOLCHAIN_IMAGE:-daml-toolchain:canton-3.7.2}"
SRC="$ROOT_DIR/${1:?fixture directory, e.g. contracts/fixtures/depth}"
NAME="$(sed -n 's/^name: //p' "$SRC/daml.yaml")"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
"$ROOT_DIR/scripts/toolchain-yaml.sh" "$SRC/daml.yaml" > "$T/daml.yaml"
# a fixture that builds on another package's DAR keeps it in <dir>/deps/ (its daml.yaml names `deps/<file>.dar` in `data-dependencies`)
DEPS=(); [ -d "$SRC/deps" ] && DEPS=(-v "$SRC/deps:/src/deps:ro")
docker run --rm -v "$SRC/daml:/src/daml:ro" -v "$T/daml.yaml:/src/daml.yaml:ro" ${DEPS[@]+"${DEPS[@]}"} -v "$T:/out" "$IMAGE" sh -c "
  set -e
  mkdir -p /tmp/p && cd /tmp/p && cp -R /src/daml . && cp /src/daml.yaml . && { [ ! -d /src/deps ] || cp -R /src/deps .; }
  dpm build -o /out/$NAME.dar"
mkdir -p "$SRC/target"
cp "$T/$NAME.dar" "$SRC/target/$NAME.dar"
ls -l "$SRC/target/$NAME.dar"
