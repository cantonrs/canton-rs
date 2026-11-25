#!/usr/bin/env bash
# Build tests/oracle/codegen/codegen-fixture.dar (the codegen oracle's input) in the pinned toolchain image.
#   scripts/build-codegen-fixture.sh
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${TOOLCHAIN_IMAGE:-daml-toolchain:canton-3.7.2}"
SRC="$ROOT_DIR/tests/oracle/codegen"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
"$ROOT_DIR/scripts/toolchain-yaml.sh" "$SRC/daml.yaml" > "$T/daml.yaml"
docker run --rm -v "$SRC/daml:/src/daml:ro" -v "$T/daml.yaml:/src/daml.yaml:ro" -v "$T:/out" "$IMAGE" sh -c '
  set -e
  mkdir -p /tmp/p && cd /tmp/p && cp -R /src/daml . && cp /src/daml.yaml .
  dpm build -o /out/codegen-fixture.dar'
cp "$T/codegen-fixture.dar" "$SRC/codegen-fixture.dar"
ls -l "$SRC/codegen-fixture.dar"
