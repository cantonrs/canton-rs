#!/usr/bin/env bash
# Build tests/oracle/script-host/script-host.dar (the Daml Script host's fixture) in the pinned component toolchain image.
#   scripts/build-script-host-dar.sh
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${TOOLCHAIN_IMAGE:-daml-toolchain:canton-3.7.2}"
SRC="$ROOT_DIR/tests/oracle/script-host"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
"$ROOT_DIR/scripts/toolchain-yaml.sh" "$SRC/daml.yaml" > "$T/daml.yaml"
docker run --rm -v "$SRC/daml:/src/daml:ro" -v "$T/daml.yaml:/src/daml.yaml:ro" -v "$T:/out" "$IMAGE" sh -c '
  set -e
  mkdir -p /tmp/p && cd /tmp/p && cp -R /src/daml . && cp /src/daml.yaml .
  dpm build -o /out/script-host.dar'
cp "$T/script-host.dar" "$SRC/script-host.dar"
ls -l "$SRC/script-host.dar"
