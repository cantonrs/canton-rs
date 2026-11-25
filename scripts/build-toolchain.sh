#!/usr/bin/env bash
# Build the component-only Daml toolchain image from docker/toolchain-components.tsv.
#   scripts/build-toolchain.sh            builds daml-toolchain:canton-3.7.2
# Environment: TOOLCHAIN_IMAGE (default daml-toolchain:canton-3.7.2), PINS (default docker/toolchain-components.tsv)
# Needs network (apt, the dpm release, the OCI registry). The base image must already be present locally.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${TOOLCHAIN_IMAGE:-daml-toolchain:canton-3.7.2}"
PINS="${PINS:-$ROOT_DIR/docker/toolchain-components.tsv}"
col() { awk -F'\t' -v k="$1" -v p="$2" '$1==k && $4==p {print $5"\t"$6}' "$PINS"; }

amd="$(col dpm linux-amd64)"; arm="$(col dpm linux-arm64)"
[ -n "$amd" ] && [ -n "$arm" ] || { echo "ERROR: dpm rows missing in $PINS" >&2; exit 1; }
refs="$(awk -F'\t' '$1=="component" {printf "%s@%s ", $5, $6}' "$PINS")"
[ -n "$refs" ] || { echo "ERROR: no component rows in $PINS" >&2; exit 1; }

docker build -f "$ROOT_DIR/docker/Dockerfile.toolchain" -t "$IMAGE" \
  --build-arg "DPM_URL_AMD64=${amd%%$'\t'*}" --build-arg "DPM_SHA256_AMD64=${amd##*$'\t'}" \
  --build-arg "DPM_URL_ARM64=${arm%%$'\t'*}" --build-arg "DPM_SHA256_ARM64=${arm##*$'\t'}" \
  --build-arg "COMPONENT_REFS=${refs% }" \
  "$ROOT_DIR/docker"
echo "built $IMAGE ($(docker image inspect "$IMAGE" --format '{{.Id}}'))"
