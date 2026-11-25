#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="daml-builder:3.7.1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_DIR="${ROOT_DIR}/contracts"
TARGET_DIR="${CONTRACT_DIR}/target"
DAR_OUTPUT="${TARGET_DIR}/sample-contract.dar"

mkdir -p "${TARGET_DIR}"

echo "==> Building Docker image ${IMAGE_NAME}..."
docker build -t "${IMAGE_NAME}" -f "${ROOT_DIR}/docker/Dockerfile" "${ROOT_DIR}"

echo "==> Compiling Daml contract to ${DAR_OUTPUT}..."
docker run --rm \
  -v "${CONTRACT_DIR}:/workspace" \
  -w /workspace \
  "${IMAGE_NAME}" \
  daml build -o /workspace/target/sample-contract.dar

echo "==> Build complete: ${DAR_OUTPUT}"
ls -lh "${DAR_OUTPUT}"
