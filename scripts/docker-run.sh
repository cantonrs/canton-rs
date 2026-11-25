#!/usr/bin/env bash
# ==============================================================================
# Docker Management CLI for Canton & Daml Full Rust Ecosystem
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
    cat <<EOF
Usage: $0 <command> [arguments]

Commands:
  build             Build all Docker images (canton-rs, daml-builder)
  up                Start full cluster (Postgres, Canton LocalNet, Ledger JSON API) in background
  down              Stop and remove all cluster containers
  logs              Follow logs of running containers
  ps                Show status of running cluster containers
  build-dar         Compile Daml smart contracts inside daml-builder container
  inspect-dar <dar> Run dar-parser inside canton-rs container
  shell             Open an interactive shell inside canton-rs container
  clean             Remove containers, networks, and persistent data volumes

Examples:
  $0 build
  $0 up
  $0 logs
  $0 build-dar
  $0 inspect-dar contracts/target/sample-contract.dar
EOF
    exit "${1:-0}"
}

CMD="${1:-help}"
shift || true

case "${CMD}" in
    build)
        echo "==> Building canton-rs and daml-builder Docker images..."
        docker compose -f "${ROOT_DIR}/docker-compose.yml" build
        docker compose -f "${ROOT_DIR}/docker-compose.yml" --profile builder build daml-builder
        ;;
    up)
        echo "==> Starting Canton cluster (Postgres, LocalNet, Ledger JSON API)..."
        docker compose -f "${ROOT_DIR}/docker-compose.yml" up -d
        echo "==> Cluster started successfully!"
        docker compose -f "${ROOT_DIR}/docker-compose.yml" ps
        ;;
    down)
        echo "==> Stopping Canton cluster..."
        docker compose -f "${ROOT_DIR}/docker-compose.yml" down
        ;;
    logs)
        docker compose -f "${ROOT_DIR}/docker-compose.yml" logs -f "$@"
        ;;
    ps)
        docker compose -f "${ROOT_DIR}/docker-compose.yml" ps
        ;;
    build-dar)
        echo "==> Compiling Daml smart contracts to DAR via Docker..."
        docker compose -f "${ROOT_DIR}/docker-compose.yml" run --rm daml-builder
        ;;
    inspect-dar)
        DAR_PATH="${1:-contracts/target/sample-contract.dar}"
        echo "==> Inspecting DAR: ${DAR_PATH}..."
        docker compose -f "${ROOT_DIR}/docker-compose.yml" run --rm \
            -v "${ROOT_DIR}/contracts:/home/canton/contracts:ro" \
            canton-localnet \
            /usr/local/bin/dar-parser "/home/canton/${DAR_PATH#contracts/}"
        ;;
    shell)
        docker compose -f "${ROOT_DIR}/docker-compose.yml" run --rm -it \
            canton-localnet /bin/bash
        ;;
    clean)
        echo "==> Cleaning containers and persistent volumes..."
        docker compose -f "${ROOT_DIR}/docker-compose.yml" down -v --remove-orphans
        ;;
    help|--help|-h)
        usage
        exit 0
        ;;
    *)
        echo "ERROR: Unknown command '${CMD}'" >&2
        usage
        exit 1
        ;;
esac
