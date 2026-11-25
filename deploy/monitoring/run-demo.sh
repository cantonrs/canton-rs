#!/usr/bin/env bash
# Turnkey Canton-RS + Prometheus + Grafana Observability Lab Runner
set -euo pipefail

export PATH="${PATH}:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:/Applications/Kiri.app/Contents/Resources/bin"

# When the host's configured `credsStore` helper symlink is broken, strip only `credsStore`
# into a temporary DOCKER_CONFIG while preserving `currentContext` and `cliPluginsExtraDirs`.
if [[ -f "${HOME}/.docker/config.json" ]] && ! command -v docker-credential-osxkeychain >/dev/null 2>&1; then
  DOCKER_CFG_TMP="$(mktemp -d "${TMPDIR:-/tmp}/crs-docker-cfg.XXXXXX")"
  chmod 0700 "${DOCKER_CFG_TMP}"
  trap 'rm -rf "${DOCKER_CFG_TMP}"' EXIT
  ln -sfn "${HOME}/.docker/contexts" "${DOCKER_CFG_TMP}/contexts" 2>/dev/null || true
  python3 -c 'import json, os, sys; p = os.path.expanduser("~/.docker/config.json"); d = json.load(open(p)); d.pop("credsStore", None); out = os.path.join(sys.argv[1], "config.json"); json.dump(d, open(out, "w")); os.chmod(out, 0o600)' "${DOCKER_CFG_TMP}"
  export DOCKER_CONFIG="${DOCKER_CFG_TMP}"
fi

MON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${MON_DIR}/../.." && pwd)"
BIN="${CANTON_RS_BIN:-${REPO_ROOT}/target/debug/canton-rs}"

if [[ ! -x "${BIN}" ]]; then
  if [[ -x "${REPO_ROOT}/target/release/canton-rs" ]]; then
    BIN="${REPO_ROOT}/target/release/canton-rs"
  else
    echo "[*] Building canton-rs..."
    (cd "${REPO_ROOT}" && cargo build -p canton-rs)
  fi
fi

ACTION="${1:-up}"
CASE="${2:-dvp}"

case "${CASE}" in
  dvp|1)
    MANIFEST="${MON_DIR}/examples/case1-dvp-multicell.yaml"
    STATE_DIR="/tmp/crs-mon-dvp"
    ;;
  bft|2)
    MANIFEST="${MON_DIR}/examples/case2-bft-chaos.yaml"
    STATE_DIR="/tmp/crs-mon-bft"
    ;;
  multidomain|3)
    MANIFEST="${MON_DIR}/examples/case3-multidomain-bridge.yaml"
    STATE_DIR="/tmp/crs-mon-md"
    ;;
  *)
    echo "Unknown case '${CASE}' (expected: dvp | bft | multidomain)" >&2
    exit 1
    ;;
esac

case "${ACTION}" in
  up)
    echo "[1/3] Starting Prometheus (:9095) + Grafana (:3300)..."
    docker compose -f "${MON_DIR}/docker-compose.yml" up -d
    echo "[2/3] Starting canton-rs stack (${MANIFEST})..."
    "${BIN}" daemon up -f "${MANIFEST}" --state-dir "${STATE_DIR}" -d
    echo "[3/3] Seeding initial transactions & privacy proof..."
    if [[ "${CASE}" == "dvp" || "${CASE}" == "1" ]]; then
      "${BIN}" daemon scenario run dvp-privacy-proof --state-dir "${STATE_DIR}"
      "${BIN}" daemon scenario run steady-load-10 --state-dir "${STATE_DIR}"
    elif [[ "${CASE}" == "bft" || "${CASE}" == "2" ]]; then
      "${BIN}" daemon scenario run bft-quorum-burst --state-dir "${STATE_DIR}"
    else
      "${BIN}" daemon scenario run smoke-create --state-dir "${STATE_DIR}"
    fi
    echo ""
    echo "=================================================================="
    echo " Grafana Dashboard : http://127.0.0.1:${GRAFANA_PORT:-3300}/d/canton-rs-overview"
    echo " Prometheus UI     : http://127.0.0.1:${PROMETHEUS_PORT:-9095}/targets"
    echo " Raw OpenMetrics   : http://127.0.0.1:9464/metrics"
    echo " Terminal TUI      : ${BIN} daemon top --state-dir ${STATE_DIR}"
    echo "=================================================================="
    ;;

  traffic)
    echo "[*] Running live scenario burst + brief @bank-c chaos fault/recovery..."
    if [[ "${CASE}" == "dvp" || "${CASE}" == "1" ]]; then
      "${BIN}" daemon scenario run steady-load-10 --state-dir "${STATE_DIR}"
      "${BIN}" daemon stop @bank-c --state-dir "${STATE_DIR}"
      sleep 4
      "${BIN}" daemon start @bank-c --state-dir "${STATE_DIR}"
      "${BIN}" daemon scenario run dvp-privacy-proof --state-dir "${STATE_DIR}"
    elif [[ "${CASE}" == "bft" || "${CASE}" == "2" ]]; then
      "${BIN}" daemon stop @bft-spare --state-dir "${STATE_DIR}"
      "${BIN}" daemon scenario run bft-quorum-burst --state-dir "${STATE_DIR}"
      "${BIN}" daemon start @bft-spare --state-dir "${STATE_DIR}"
    else
      "${BIN}" daemon scenario run steady-burst-5 --state-dir "${STATE_DIR}"
    fi
    ;;

  down)
    echo "[*] Stopping canton-rs stack (${STATE_DIR}) and monitoring containers..."
    "${BIN}" daemon down --state-dir "${STATE_DIR}" --clean-files || true
    docker compose -f "${MON_DIR}/docker-compose.yml" down -v
    ;;

  status)
    "${BIN}" daemon ps -a --state-dir "${STATE_DIR}" || true
    docker compose -f "${MON_DIR}/docker-compose.yml" ps
    ;;

  *)
    echo "Usage: $0 <up|traffic|status|down> [dvp|bft|multidomain]" >&2
    exit 1
    ;;
esac
