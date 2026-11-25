#!/usr/bin/env bash
# ==============================================================================
# tests/e2e/harness/test_helpers.sh
# E2E Test Suite Assertion & Utility Library
# ==============================================================================

set -o pipefail

# ANSI color codes
COLOR_RESET="\033[0m"
COLOR_RED="\033[31m"
COLOR_GREEN="\033[32m"
COLOR_YELLOW="\033[33m"
COLOR_BLUE="\033[34m"
COLOR_CYAN="\033[36m"
COLOR_BOLD="\033[1m"

# Counters
TOTAL_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

CURRENT_TEST_NAME=""
LAST_EXIT_CODE=0
LAST_STDOUT=""
LAST_STDERR=""

# Resolve Paths
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_ROOT="$(cd "${HARNESS_DIR}/.." && pwd)"
PROJECT_ROOT="$(cd "${E2E_ROOT}/../.." && pwd)"
FIXTURES_DIR="${E2E_ROOT}/fixtures"

log_info() {
    echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"
}

log_success() {
    echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} $*"
}

log_warn() {
    echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*"
}

log_error() {
    echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} $*"
}

log_tier() {
    echo -e "\n${COLOR_CYAN}${COLOR_BOLD}=== $* ===${COLOR_RESET}"
}

# Find or resolve the dar-parser binary
find_dar_parser() {
    if [[ -n "${DAR_PARSER_BIN:-}" && -x "${DAR_PARSER_BIN}" ]]; then
        echo "${DAR_PARSER_BIN}"
        return 0
    fi

    local release_bin="${PROJECT_ROOT}/target/release/dar-parser"
    if [[ -x "${release_bin}" ]]; then
        echo "${release_bin}"
        return 0
    fi

    local debug_bin="${PROJECT_ROOT}/target/debug/dar-parser"
    if [[ -x "${debug_bin}" ]]; then
        echo "${debug_bin}"
        return 0
    fi

    # Fallback to cargo wrapper if Cargo.toml exists
    if [[ -f "${PROJECT_ROOT}/Cargo.toml" ]]; then
        echo "CARGO_RUN"
        return 0
    fi

    return 1
}

run_dar_parser() {
    local bin
    bin="$(find_dar_parser || true)"

    local stdout_file
    local stderr_file
    stdout_file="$(mktemp)"
    stderr_file="$(mktemp)"

    if [[ -z "${bin}" ]]; then
        echo "dar-parser binary not found and cargo not configured" > "${stderr_file}"
        LAST_EXIT_CODE=127
        LAST_STDOUT=""
        LAST_STDERR="$(cat "${stderr_file}")"
        rm -f "${stdout_file}" "${stderr_file}"
        return 127
    fi

    if [[ "${bin}" == "CARGO_RUN" ]]; then
        (
            cd "${PROJECT_ROOT}"
            cargo run --quiet --bin dar-parser -- "$@" > "${stdout_file}" 2> "${stderr_file}"
        )
        LAST_EXIT_CODE=$?
    else
        "${bin}" "$@" > "${stdout_file}" 2> "${stderr_file}"
        LAST_EXIT_CODE=$?
    fi

    LAST_STDOUT="$(cat "${stdout_file}")"
    LAST_STDERR="$(cat "${stderr_file}")"
    rm -f "${stdout_file}" "${stderr_file}"

    return ${LAST_EXIT_CODE}
}

test_start() {
    CURRENT_TEST_NAME="$1"
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    echo -ne "  [TEST] ${CURRENT_TEST_NAME} ... "
}

test_pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "${COLOR_GREEN}PASSED${COLOR_RESET}"
}

test_fail() {
    local reason="$1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "${COLOR_RED}FAILED${COLOR_RESET}"
    echo -e "         ${COLOR_RED}Reason: ${reason}${COLOR_RESET}"
    if [[ -n "${LAST_STDERR}" ]]; then
        echo -e "         ${COLOR_YELLOW}stderr: ${LAST_STDERR}${COLOR_RESET}"
    fi
    if [[ -n "${LAST_STDOUT}" ]]; then
        echo -e "         ${COLOR_YELLOW}stdout (first 3 lines): ${COLOR_RESET}$(echo "${LAST_STDOUT}" | head -n 3)"
    fi
}

test_skip() {
    local reason="$1"
    SKIP_COUNT=$((SKIP_COUNT + 1))
    echo -e "${COLOR_YELLOW}SKIPPED${COLOR_RESET} (${reason})"
}

assert_exit_code() {
    local expected="$1"
    local actual="$2"
    if [[ "${actual}" -ne "${expected}" ]]; then
        test_fail "Expected exit code ${expected}, got ${actual}"
        return 1
    fi
    return 0
}

assert_contains() {
    local needle="$1"
    local haystack="$2"
    if [[ "${haystack}" != *"${needle}"* ]]; then
        test_fail "Expected string to contain '${needle}'"
        return 1
    fi
    return 0
}

assert_not_contains() {
    local needle="$1"
    local haystack="$2"
    if [[ "${haystack}" == *"${needle}"* ]]; then
        test_fail "Expected string NOT to contain '${needle}'"
        return 1
    fi
    return 0
}

assert_matches_regex() {
    local regex="$1"
    local text="$2"
    if ! echo "${text}" | grep -qE "${regex}"; then
        test_fail "Expected text to match regex '${regex}'"
        return 1
    fi
    return 0
}

assert_file_exists() {
    local path="$1"
    if [[ ! -f "${path}" ]]; then
        test_fail "File '${path}' does not exist"
        return 1
    fi
    return 0
}

assert_file_non_empty() {
    local path="$1"
    if [[ ! -s "${path}" ]]; then
        test_fail "File '${path}' is empty or does not exist"
        return 1
    fi
    return 0
}

assert_json_valid() {
    local json_text="$1"
    if ! python3 -c "import json, sys; json.loads(sys.argv[1])" "${json_text}" 2>/dev/null; then
        test_fail "Output is not valid JSON: ${json_text}"
        return 1
    fi
    return 0
}

assert_json_field_equals() {
    local json_text="$1"
    local key_path="$2"
    local expected="$3"

    local actual
    actual=$(python3 -c "
import json, sys
data = json.loads(sys.argv[1])
keys = sys.argv[2].split('.')
val = data
for k in keys:
    if isinstance(val, dict):
        val = val.get(k)
    else:
        val = None
        break
print(str(val) if val is not None else '')
" "${json_text}" "${key_path}" 2>/dev/null)

    if [[ "${actual}" != "${expected}" ]]; then
        test_fail "JSON field '${key_path}': expected '${expected}', got '${actual}'"
        return 1
    fi
    return 0
}
