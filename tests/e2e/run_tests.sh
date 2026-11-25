#!/usr/bin/env bash
# ==============================================================================
# tests/e2e/run_tests.sh
# Unified E2E Test Suite Runner for Canton / Daml 3.x Rust Conversion
# Opaque-box requirement-driven testing across Tiers 1-4
# ==============================================================================

set -uo pipefail

RUNNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${RUNNER_DIR}/../.." && pwd)"
HARNESS_DIR="${RUNNER_DIR}/harness"
CASES_DIR="${RUNNER_DIR}/cases"
FIXTURES_DIR="${RUNNER_DIR}/fixtures"

# ANSI color codes
COLOR_RESET="\033[0m"
COLOR_RED="\033[31m"
COLOR_GREEN="\033[32m"
COLOR_YELLOW="\033[33m"
COLOR_BLUE="\033[34m"
COLOR_CYAN="\033[36m"
COLOR_BOLD="\033[1m"

TARGET_TIER=""
VERBOSE=false
JSON_MODE=false

show_help() {
    cat <<EOF
Usage: ./tests/e2e/run_tests.sh [OPTIONS]

Unified E2E test runner for Daml 3.x Docker & Rust DAR Parser tool.

Options:
  --tier <1|2|3|4>     Run only the specified test tier
  -v, --verbose        Show detailed execution logs
  --json               Output test results as machine-readable JSON
  -h, --help           Show this help message and exit

Tiers:
  Tier 1: Feature Coverage (isolated happy path verification)
  Tier 2: Boundary & Corner Cases (limits, corrupted headers, security invariants)
  Tier 3: Cross-Feature Combinations (pairwise interactions, multiple packages, CLI flags)
  Tier 4: Real-World Scenarios (complete workflows: build container -> compile DAR -> parse DAR)

Exit Codes:
  0   All executed tests passed (or were legitimately skipped)
  1   One or more tests failed
  2   Usage / configuration error
EOF
}

# Parse CLI options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tier)
            TARGET_TIER="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --json)
            JSON_MODE=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            show_help >&2
            exit 2
            ;;
    esac
done

# Ensure test fixtures exist
if [[ ! -f "${FIXTURES_DIR}/valid_minimal.dar" ]]; then
    if [[ "${JSON_MODE}" == false ]]; then
        echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} Test fixtures missing; invoking generate_fixtures.py..."
    fi
    python3 "${HARNESS_DIR}/generate_fixtures.py" "${FIXTURES_DIR}" >/dev/null 2>&1
fi

TOTAL_TESTS=0
TOTAL_PASSED=0
TOTAL_FAILED=0
TOTAL_SKIPPED=0

TIER1_RESULT=0
TIER2_RESULT=0
TIER3_RESULT=0
TIER4_RESULT=0

run_tier_script() {
    local tier_num="$1"
    local script_name="$2"
    local script_path="${CASES_DIR}/${script_name}"

    if [[ ! -f "${script_path}" ]]; then
        echo "Error: Test script '${script_path}' not found." >&2
        return 1
    fi

    local output
    local status=0

    if [[ "${VERBOSE}" == true ]]; then
        "${script_path}"
        status=$?
    else
        output=$("${script_path}" 2>&1)
        status=$?
        if [[ "${JSON_MODE}" == false ]]; then
            echo "${output}"
        fi
    fi

    # Parse counts from output
    local counts
    counts=$(echo "${output:-}" | grep -E "Summary: Total=" || true)
    if [[ -n "${counts}" ]]; then
        local t p f s
        t=$(echo "${counts}" | sed -E 's/.*Total=([0-9]+).*/\1/')
        p=$(echo "${counts}" | sed -E 's/.*Passed=([0-9]+).*/\1/')
        f=$(echo "${counts}" | sed -E 's/.*Failed=([0-9]+).*/\1/')
        s=$(echo "${counts}" | sed -E 's/.*Skipped=([0-9]+).*/\1/')

        TOTAL_TESTS=$((TOTAL_TESTS + t))
        TOTAL_PASSED=$((TOTAL_PASSED + p))
        TOTAL_FAILED=$((TOTAL_FAILED + f))
        TOTAL_SKIPPED=$((TOTAL_SKIPPED + s))
    fi

    return ${status}
}

# Execution
if [[ -z "${TARGET_TIER}" || "${TARGET_TIER}" == "1" ]]; then
    run_tier_script 1 "tier1_feature_coverage.sh" || TIER1_RESULT=1
fi

if [[ -z "${TARGET_TIER}" || "${TARGET_TIER}" == "2" ]]; then
    run_tier_script 2 "tier2_boundary_corner.sh" || TIER2_RESULT=1
fi

if [[ -z "${TARGET_TIER}" || "${TARGET_TIER}" == "3" ]]; then
    run_tier_script 3 "tier3_combinations.sh" || TIER3_RESULT=1
fi

if [[ -z "${TARGET_TIER}" || "${TARGET_TIER}" == "4" ]]; then
    run_tier_script 4 "tier4_real_world.sh" || TIER4_RESULT=1
fi

OVERALL_STATUS=0
if [[ ${TIER1_RESULT} -ne 0 || ${TIER2_RESULT} -ne 0 || ${TIER3_RESULT} -ne 0 || ${TIER4_RESULT} -ne 0 || ${TOTAL_FAILED} -gt 0 ]]; then
    OVERALL_STATUS=1
fi

if [[ "${JSON_MODE}" == true ]]; then
    cat <<EOF
{
  "total": ${TOTAL_TESTS},
  "passed": ${TOTAL_PASSED},
  "failed": ${TOTAL_FAILED},
  "skipped": ${TOTAL_SKIPPED},
  "status": "$([[ ${OVERALL_STATUS} -eq 0 ]] && echo "PASSED" || echo "FAILED")",
  "tiers": {
    "tier1": { "status": "$([[ ${TIER1_RESULT} -eq 0 ]] && echo "OK" || echo "FAIL")" },
    "tier2": { "status": "$([[ ${TIER2_RESULT} -eq 0 ]] && echo "OK" || echo "FAIL")" },
    "tier3": { "status": "$([[ ${TIER3_RESULT} -eq 0 ]] && echo "OK" || echo "FAIL")" },
    "tier4": { "status": "$([[ ${TIER4_RESULT} -eq 0 ]] && echo "OK" || echo "FAIL")" }
  }
}
EOF
else
    echo -e "\n${COLOR_CYAN}${COLOR_BOLD}================================================================================${COLOR_RESET}"
    echo -e "${COLOR_BOLD}E2E Test Execution Summary${COLOR_RESET}"
    echo -e "${COLOR_CYAN}================================================================================${COLOR_RESET}"
    printf "  %-35s %-10s\n" "Tier" "Result"
    echo -e "  -------------------------------------------------"
    printf "  %-35s %s\n" "Tier 1: Feature Coverage" "$([[ ${TIER1_RESULT} -eq 0 ]] && echo -e "${COLOR_GREEN}PASSED${COLOR_RESET}" || echo -e "${COLOR_RED}FAILED${COLOR_RESET}")"
    printf "  %-35s %s\n" "Tier 2: Boundary & Corner Cases" "$([[ ${TIER2_RESULT} -eq 0 ]] && echo -e "${COLOR_GREEN}PASSED${COLOR_RESET}" || echo -e "${COLOR_RED}FAILED${COLOR_RESET}")"
    printf "  %-35s %s\n" "Tier 3: Cross-Feature Combinations" "$([[ ${TIER3_RESULT} -eq 0 ]] && echo -e "${COLOR_GREEN}PASSED${COLOR_RESET}" || echo -e "${COLOR_RED}FAILED${COLOR_RESET}")"
    printf "  %-35s %s\n" "Tier 4: Real-World Scenarios" "$([[ ${TIER4_RESULT} -eq 0 ]] && echo -e "${COLOR_GREEN}PASSED${COLOR_RESET}" || echo -e "${COLOR_RED}FAILED${COLOR_RESET}")"
    echo -e "  -------------------------------------------------"
    echo -e "  Total Tests:   ${TOTAL_TESTS}"
    echo -e "  Passed:        ${COLOR_GREEN}${TOTAL_PASSED}${COLOR_RESET}"
    echo -e "  Failed:        ${COLOR_RED}${TOTAL_FAILED}${COLOR_RESET}"
    echo -e "  Skipped:       ${COLOR_YELLOW}${TOTAL_SKIPPED}${COLOR_RESET}"
    echo -e "${COLOR_CYAN}================================================================================${COLOR_RESET}"

    if [[ ${OVERALL_STATUS} -eq 0 ]]; then
        echo -e "${COLOR_GREEN}${COLOR_BOLD}OVERALL RESULT: SUCCESS${COLOR_RESET}\n"
    else
        echo -e "${COLOR_RED}${COLOR_BOLD}OVERALL RESULT: FAILURE${COLOR_RESET}\n"
    fi
fi

exit ${OVERALL_STATUS}
