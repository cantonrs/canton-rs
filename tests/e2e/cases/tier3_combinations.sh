#!/usr/bin/env bash
# ==============================================================================
# tests/e2e/cases/tier3_combinations.sh
# Tier 3: Cross-Feature Combinations & Pairwise Interactions
# Covers combinations of CLI flags, multi-package archives, path styles, and shell pipes
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../harness/test_helpers.sh"

log_tier "TIER 3: CROSS-FEATURE COMBINATIONS & PAIRWISE INTERACTIONS"

# Ensure test fixtures exist
if [[ ! -f "${FIXTURES_DIR}/valid_multidalf.dar" ]]; then
    log_info "Generating test fixtures..."
    python3 "${HARNESS_DIR}/generate_fixtures.py" "${FIXTURES_DIR}" >/dev/null 2>&1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

# ------------------------------------------------------------------------------
# Test 1: Combining --json flag with pipe to jq / python json parser
# ------------------------------------------------------------------------------
test_start "Combining --json with standard stream piping to JSON parser"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser --json "${FIXTURES_DIR}/valid_minimal.dar"
    if [[ $LAST_EXIT_CODE -eq 0 ]]; then
        PARSED_NAME=$(echo "${LAST_STDOUT}" | python3 -c "import json, sys; print(json.load(sys.stdin)['main_package']['name'])" 2>/dev/null || true)
        if [[ "${PARSED_NAME}" == "sample-contract" ]]; then
            test_pass
        else
            test_fail "Piped JSON extraction yielded '${PARSED_NAME}', expected 'sample-contract'"
        fi
    else
        test_fail "Exit code non-zero: ${LAST_EXIT_CODE}"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 2: Multi-DALF archive + --json flag (pairwise: multi-package & machine-readable)
# ------------------------------------------------------------------------------
test_start "Multi-DALF archive with --json contains main package and dependency DALFs"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser --json "${FIXTURES_DIR}/valid_multidalf.dar"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && assert_json_valid "${LAST_STDOUT}"; then
        assert_json_field_equals "${LAST_STDOUT}" "main_package.name" "multidalf-contract" && \
        if echo "${LAST_STDOUT}" | grep -q "daml-prim.dalf" && echo "${LAST_STDOUT}" | grep -q "daml-stdlib.dalf"; then
            test_pass
        else
            test_fail "Multi-DALF dependency list missing from JSON"
        fi
    else
        test_fail "JSON parsing failed for multi-DALF archive"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 3: RFC 822 folded manifest combined with multi-DALF dependencies
# ------------------------------------------------------------------------------
test_start "RFC 822 folded manifest combined with multi-DALF dependencies"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser --json "${FIXTURES_DIR}/valid_folded_manifest.dar"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && assert_json_valid "${LAST_STDOUT}"; then
        assert_json_field_equals "${LAST_STDOUT}" "main_package.name" "folded-contract" && \
        if echo "${LAST_STDOUT}" | grep -q "sample-very-long-name-contract" && echo "${LAST_STDOUT}" | grep -q "daml-prim.dalf"; then
            test_pass
        else
            test_fail "Folded manifest entries not correctly resolved in multi-DALF archive"
        fi
    else
        test_fail "Failed to parse folded multi-DALF manifest"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 4: Path normalization: relative path with redundant dot segments
# ------------------------------------------------------------------------------
test_start "Path normalization handles redundant relative segments (./ and ../)"
if find_dar_parser >/dev/null 2>&1; then
    COMPLEX_PATH="${SCRIPT_DIR}/../fixtures/../fixtures/./valid_minimal.dar"
    run_dar_parser "${COMPLEX_PATH}"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && [[ "${LAST_STDOUT}" == *"sample-contract"* ]]; then
        test_pass
    else
        test_fail "Failed to inspect file via complex relative path"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 5: Absolute path invocation
# ------------------------------------------------------------------------------
test_start "Absolute path invocation resolves identical package metadata"
if find_dar_parser >/dev/null 2>&1; then
    ABS_PATH="$(cd "${FIXTURES_DIR}" && pwd)/valid_minimal.dar"
    run_dar_parser "${ABS_PATH}"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && [[ "${LAST_STDOUT}" == *"sample-contract"* ]]; then
        test_pass
    else
        test_fail "Failed to inspect file via absolute path"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 6: Combining flags: positional arg before vs. after flags
# ------------------------------------------------------------------------------
test_start "Flexible flag order: flags before vs. after DAR file path"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/valid_minimal.dar" --json
    if [[ $LAST_EXIT_CODE -eq 0 ]] && assert_json_valid "${LAST_STDOUT}"; then
        test_pass
    else
        test_fail "CLI failed when --json passed after positional path argument"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 7: Error handling with --json flag on corrupted input
# ------------------------------------------------------------------------------
test_start "Corrupted input with --json exits non-zero without JSON parser crash"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser --json "${FIXTURES_DIR}/corrupt_tampered_payload.dar"
    if [[ $LAST_EXIT_CODE -ne 0 ]]; then
        test_pass
    else
        test_fail "Expected non-zero exit code on tampered payload even with --json"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 8: Successive archive inspections in isolated processes
# ------------------------------------------------------------------------------
test_start "Successive archive inspections execute deterministically"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/valid_lf22.dar"
    CODE1=$LAST_EXIT_CODE
    OUT1=$LAST_STDOUT
    run_dar_parser "${FIXTURES_DIR}/valid_lf23.dar"
    CODE2=$LAST_EXIT_CODE
    OUT2=$LAST_STDOUT
    run_dar_parser "${FIXTURES_DIR}/valid_lf24.dar"
    CODE3=$LAST_EXIT_CODE
    OUT3=$LAST_STDOUT

    if [[ $CODE1 -eq 0 ]] && [[ $CODE2 -eq 0 ]] && [[ $CODE3 -eq 0 ]] && \
       [[ "${OUT1}" != "${OUT2}" ]]; then
        test_pass
    else
        test_fail "Successive invocations failed or produced cross-run contamination"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 9: Daml project configuration and sample contract coordination
# ------------------------------------------------------------------------------
test_start "Coordinated check: contracts/daml.yaml name matches contract module"
DAML_YAML="${PROJECT_ROOT}/contracts/daml.yaml"
CONTRACT_DAML="${PROJECT_ROOT}/contracts/daml/AssetHolding.daml"
if [[ -f "${DAML_YAML}" ]] && [[ -f "${CONTRACT_DAML}" ]]; then
    YAML_NAME=$(grep "^name:" "${DAML_YAML}" | awk '{print $2}')
    if [[ "${YAML_NAME}" == "sample-contract" ]] && grep -q "module AssetHolding" "${CONTRACT_DAML}"; then
        test_pass
    else
        test_fail "Mismatch between project configuration and contract module"
    fi
else
    test_fail "daml.yaml or AssetHolding.daml missing"
fi

# ------------------------------------------------------------------------------
# Test 10: Developer tooling clean and verify cycle
# ------------------------------------------------------------------------------
test_start "Makefile verification target enforces existence of DAR file"
MAKEFILE="${PROJECT_ROOT}/Makefile"
if [[ -f "${MAKEFILE}" ]]; then
    # Test that verify fails if DAR file does not exist
    NONEXISTENT_DIR="${TMP_DIR}/fake_contract_dir"
    mkdir -p "${NONEXISTENT_DIR}"
    (
        cd "${PROJECT_ROOT}"
        make verify DAR_FILE="${NONEXISTENT_DIR}/fake.dar" >/dev/null 2>&1
    )
    if [[ $? -ne 0 ]]; then
        test_pass
    else
        test_fail "make verify succeeded on nonexistent DAR file"
    fi
else
    test_fail "Makefile missing"
fi

echo -e "\nTier 3 Summary: Total=${TOTAL_COUNT}, Passed=${PASS_COUNT}, Failed=${FAIL_COUNT}, Skipped=${SKIP_COUNT}"
if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
fi
exit 0
