#!/usr/bin/env bash
# ==============================================================================
# tests/e2e/cases/tier1_feature_coverage.sh
# Tier 1: Feature Coverage (Isolated Happy Path Verification)
# Covers Features 1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 23, 24, 25, 26
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../harness/test_helpers.sh"

log_tier "TIER 1: FEATURE COVERAGE (HAPPY PATH)"

# Ensure test fixtures exist
if [[ ! -f "${FIXTURES_DIR}/valid_minimal.dar" ]]; then
    log_info "Generating test fixtures..."
    python3 "${HARNESS_DIR}/generate_fixtures.py" "${FIXTURES_DIR}" >/dev/null 2>&1
fi

# ------------------------------------------------------------------------------
# Test 1: CLI --help option
# ------------------------------------------------------------------------------
test_start "CLI --help displays usage instructions and options"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser --help
    if [[ $LAST_EXIT_CODE -eq 0 ]] && [[ "${LAST_STDOUT}" =~ (Usage|Options|Commands|dar-parser) ]]; then
        test_pass
    else
        test_fail "Expected exit code 0 with help text, got code ${LAST_EXIT_CODE}"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 2: CLI --version option
# ------------------------------------------------------------------------------
test_start "CLI --version displays application version"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser --version
    if [[ $LAST_EXIT_CODE -eq 0 ]] && [[ "${LAST_STDOUT}" =~ (dar-parser|[0-9]+\.[0-9]+\.[0-9]+) ]]; then
        test_pass
    else
        test_fail "Expected exit code 0 with version string, got code ${LAST_EXIT_CODE}"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 3: Inspect Valid Minimal DAR (Pretty ASCII Output)
# ------------------------------------------------------------------------------
test_start "Inspect valid minimal DAR emits formatted ASCII report"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/valid_minimal.dar"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && \
       [[ "${LAST_STDOUT}" == *"sample-contract"* ]] && \
       [[ "${LAST_STDOUT}" == *"0.1.0"* ]] && \
       [[ "${LAST_STDOUT}" == *"AssetHolding"* ]] && \
       [[ "${LAST_STDOUT}" =~ (2\.1|LF Version) ]]; then
        test_pass
    else
        test_fail "Missing expected metadata fields in text output"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 4: Inspect Valid Minimal DAR with --json
# ------------------------------------------------------------------------------
test_start "Inspect valid minimal DAR with --json emits valid JSON schema"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser --json "${FIXTURES_DIR}/valid_minimal.dar"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && assert_json_valid "${LAST_STDOUT}"; then
        assert_json_field_equals "${LAST_STDOUT}" "main_package.name" "sample-contract" && \
        assert_json_field_equals "${LAST_STDOUT}" "main_package.version" "0.1.0" && \
        assert_json_field_equals "${LAST_STDOUT}" "main_package.lf_version" "2.1" && \
        test_pass
    else
        test_fail "JSON output validation failed"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 5: Multi-DALF DAR dependencies inspection
# ------------------------------------------------------------------------------
test_start "Inspect multi-DALF DAR parses main package and dependencies"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/valid_multidalf.dar"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && \
       [[ "${LAST_STDOUT}" == *"multidalf-contract"* ]] && \
       [[ "${LAST_STDOUT}" == *"daml-prim"* ]] && \
       [[ "${LAST_STDOUT}" == *"daml-stdlib"* ]]; then
        test_pass
    else
        test_fail "Multi-DALF dependencies not listed in human output"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 6: Multi-DALF DAR --json dependencies schema
# ------------------------------------------------------------------------------
test_start "Inspect multi-DALF DAR with --json lists all bundled DALF paths"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser --json "${FIXTURES_DIR}/valid_multidalf.dar"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && assert_json_valid "${LAST_STDOUT}"; then
        if echo "${LAST_STDOUT}" | grep -q "daml-prim" && echo "${LAST_STDOUT}" | grep -q "daml-stdlib"; then
            test_pass
        else
            test_fail "Dependency DALFs not found in JSON"
        fi
    else
        test_fail "Invalid JSON for multi-DALF archive"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 7: RFC 822 Manifest line unfolding (space prefixed lines)
# ------------------------------------------------------------------------------
test_start "RFC 822 manifest line unfolding resolves wrapped Main-Dalf"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/valid_folded_manifest.dar"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && [[ "${LAST_STDOUT}" == *"folded-contract"* ]]; then
        test_pass
    else
        test_fail "Failed to resolve unfolded Main-Dalf entry"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 8: LF 2 Minor Version Support: 2.2
# ------------------------------------------------------------------------------
test_start "Supports Daml-LF 2.2 archive without rejection"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/valid_lf22.dar"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && [[ "${LAST_STDOUT}" =~ (2\.2|contract-lf22) ]]; then
        test_pass
    else
        test_fail "LF 2.2 archive failed to parse or was rejected"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 9: LF 2 Minor Version Support: 2.3
# ------------------------------------------------------------------------------
test_start "Supports Daml-LF 2.3 archive without rejection"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/valid_lf23.dar"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && [[ "${LAST_STDOUT}" =~ (2\.3|contract-lf23) ]]; then
        test_pass
    else
        test_fail "LF 2.3 archive failed to parse or was rejected"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 10: LF 2 Minor Version Support: 2.4
# ------------------------------------------------------------------------------
test_start "Supports Daml-LF 2.4 archive without rejection"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/valid_lf24.dar"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && [[ "${LAST_STDOUT}" =~ (2\.4|contract-lf24) ]]; then
        test_pass
    else
        test_fail "LF 2.4 archive failed to parse or was rejected"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 11: Dockerfile structure and configuration (Feature 13, 14, 15)
# ------------------------------------------------------------------------------
test_start "docker/Dockerfile defines Temurin 21 base and dpm 3.7.1 SDK"
DOCKERFILE="${PROJECT_ROOT}/docker/Dockerfile"
if [[ -f "${DOCKERFILE}" ]]; then
    if grep -q "eclipse-temurin:21-jdk-jammy" "${DOCKERFILE}" && \
       grep -q "3.7.1" "${DOCKERFILE}" && \
       grep -q "ln -sf" "${DOCKERFILE}"; then
        test_pass
    else
        test_fail "Dockerfile missing required Temurin 21 base, SDK 3.7.1, or symlink definitions"
    fi
else
    test_fail "docker/Dockerfile does not exist"
fi

# ------------------------------------------------------------------------------
# Test 12: Daml project configuration contracts/daml.yaml (Feature 16)
# ------------------------------------------------------------------------------
test_start "contracts/daml.yaml pins SDK 3.7.1 and target 2.1"
DAML_YAML="${PROJECT_ROOT}/contracts/daml.yaml"
if [[ -f "${DAML_YAML}" ]]; then
    if grep -q "sdk-version: 3.7.1" "${DAML_YAML}" && \
       grep -q "sample-contract" "${DAML_YAML}" && \
       grep -q -- "--target=2.1" "${DAML_YAML}"; then
        test_pass
    else
        test_fail "contracts/daml.yaml missing sdk-version 3.7.1, sample-contract name, or --target=2.1"
    fi
else
    test_fail "contracts/daml.yaml does not exist"
fi

# ------------------------------------------------------------------------------
# Test 13: Sample Daml smart contract AssetHolding.daml (Feature 17)
# ------------------------------------------------------------------------------
test_start "contracts/daml/AssetHolding.daml defines multi-party contract"
CONTRACT_DAML="${PROJECT_ROOT}/contracts/daml/AssetHolding.daml"
if [[ -f "${CONTRACT_DAML}" ]]; then
    if grep -q "template AssetHolding" "${CONTRACT_DAML}" && \
       grep -q "signatory bank, owner" "${CONTRACT_DAML}" && \
       grep -q "observer auditor" "${CONTRACT_DAML}" && \
       grep -q "choice Transfer" "${CONTRACT_DAML}"; then
        test_pass
    else
        test_fail "AssetHolding.daml missing template, signatories, observers, or choices"
    fi
else
    test_fail "contracts/daml/AssetHolding.daml does not exist"
fi

# ------------------------------------------------------------------------------
# Test 14: Developer automation tooling Makefile (Feature 19)
# ------------------------------------------------------------------------------
test_start "Makefile contains build-image, build-dar, and verify targets"
MAKEFILE="${PROJECT_ROOT}/Makefile"
if [[ -f "${MAKEFILE}" ]]; then
    if grep -q "build-image:" "${MAKEFILE}" && \
       grep -q "build-dar:" "${MAKEFILE}" && \
       grep -q "verify:" "${MAKEFILE}"; then
        test_pass
    else
        test_fail "Makefile missing required targets"
    fi
else
    test_fail "Makefile does not exist"
fi

# ------------------------------------------------------------------------------
# Test 15: Developer automation script build-dar.sh (Feature 19)
# ------------------------------------------------------------------------------
test_start "scripts/build-dar.sh is executable and invokes docker build/run"
BUILD_SCRIPT="${PROJECT_ROOT}/scripts/build-dar.sh"
if [[ -f "${BUILD_SCRIPT}" ]]; then
    if [[ -x "${BUILD_SCRIPT}" ]] && \
       grep -q "docker build" "${BUILD_SCRIPT}" && \
       grep -q "docker run" "${BUILD_SCRIPT}" && \
       grep -q "sample-contract.dar" "${BUILD_SCRIPT}"; then
        test_pass
    else
        test_fail "scripts/build-dar.sh not executable or missing docker build/run commands"
    fi
else
    test_fail "scripts/build-dar.sh does not exist"
fi

echo -e "\nTier 1 Summary: Total=${TOTAL_COUNT}, Passed=${PASS_COUNT}, Failed=${FAIL_COUNT}, Skipped=${SKIP_COUNT}"
if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
fi
exit 0
