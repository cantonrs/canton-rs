#!/usr/bin/env bash
# ==============================================================================
# tests/e2e/cases/tier4_real_world.sh
# Tier 4: Real-World Scenarios & Full Integration Workflows
# Complete workflow: Docker container -> Daml compile -> DAR file -> Rust CLI inspection
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../harness/test_helpers.sh"

log_tier "TIER 4: REAL-WORLD SCENARIOS & PRODUCTION WORKFLOWS"

DAR_FILE="${PROJECT_ROOT}/contracts/target/sample-contract.dar"
KNOWN_PACKAGE_ID="0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2"

# ------------------------------------------------------------------------------
# Test 1: Production DAR artifact generated on host filesystem
# ------------------------------------------------------------------------------
test_start "Production DAR artifact exists and is non-empty at contracts/target/sample-contract.dar"
if [[ -f "${DAR_FILE}" && -s "${DAR_FILE}" ]]; then
    test_pass
else
    test_fail "contracts/target/sample-contract.dar not found or is 0 bytes"
fi

# ------------------------------------------------------------------------------
# Test 2: Production DAR archive passes make verify (ZIP integrity & Manifest)
# ------------------------------------------------------------------------------
test_start "make verify succeeds on production DAR artifact"
if (cd "${PROJECT_ROOT}" && make verify >/dev/null 2>&1); then
    test_pass
else
    test_fail "make verify failed on ${DAR_FILE}"
fi

# ------------------------------------------------------------------------------
# Test 3: Docker container image validation
# ------------------------------------------------------------------------------
test_start "Docker toolchain image daml-toolchain:canton-3.7.2 is available and runnable"
TOOLCHAIN_IMAGE="${TOOLCHAIN_IMAGE:-daml-toolchain:canton-3.7.2}"
if docker image inspect "${TOOLCHAIN_IMAGE}" >/dev/null 2>&1; then
    CONTAINER_OUT=$(docker run --rm "${TOOLCHAIN_IMAGE}" dpm --version 2>&1 || true)
    if echo "${CONTAINER_OUT}" | grep -qE "version: 1\.1\.1"; then
        test_pass
    else
        test_fail "Container ${TOOLCHAIN_IMAGE} executed but unexpected dpm version output: ${CONTAINER_OUT}"
    fi
else
    test_skip "${TOOLCHAIN_IMAGE} docker image not present (run: make build-toolchain)"
fi

# ------------------------------------------------------------------------------
# Test 4: Real-World DAR human inspection via dar-parser CLI
# ------------------------------------------------------------------------------
test_start "dar-parser CLI human inspection of production sample-contract.dar"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${DAR_FILE}"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && \
       [[ "${LAST_STDOUT}" == *"${KNOWN_PACKAGE_ID}"* ]] && \
       [[ "${LAST_STDOUT}" == *"sample-contract"* ]] && \
       [[ "${LAST_STDOUT}" == *"0.1.0"* ]] && \
       [[ "${LAST_STDOUT}" == *"AssetHolding"* ]]; then
        test_pass
    else
        test_fail "dar-parser failed to extract known package ID, name, or module from production DAR"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 5: Real-World DAR machine-readable JSON inspection via dar-parser --json
# ------------------------------------------------------------------------------
test_start "dar-parser --json production output matches damlc inspect-dar schema"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser --json "${DAR_FILE}"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && assert_json_valid "${LAST_STDOUT}"; then
        assert_json_field_equals "${LAST_STDOUT}" "main_package_id" "${KNOWN_PACKAGE_ID}" && \
        assert_json_field_equals "${LAST_STDOUT}" "main_package.name" "sample-contract" && \
        assert_json_field_equals "${LAST_STDOUT}" "main_package.version" "0.1.0" && \
        assert_json_field_equals "${LAST_STDOUT}" "main_package.lf_version" "2.1" && \
        if echo "${LAST_STDOUT}" | grep -q "AssetHolding"; then
            test_pass
        else
            test_fail "AssetHolding module not found in JSON main_package.modules"
        fi
    else
        test_fail "JSON output from production DAR is invalid or missing required fields"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 6: Quickstart documentation verification (Feature 26)
# ------------------------------------------------------------------------------
test_start "Quickstart documentation exists and covers Docker, DAR build, and CLI usage"
DOC_FILE="${PROJECT_ROOT}/doc/01-daml-dar-rust-quickstart.md"
if [[ -f "${DOC_FILE}" ]]; then
    if grep -q "build-image" "${DOC_FILE}" && \
       grep -q "build-dar" "${DOC_FILE}" && \
       grep -q "dar-parser" "${DOC_FILE}" && \
       grep -q "verify-inspect" "${DOC_FILE}"; then
        test_pass
    else
        test_fail "${DOC_FILE} missing build-image, build-dar, dar-parser, or verify-inspect"
    fi
else
    test_skip "doc/01-daml-dar-rust-quickstart.md not written yet"
fi

# ------------------------------------------------------------------------------
# Test 7: Human surface of AssetHolding
# ------------------------------------------------------------------------------
test_start "dar-parser human output shows AssetHolding template surface"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${DAR_FILE}"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && \
       [[ "${LAST_STDOUT}" == *"template AssetHolding"* ]] && \
       [[ "${LAST_STDOUT}" == *"bank : Party"* ]] && \
       [[ "${LAST_STDOUT}" == *"owner : Party"* ]] && \
       [[ "${LAST_STDOUT}" == *"auditor : Party"* ]] && \
       [[ "${LAST_STDOUT}" == *"assetSymbol : Text"* ]] && \
       [[ "${LAST_STDOUT}" == *"amount : Decimal"* ]] && \
       [[ "${LAST_STDOUT}" == *"Signatories: bank, owner"* ]] && \
       [[ "${LAST_STDOUT}" == *"Observers: auditor"* ]] && \
       [[ "${LAST_STDOUT}" == *"Ensure Precondition: present"* ]] && \
       [[ "${LAST_STDOUT}" == *"choice Transfer (consuming)"* ]] && \
       [[ "${LAST_STDOUT}" == *"newOwner : Party"* ]] && \
       [[ "${LAST_STDOUT}" == *"choice SplitTransfer (consuming)"* ]] && \
       [[ "${LAST_STDOUT}" == *"transferAmount : Decimal, recipient : Party"* ]] && \
       [[ "${LAST_STDOUT}" == *"choice Settle (consuming)"* ]] && \
       [[ "${LAST_STDOUT}" == *"choice Archive (consuming)"* ]] && \
       [[ "${LAST_STDOUT}" == *"Do Body: present"* ]]; then
        test_pass
    else
        test_fail "human output missing AssetHolding surface fields, parties, or choices"
    fi
else
    test_skip "dar-parser binary not built yet"
fi

# ------------------------------------------------------------------------------
# Test 8: JSON module_surfaces
# ------------------------------------------------------------------------------
test_start "dar-parser --json module_surfaces matches AssetHolding surface"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser --json "${DAR_FILE}"
    if [[ $LAST_EXIT_CODE -eq 0 ]] && printf '%s' "${LAST_STDOUT}" | python3 -c '
import json, sys
data = json.load(sys.stdin)
surfaces = data.get("module_surfaces")
assert surfaces == data["main_package"]["module_surfaces"]
tmpl = surfaces[0]["templates"][0]
fields = [(f["name"], f["type_str"]) for f in tmpl["fields"]]
assert fields == [("bank","Party"),("owner","Party"),("auditor","Party"),("assetSymbol","Text"),("amount","Decimal")]
assert tmpl["signatories"] == ["bank", "owner"]
assert tmpl["observers"] == ["auditor"]
assert tmpl["ensure"]["present"] is True and tmpl["ensure"]["bytes_len"] > 0
choices = {c["name"]: c for c in tmpl["choices"]}
assert choices["Transfer"]["controllers"] == ["owner"]
assert choices["Transfer"]["params"][0]["name"] == "newOwner"
assert choices["SplitTransfer"]["controllers"] == ["owner"]
assert [p["name"] for p in choices["SplitTransfer"]["params"]] == ["transferAmount", "recipient"]
assert choices["Settle"]["controllers"] == ["bank"]
assert choices["Archive"]["controllers"] == ["bank", "owner"]
for choice in choices.values():
    assert choice["do_body"]["present"] is True and choice["do_body"]["bytes_len"] > 0
'; then
        test_pass
    else
        test_fail "JSON module_surfaces missing AssetHolding fields, parties, choices, or byte presence"
    fi
else
    test_skip "dar-parser binary not built yet"
fi

# ------------------------------------------------------------------------------
# Test 9: Official damlc inspect comparison
# ------------------------------------------------------------------------------
test_start "verify-damlc-inspect aligns dar-parser with official damlc inspect"
if [[ -x "${PROJECT_ROOT}/scripts/verify-damlc-inspect.sh" ]]; then
    if (cd "${PROJECT_ROOT}" && ./scripts/verify-damlc-inspect.sh >/dev/null); then
        test_pass
    else
        test_fail "scripts/verify-damlc-inspect.sh exited non-zero"
    fi
else
    test_fail "scripts/verify-damlc-inspect.sh is missing or not executable"
fi

echo -e "\nTier 4 Summary: Total=${TOTAL_COUNT}, Passed=${PASS_COUNT}, Failed=${FAIL_COUNT}, Skipped=${SKIP_COUNT}"
if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
fi
exit 0
