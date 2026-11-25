#!/usr/bin/env bash
# ==============================================================================
# tests/e2e/cases/tier2_boundary_corner.sh
# Tier 2: Boundary, Corner Cases, and Security Invariants
# Covers AT-A01 (limits), AT-A02 (traversal), AT-A04 (tampering), AT-A06 (LF2 gating), AT-A08 (interned oob)
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../harness/test_helpers.sh"

log_tier "TIER 2: BOUNDARY & CORNER CASES (SECURITY & MALFORMED INPUTS)"

# Ensure test fixtures exist
if [[ ! -f "${FIXTURES_DIR}/corrupt_bad_magic.dar" ]]; then
    log_info "Generating test fixtures..."
    python3 "${HARNESS_DIR}/generate_fixtures.py" "${FIXTURES_DIR}" >/dev/null 2>&1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

# ------------------------------------------------------------------------------
# Test 1: CLI invocation with missing required argument
# ------------------------------------------------------------------------------
test_start "CLI invocation without arguments exits non-zero with error"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser
    if [[ $LAST_EXIT_CODE -ne 0 ]]; then
        test_pass
    else
        test_fail "Expected non-zero exit code when no arguments provided"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 2: Non-existent file path
# ------------------------------------------------------------------------------
test_start "Rejects non-existent file path with non-zero exit code"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${TMP_DIR}/nonexistent_dar_archive_path.dar"
    if [[ $LAST_EXIT_CODE -ne 0 ]]; then
        test_pass
    else
        test_fail "Expected non-zero exit code for nonexistent file"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 3: Zero-byte empty file
# ------------------------------------------------------------------------------
test_start "Rejects zero-byte empty file with non-zero exit code"
EMPTY_FILE="${TMP_DIR}/empty_file.dar"
touch "${EMPTY_FILE}"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${EMPTY_FILE}"
    if [[ $LAST_EXIT_CODE -ne 0 ]]; then
        test_pass
    else
        test_fail "Expected non-zero exit code for empty file"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 4: Malformed magic bytes (Not a ZIP)
# ------------------------------------------------------------------------------
test_start "Rejects non-ZIP file with corrupted header magic"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/corrupt_bad_magic.dar"
    if [[ $LAST_EXIT_CODE -ne 0 ]]; then
        test_pass
    else
        test_fail "Expected non-zero exit code for non-ZIP file"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 5: Missing META-INF/MANIFEST.MF
# ------------------------------------------------------------------------------
test_start "Rejects ZIP archive missing META-INF/MANIFEST.MF"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/corrupt_no_manifest.dar"
    if [[ $LAST_EXIT_CODE -ne 0 ]] && [[ "${LAST_STDERR} ${LAST_STDOUT}" =~ (MANIFEST|manifest|Missing) ]]; then
        test_pass
    else
        test_fail "Expected error reporting missing manifest"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 6: Manifest missing Main-Dalf header
# ------------------------------------------------------------------------------
test_start "Rejects manifest missing required Main-Dalf header"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/corrupt_no_main_dalf.dar"
    if [[ $LAST_EXIT_CODE -ne 0 ]] && [[ "${LAST_STDERR} ${LAST_STDOUT}" =~ (Main-Dalf|main-dalf|Missing) ]]; then
        test_pass
    else
        test_fail "Expected error reporting missing Main-Dalf"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 7: Main-Dalf points to missing entry in ZIP
# ------------------------------------------------------------------------------
test_start "Rejects archive where declared Main-Dalf is missing from ZIP"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/corrupt_missing_main_file.dar"
    if [[ $LAST_EXIT_CODE -ne 0 ]]; then
        test_pass
    else
        test_fail "Expected non-zero exit code for missing main dalf entry"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 8: Non-UTF-8 bytes in MANIFEST.MF
# ------------------------------------------------------------------------------
test_start "Rejects manifest containing invalid non-UTF-8 byte sequences"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/corrupt_invalid_utf8.dar"
    if [[ $LAST_EXIT_CODE -ne 0 ]] && [[ "${LAST_STDERR} ${LAST_STDOUT}" =~ (UTF-8|utf-8|Invalid) ]]; then
        test_pass
    else
        test_fail "Expected UTF-8 decoding error"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 9: AT-A04 Cryptographic Payload Tampering
# ------------------------------------------------------------------------------
test_start "AT-A04: Rejects payload with tampered bytes (hash mismatch)"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/corrupt_tampered_payload.dar"
    if [[ $LAST_EXIT_CODE -ne 0 ]] && [[ "${LAST_STDERR} ${LAST_STDOUT}" =~ (mismatch|Mismatch|PackageIdMismatch|hash|integrity) ]]; then
        test_pass
    else
        test_fail "Expected AT-A04 Package ID mismatch rejection"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 10: Unsupported Hash Function enum in Archive envelope
# ------------------------------------------------------------------------------
test_start "Rejects archive with unsupported hash function enum (non-SHA256)"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/corrupt_bad_hash_func.dar"
    if [[ $LAST_EXIT_CODE -ne 0 ]] && [[ "${LAST_STDERR} ${LAST_STDOUT}" =~ (hash_function|HashFunction|UnsupportedHashFunction|7) ]]; then
        test_pass
    else
        test_fail "Expected rejection of non-SHA256 hash function"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 11: AT-A06 Legacy Daml-LF 1.x Archive Rejection
# ------------------------------------------------------------------------------
test_start "AT-A06: Rejects legacy Daml-LF 1.x archive (requires LF 2)"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/corrupt_legacy_lf1.dar"
    if [[ $LAST_EXIT_CODE -ne 0 ]] && [[ "${LAST_STDERR} ${LAST_STDOUT}" =~ (Daml-LF 1|LF 1|UnsupportedMajorVersion|major version|LF2 required) ]]; then
        test_pass
    else
        test_fail "Expected AT-A06 LF 1 rejection"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 12: AT-A06 Unsupported LF 2 Minor Version
# ------------------------------------------------------------------------------
test_start "AT-A06: Rejects unknown LF 2 minor version ('99')"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/corrupt_unknown_minor.dar"
    if [[ $LAST_EXIT_CODE -ne 0 ]] && [[ "${LAST_STDERR} ${LAST_STDOUT}" =~ (UnsupportedMinor|minor|99) ]]; then
        test_pass
    else
        test_fail "Expected AT-A06 unknown minor version rejection"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 13: AT-A08 Out-of-bounds interned string index handling
# ------------------------------------------------------------------------------
test_start "AT-A08: Safely handles out-of-bounds interned string index"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/corrupt_interned_oob.dar"
    # Must exit without panic or crash (exit code non-zero or safe fallback)
    if [[ ! "${LAST_STDERR}" =~ (panicked|SIGSEGV|core dumped) ]]; then
        test_pass
    else
        test_fail "Process panicked or dumped core on AT-A08 out-of-bounds index"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 14: AT-A02 Path Traversal Attack
# ------------------------------------------------------------------------------
test_start "AT-A02: Rejects archive containing path traversal sequences (../)"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/attack_path_traversal.dar"
    if [[ $LAST_EXIT_CODE -ne 0 ]] && [[ "${LAST_STDERR} ${LAST_STDOUT}" =~ (traversal|Traversal|PathTraversal|security) ]]; then
        test_pass
    else
        test_fail "Expected AT-A02 path traversal rejection"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 15: AT-A01 Per-Entry Decompression Ceiling (> 256 MiB)
# ------------------------------------------------------------------------------
test_start "AT-A01: Rejects single entry exceeding 256 MiB decompression limit"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/attack_entry_bomb.dar"
    if [[ $LAST_EXIT_CODE -ne 0 ]] && [[ "${LAST_STDERR} ${LAST_STDOUT}" =~ (limit|budget|ceiling|EntryTooLarge|too large) ]]; then
        test_pass
    else
        test_fail "Expected AT-A01 entry ceiling violation rejection"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

# ------------------------------------------------------------------------------
# Test 16: AT-A01 Cumulative Archive Decompression Ceiling (> 2 GiB)
# ------------------------------------------------------------------------------
test_start "AT-A01: Rejects archive exceeding 2 GiB cumulative budget limit"
if find_dar_parser >/dev/null 2>&1; then
    run_dar_parser "${FIXTURES_DIR}/attack_total_budget.dar"
    if [[ $LAST_EXIT_CODE -ne 0 ]] && [[ "${LAST_STDERR} ${LAST_STDOUT}" =~ (limit|budget|ceiling|ArchiveTooLarge|too large) ]]; then
        test_pass
    else
        test_fail "Expected AT-A01 archive budget violation rejection"
    fi
else
    test_skip "dar-parser binary not built yet (M3 dependency)"
fi

echo -e "\nTier 2 Summary: Total=${TOTAL_COUNT}, Passed=${PASS_COUNT}, Failed=${FAIL_COUNT}, Skipped=${SKIP_COUNT}"
if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
fi
exit 0
