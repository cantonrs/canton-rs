#!/usr/bin/env bash
# S-LIC-003: the single-license layout (Apache-2.0 for the whole repository) is consistent with LICENSING.md.
#   - LICENSE-APACHE is the unmodified standard text (pinned SHA-256), NOTICE and LICENSING.md exist, no LICENSE-MIT remains
#   - every workspace crate declares `Apache-2.0`
#   - the separately sourced paths of LICENSING.md exist and canton-proto carries the upstream license copy
# Fails on any drift; the selftest shows the crate check rejects a wrong declaration.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
fail() { echo "FAIL: $*" >&2; exit 1; }

APACHE_SHA="62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a"
for f in LICENSE-APACHE NOTICE LICENSING.md; do [[ -s "$f" ]] || fail "missing $f"; done
[[ ! -e LICENSE-MIT ]] || fail "LICENSE-MIT must not exist: the repository is Apache-2.0 only"
[[ "$(shasum -a 256 LICENSE-APACHE | cut -d' ' -f1)" == "${APACHE_SHA}" ]] || fail "LICENSE-APACHE is not the pinned standard text"

expected_for() { echo "Apache-2.0"; }
check_declared() { # <Cargo.toml> <declared license string>
    [[ "$2" == "$(expected_for "$1")" ]]
}
n=0
for toml in crates/*/*/Cargo.toml; do
    declared="$(sed -n 's/^license = "\(.*\)"$/\1/p' "${toml}" | head -1)"
    [[ -n "${declared}" ]] || fail "${toml}: no license field"
    check_declared "${toml}" "${declared}" || fail "${toml}: declares '${declared}', policy says '$(expected_for "${toml}")'"
    n=$((n + 1))
done
check_declared "crates/protocol/canton-proto/Cargo.toml" "MIT OR Apache-2.0" && fail "selftest: a wrong declaration was accepted"
grep -q "MIT" NOTICE && fail "NOTICE still mentions the MIT license"

for p in crates/protocol/canton-proto crates/core/canton-participant/migrations tests/oracle/lf-vectors tests/oracle/lf-diff tests/oracle/canton-hash tests/oracle/splice-dars tests/oracle/provenance; do
    [[ -d "$p" ]] || fail "Apache-only path missing: $p"
    grep -q "$p" LICENSING.md || fail "LICENSING.md does not list $p"
done
[[ -s crates/core/canton-participant/migrations/LICENSE.txt ]] || fail "canton-participant/migrations lacks the upstream license copy"
[[ -s crates/protocol/canton-proto/proto/LICENSE.txt ]] || fail "canton-proto lacks the upstream license copy"
grep -q "Apache License" crates/protocol/canton-proto/proto/LICENSE.txt || fail "canton-proto/proto/LICENSE.txt is not the Apache license"
echo "verify-licensing: OK (${n} crates checked, selftest ok)"
