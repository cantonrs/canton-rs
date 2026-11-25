#!/usr/bin/env bash
# AT-V01: a test must not pass because its input is missing. This scanner fails when a Rust test file under a `tests/` directory
# (or a `*_tests.rs` file) skips silently: an `if !<path>.exists() { return; }` guard, an environment-variable check that returns,
# or an `#[ignore]` attribute. A missing input has to panic (assert!/expect), so that it is counted as a failure.
#
#   scripts/check-no-silent-skips.sh             scan the workspace          (exit 0 clean, 1 a silent skip was found)
#   scripts/check-no-silent-skips.sh --selftest  prove the scanner fails on each pattern (negative controls)
#
# An `#[ignore]` is allowed only when tests/ignored-tests.tsv lists that test (columns: file, test, how it is run, why). The list is
# the review point: a test that has to run alone on the shared sandbox, or that is parked as an open UNRESOLVED item, is named there
# with the command that runs it. An ignore that is not listed, and a listed test that has no `#[ignore]` any more, both fail.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

scan() {
python3 - "$@" <<'PY'
import pathlib, re, sys

import os
allow = {}
allow_path = os.environ.get("IGNORED_TESTS_TSV", "")
if allow_path and os.path.exists(allow_path):
    for ln in open(allow_path, encoding="utf-8"):
        if ln.startswith("#") or not ln.strip():
            continue
        c = ln.rstrip("\n").split("\t")
        allow[(c[0], c[1])] = ln
used = set()
root_dir = os.environ.get("REPO_ROOT", "")
roots = [pathlib.Path(p) for p in sys.argv[1:]]
files = []
for root in roots:
    if root.is_file():
        files.append(root)
        continue
    for f in root.rglob("*.rs"):
        parts = f.parts
        if "target" in parts or "references" in parts:
            continue
        if "tests" in parts or f.name.endswith("_tests.rs"):
            files.append(f)

exists_guard = re.compile(r"if\s+!\s*[\w\.\(\)&:]*?(exists|is_file|is_dir)\s*\(\s*\)")
env_guard = re.compile(r"if\s+(std::)?env::var(_os)?\([^)]*\)\s*\.\s*(is_err|is_none)\s*\(\s*\)")
found = []
for f in sorted(set(files)):
    lines = f.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#[ignore"):
            name = ""
            for nxt in lines[i + 1:i + 6]:
                m = re.match(r"\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)", nxt)
                if m:
                    name = m.group(1)
                    break
            rel = os.path.relpath(f, root_dir) if root_dir else str(f)
            if (rel, name) in allow:
                used.add((rel, name))
            else:
                found.append((f, i + 1, "#[ignore] that tests/ignored-tests.tsv does not list (an ignored test is a skipped test)"))
        if exists_guard.search(line) or env_guard.search(line):
            window = " ".join(l.strip() for l in lines[i:i + 4])
            if re.search(r"\breturn\s*(;|Ok\(\(\)\))", window):
                found.append((f, i + 1, "missing input returns instead of failing"))
for key in sorted(set(allow) - used):
    if root_dir and any(str(r).startswith(root_dir) and r.is_dir() for r in roots):
        found.append((key[0], 0, f"tests/ignored-tests.tsv lists {key[1]} but it has no #[ignore] any more: remove the row"))
for f, n, why in found:
    print(f"SILENT SKIP {f}:{n}: {why}")
sys.exit(1 if found else 0)
PY
}

if [[ "${1:-}" == "--selftest" ]]; then
    T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
    mkdir -p "$T/tests"
    bad=0
    check() { # name, content
        printf '%s\n' "$2" > "$T/tests/case.rs"
        if scan "$T/tests/case.rs" >/dev/null 2>&1; then echo "SELFTEST FAIL: $1 was not detected" >&2; bad=1; else echo "  ok: $1 is detected"; fi
    }
    check "an exists() guard that returns" $'#[test]\nfn t() {\n    let p = x();\n    if !p.exists() {\n        return;\n    }\n}'
    check "an env guard that returns" $'#[test]\nfn t() {\n    if std::env::var("DAR").is_err() {\n        return;\n    }\n}'
    check "an #[ignore] attribute" $'#[test]\n#[ignore]\nfn t() {}'
    printf '#[test]\nfn t() {\n    assert!(p.exists(), "missing");\n}\n' > "$T/tests/clean.rs"
    if scan "$T/tests/clean.rs" >/dev/null 2>&1; then echo "  ok: an assert on a missing input is clean"; else echo "SELFTEST FAIL: a clean test was flagged" >&2; bad=1; fi
    [[ "$bad" == 0 ]] || exit 1
    echo "check-no-silent-skips selftest: OK"
    exit 0
fi

IGNORED_TESTS_TSV="$ROOT/tests/ignored-tests.tsv" REPO_ROOT="$ROOT" scan "$ROOT/crates" "$ROOT/tests" && echo "check-no-silent-skips: OK (no silent skip in the Rust tests)"
