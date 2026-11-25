#!/usr/bin/env bash
# S-PROTO-001 self-check for the canton-proto crate.
#   1. the vendored .proto files are byte-identical to the pinned Canton 3.7.2 zip, and the checker catches tampering
#   2. the crate builds (messages only, and with the grpc feature), passes clippy -D warnings, and its tests pass
#      (real DALF bytes from the sample and Splice DARs; cross-check with lf-archive)
# Exit codes: 0 all checks passed; 1 a check failed; 3 NOT_RUN (references/ lacks the pinned 3.7.2 zip).
set -uo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
PROTO="$ROOT_DIR/crates/protocol/canton-proto/proto"
bad=0
ok() { echo "PASS $1"; }
no() { echo "FAIL $1"; bad=$((bad + 1)); }
step() { # name command...
  local name="$1"; shift
  if "$@" > "$T/step.out" 2>&1; then ok "$name"; else no "$name"; tail -15 "$T/step.out" | cut -c1-200 | sed 's/^/    /'; fi
}
T="$(mktemp -d "${TMPDIR:-/tmp}/verifyproto.XXXXXX")"; trap 'rm -rf "$T"' EXIT

echo "== 1. vendored protos"
./scripts/vendor-protos.sh --check > "$T/v.out" 2>&1; rc=$?
if [ "$rc" -eq 3 ]; then cat "$T/v.out"; echo "NOT_RUN: nothing was verified"; exit 3; fi
[ "$rc" -eq 0 ] && cat "$T/v.out" | sed 's/^PASS/PASS/' || { cat "$T/v.out"; no "vendored protos differ from the pinned zip"; }

ctl() { # name expected_exit mutation-command
  rm -rf "$T/copy"; cp -R "$PROTO" "$T/copy"
  ( cd "$T/copy" && eval "$3" ) >/dev/null 2>&1
  PROTO_VENDOR_DIR="$T/copy" ./scripts/vendor-protos.sh --check >/dev/null 2>&1; local got=$?
  [ "$got" -eq "$2" ] && ok "negative control: $1 (exit $got)" || no "negative control: $1 (expected exit $2, got $got)"
}
first="$(cd "$PROTO" && find . -name '*.proto' | LC_ALL=C sort | head -1)"
ctl "unchanged copy passes" 0 ":"
ctl "one appended byte is detected" 1 "printf x >> \"$first\""
ctl "a deleted file is detected" 1 "rm \"$first\""
ctl "an extra proto is detected" 1 "echo 'syntax = \"proto3\";' > extra_unlisted.proto"
ctl "an edited SOURCES.tsv is detected" 1 "sed -i '' '3s/^/x/' SOURCES.tsv"

echo "== 2. crate"
step "cargo build -p canton-proto (messages)" cargo build -p canton-proto
step "cargo build -p canton-proto --features grpc (messages and tonic stubs)" cargo build -p canton-proto --features grpc
step "cargo clippy -p canton-proto --all-targets -- -D warnings" cargo clippy -p canton-proto --all-targets -- -D warnings
step "cargo test -p canton-proto (real DALF bytes, lf-archive cross-check, Splice wire table)" cargo test -p canton-proto

echo "== result"
if [ "$bad" -eq 0 ]; then echo "S-PROTO-001: all checks passed"; exit 0; fi
echo "S-PROTO-001: $bad check(s) FAILED"; exit 1
