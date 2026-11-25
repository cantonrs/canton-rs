# daml-builder:3.7.1 is the frozen SDK 3.7.1 provenance of the pinned sample DAR (build-image / build-dar only).
# Everything else runs on daml-toolchain:canton-3.7.2 (make build-toolchain).
DOCKER_IMAGE := daml-builder:3.7.1
DOCKERFILE   := docker/Dockerfile
CONTRACT_DIR := contracts
TARGET_DIR   := $(CONTRACT_DIR)/target
DAR_FILE     := $(TARGET_DIR)/sample-contract.dar

.PHONY: all build-image build-dar clean verify verify-inspect verify-inspect-dar verify-lf-eval verify-tx-ledger verify-canton-hash verify-g0-provenance verify-ledger-api verify-participant verify-sequencer verify-mediator verify-ordering verify-stage10 verify-reassignment verify-stage11 verify-splice verify-stage12 verify-db-takeover verify-stage13 verify-dev-tools verify-stage14 verify-localnet verify-stage15 verify-all fmt docker-build docker-up docker-down docker-logs docker-clean fetch-references verify-references verify-base oracle-verify oracle-selftest verify-proto vendor-protos build-toolchain verify-toolchain inventory-lf verify-lf-inventory verify-lf-diff verify-lf-diff-selftest verify-g0-372 verify-console-dsl-372 verify-damlc-license-372 verify-scala-files-372 verify-crypto-accept-372 verify-wycheproof verify-doc-anchors verify-splice-diff verify-licensing verify-splice-census verify-key-diff verify-json-api verify-lf-fatal verify-pg-store verify-prune verify-pg-migrate verify-sequencer-connect verify-rust-sequencer verify-merkle-views

all: build-dar

fmt:
	cargo fmt --all

# Docker management targets
docker-build:
	@echo "==> Building all Docker images (canton-rs, daml-builder)..."
	./scripts/docker-run.sh build

docker-up:
	@echo "==> Starting Canton cluster containers (LocalNet, Postgres, JSON API)..."
	./scripts/docker-run.sh up

docker-down:
	@echo "==> Stopping Canton cluster containers..."
	./scripts/docker-run.sh down

docker-logs:
	./scripts/docker-run.sh logs

docker-clean:
	@echo "==> Cleaning all cluster containers and data volumes..."
	./scripts/docker-run.sh clean

# Build the Daml 3.x Docker container image
build-image:
	@echo "==> Building Daml 3.x builder container image ($(DOCKER_IMAGE))..."
	docker build -t $(DOCKER_IMAGE) -f $(DOCKERFILE) .

# Compile the Daml smart contract inside the Docker container
build-dar: build-image
	@echo "==> Ensuring target directory exists..."
	@mkdir -p $(TARGET_DIR)
	@echo "==> Compiling Daml smart contract to DAR..."
	./scripts/build-dar.sh

# Verify the generated DAR archive exists and is non-empty
verify:
	@echo "==> Verifying DAR artifact at $(DAR_FILE)..."
	@test -f $(DAR_FILE) || (echo "ERROR: $(DAR_FILE) does not exist" && exit 1)
	@test -s $(DAR_FILE) || (echo "ERROR: $(DAR_FILE) is empty" && exit 1)
	@echo "==> Verifying ZIP integrity and manifest..."
	@unzip -t $(DAR_FILE) > /dev/null || (echo "ERROR: $(DAR_FILE) is not a valid ZIP file" && exit 1)
	@unzip -l $(DAR_FILE) | grep -q "META-INF/MANIFEST.MF" || (echo "ERROR: $(DAR_FILE) missing META-INF/MANIFEST.MF" && exit 1)
	@echo "==> Verification SUCCESS: $(DAR_FILE) is valid."
	@ls -lh $(DAR_FILE)

# Compare dar-parser surface output with official damlc inspect.
# Uses the pinned DAR. Does not rebuild it. Falls back to the committed dump
# when the daml-builder image is unavailable.
verify-inspect:
	./scripts/verify-damlc-inspect.sh

# Compare package ids with official `daml inspect-dar`. Does not rebuild the DAR.
verify-inspect-dar:
	./scripts/verify-inspect-dar.sh

# AT-V01: a removed oracle prerequisite must never count as a pass (negative controls for the oracle scripts and the Rust tests).
verify-guard:
	./scripts/verify-guard.sh

# AT-V02: the requirement denominator and the feature manifest catch a missing requirement and a skipped feature.
verify-requirements:
	./scripts/verify-requirements.sh

# AT-V05: the differential corpora must contain the LF versions, keys, rollback and interface choices the requirements name.
verify-corpus-coverage:
	./scripts/verify-corpus-coverage.sh

# AT-C02: hash purposes and signatures against a Canton node's own crypto API (needs Docker).
verify-canton-crypto:
	./scripts/verify-canton-crypto.sh

# AT-T01/T02: two racing submissions on one contract or key, node vs Rust JSON API (needs Docker).
verify-concurrency:
	./scripts/verify-concurrency.sh

# S-NET-001 (G5): Rust's first gRPC session with an official Canton 3.7.2 sequencer (needs Docker and the Canton JAR).
verify-sequencer-connect:
	./scripts/verify-sequencer-connect.sh

# S-NET-037 (G6): an official JVM participant connects to the Rust sequencer; reports how far it gets (needs Docker and the Canton JAR).
verify-rust-sequencer:
	./scripts/verify-rust-sequencer.sh

verify-merkle-views:
	./scripts/verify-merkle-views.sh

# S-STORE-008: the official PostgreSQL migrations applied by Rust, history and schema vs a participant's (needs Docker and references).
verify-pg-migrate:
	./scripts/verify-pg-migrate.sh

# S-STORE-007: participant pruning (U-17), node vs Rust JSON API (needs Docker; one wait of 75 s).
verify-prune:
	./scripts/verify-prune.sh

# S-STORE-005: the PostgreSQL ledger store: DB tests, the oracle corpus across restarts, SIGKILL of the server and the database (needs Docker).
verify-pg-store:
	./scripts/verify-pg-store.sh

# AT-L04: BigNumeric exists only in LF 2.dev, which neither the JVM participant nor the Rust loader accepts (needs Docker).
verify-bignumeric:
	./scripts/verify-bignumeric.sh

# AT-A01..A05, A07: DAR-input cases agree with the JVM upload endpoint (needs Docker).
verify-dar-input:
	./scripts/verify-dar-input.sh

# Compile the LF corpus with the image damlc and diff `daml script` against lf-eval.
verify-lf-eval:
	./scripts/verify-lf-eval.sh

# Compile the transaction corpus and diff ide-ledger output with tx-ledger.
verify-tx-ledger:
	./scripts/verify-tx-ledger.sh

verify-canton-hash:
	./scripts/verify-canton-hash.sh

verify-g0-provenance:
	./scripts/verify-g0-provenance.sh

# Verify Daml Ledger API & JSON API endpoints, authorization, and ACS
verify-ledger-api:
	./scripts/verify-ledger-api.sh

# Verify Canton native participant node, topology authorization, and ACS commitments
verify-participant:
	./scripts/verify-participant.sh

# Verify Canton Sequencer & Member Auth (Stage 09: Gate G6)
verify-sequencer:
	./scripts/verify-sequencer.sh

# Verify Canton Mediator Node Engine (Stage 10: Gate G7)
verify-mediator:
	./scripts/verify-mediator.sh

# Verify Canton BFT Consensus Ordering Engine (Stage 10: Gate G7)
verify-ordering:
	./scripts/verify-ordering.sh

# Combined Stage 10 Mediator & BFT Ordering Consensus Verification
verify-stage10: verify-mediator verify-ordering
	@echo "==> Stage 10 Mediator & BFT Ordering Consensus Verification Complete!"

# Verify Canton Multi-Synchronizer & Contract Reassignment (Stage 11)
verify-reassignment:
	./scripts/verify-reassignment-wire.sh
	./scripts/verify-rust-reassignment.sh
	RA_RUST_PARTICIPANT=1 ./scripts/verify-rust-reassignment.sh

verify-stage11: verify-reassignment

# Verify Splice Native Services & DAR Execution (Stage 12: Gate G8)
verify-splice:
	chmod +x ./scripts/verify-splice.sh
	./scripts/verify-splice.sh

verify-stage12: verify-splice

# Verify PostgreSQL Storage Engine, Flyway Compatibility & DB Takeover (Stage 13: Gate G9)
verify-db-takeover:
	chmod +x ./scripts/verify-db-takeover.sh
	./scripts/verify-db-takeover.sh

verify-stage13: verify-db-takeover

# Verify Rust CLI Ecosystem, DPM, Daml Script, Codegen & Console REPL (Stage 14: Gate G10)
verify-dev-tools:
	chmod +x ./scripts/verify-dev-tools.sh
	./scripts/verify-dev-tools.sh

verify-stage14: verify-dev-tools

# Verify Full Rust LocalNet & Unified Standalone Executable (Stage 15: Gate G11)
verify-localnet:
	chmod +x ./scripts/verify-localnet.sh
	./scripts/verify-localnet.sh

# The native audit of the product (Gate G11): libraries, process spawns, native code, roles served by the one executable. Fails while a role is not served.
audit-native:
	python3 scripts/audit-native.py

# The audit's own test: each check fails on a planted violation
audit-native-selftest:
	python3 scripts/audit-native.py --selftest

verify-stage15: verify-localnet

# Full Stage 11-15 Verification Pipeline
verify-all: verify-stage10 verify-stage11 verify-stage12 verify-stage13 verify-stage14 verify-stage15
	@echo "==> ALL STAGES (01..15) VERIFIED 100% PASS!"

# Clean up build artifacts
clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(TARGET_DIR)
	rm -rf $(CONTRACT_DIR)/.daml

# S-BASE-001: pinned external references (tests/oracle/provenance/references-manifest.tsv)
fetch-references:
	./scripts/fetch-references.sh

verify-references:
	./scripts/fetch-references.sh --check

verify-base:
	./scripts/verify-base.sh

# S-BASE-002: Canton 3.7.2 JVM oracle (boot three roles on PostgreSQL, compare with the tracked baseline)
oracle-verify:
	./scripts/oracle-up.sh

oracle-selftest:
	./scripts/oracle-up.sh --selftest

# S-PROTO-001: canton-proto crate generated from the vendored official 3.7.2 protos
verify-proto:
	./scripts/verify-proto.sh

vendor-protos:
	./scripts/vendor-protos.sh

# S-BASE-003: component-only Daml toolchain image (no SDK bundle; Canton 3.7.2 component)
build-toolchain:
	./scripts/build-toolchain.sh

verify-toolchain:
	./scripts/verify-toolchain.sh

# S-LF-001: inventory of the Scala Daml-LF tests in the pinned Canton 3.7.2 source
inventory-lf:
	python3 -I scripts/inventory-lf-tests.py

verify-lf-inventory:
	./scripts/verify-lf-inventory.sh

# S-LF-002: pure-expression differential, JVM 3.7.2 (daml script) vs Rust lf-eval. A mismatch is a finding
# recorded in tests/oracle/lf-diff/findings.tsv; the target fails only if that register or the corpus drifts.
verify-lf-diff:
	./scripts/verify-lf-diff.sh

verify-lf-diff-selftest:
	./scripts/verify-lf-diff.sh --selftest

# S-G0-002: 3.7.2 re-measurement of the mechanically readable G0 provenance facts
verify-g0-372:
	./scripts/verify-g0-372.sh

verify-console-dsl-372:
	./scripts/collect-console-dsl-372.sh

verify-damlc-license-372:
	./scripts/collect-damlc-license-372.sh

verify-scala-files-372:
	./scripts/collect-scala-files-372.py

verify-crypto-accept-372:
	./scripts/collect-crypto-accept-372.py

verify-wycheproof:
	./scripts/verify-wycheproof.sh

# S-DOC-001: the citations of the privacy note still exist in the pinned sources
verify-doc-anchors:
	./scripts/verify-doc-anchors.sh

# S-TX-001 (part 2): Splice choice-body execution, JVM 3.7.2 (daml script --ide-ledger) vs Rust
verify-splice-diff:
	./scripts/verify-splice-diff.sh

# S-LIC-001: the dual-license layout matches LICENSING.md
verify-licensing:
	./scripts/verify-licensing.sh

# S-TX-001 (part 3): which Daml-LF forms the Splice packages use and whether lf-eval evaluates them
verify-splice-census:
	cargo run -q -p lf-eval --bin splice-census -- tests/oracle/splice-dars/*.dar | diff - tests/oracle/splice-census/census.tsv

verify-key-diff:
	scripts/verify-key-diff.sh

verify-json-api:
	scripts/verify-json-api.sh

verify-lf-fatal:
	scripts/verify-lf-fatal.sh
