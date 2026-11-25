# Licensing

This repository is licensed as a whole under the Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE)). See [`NOTICE`](NOTICE) for attribution notices.

## Policy

1. **Single repository-wide license (`Apache-2.0`)**: All Rust crates, scripts, documentation, and test fixtures in this repository are licensed under the Apache License, Version 2.0. Every workspace crate declares `license = "Apache-2.0"` in its `Cargo.toml`.
2. **Apache-2.0 Section 4 compliance**: Distributions must retain a copy of [`LICENSE-APACHE`](LICENSE-APACHE), [`NOTICE`](NOTICE), and all copyright, patent, trademark, and attribution notices, and mark modified files where applicable.
3. **Upstream attribution**: Files copied or derived from Digital Asset's Apache-2.0 repositories (Canton, Daml, Splice) carry explicit provenance records in the table below, in `doc/traceability/scala-rust-map.md`, and in source comments.
4. **Third-party crates & trademarks**: External crate dependencies and bundled third-party artifacts retain their respective licenses. Trademarks (including Canton and Daml) are not granted by this license.

## Separately Sourced Paths

| Path | Provenance |
|---|---|
| `crates/protocol/canton-proto/` | Contains 151 verbatim official Canton 3.7.2 `.proto` definitions (`proto/SOURCES.tsv`) and generated Rust bindings. `proto/LICENSE.txt` retains the upstream Apache-2.0 notice. |
| `crates/core/canton-participant/migrations/` | Embeds 28 verbatim PostgreSQL stable migration SQL files from the official Canton 3.7.2 JAR (`SOURCES.tsv`). `LICENSE.txt` retains the upstream Apache-2.0 notice. |
| `tests/oracle/lf-vectors/` | Expression test vectors and expected values extracted from Canton Scala tests (with `file:line` provenance). |
| `tests/oracle/lf-diff/` | Differential test cases whose `origin` column in `cases.tsv` references upstream Canton Scala test `file:line` locations. |
| `tests/oracle/canton-hash/` | `HashPurpose` table extracted from `HashPurpose.scala` via `scripts/verify-canton-hash.sh`. |
| `tests/oracle/splice-dars/` | DAR artifacts built from Splice 0.10.1 and associated measurement tables. |
| `tests/oracle/provenance/` | Factual measurement records derived from Canton, Daml, and Splice artifacts (JAR license inventories, SQL hashes, etc.). |

`references/` (locally downloaded upstream sources and JARs) is gitignored and is not part of this repository.

## Open Items

- **Copyright holder**: `"canton-rs contributors"` in [`NOTICE`](NOTICE) is a placeholder to be finalized with the official copyright holder before GA distribution.
- **Per-file SPDX headers**: Omitted across the tree because the entire repository uses a single license (`Apache-2.0`).
- **Disclaimer**: This document is not legal advice. Seek legal review prior to commercial distribution.

Verification: `make verify-licensing` ([`scripts/verify-licensing.sh`](scripts/verify-licensing.sh)).
