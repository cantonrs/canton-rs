<div align="center">

# canton-rs

**Single-binary, zero-JVM Rust runtime for Canton & Splice.**  
Participant · Sequencer · Mediator · LocalNet DX · PQS · Console

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE-APACHE)
[![Release](https://img.shields.io/badge/release-v0.8.0-D95A2B.svg)](https://github.com/cantonrs/canton-rs/releases)
[![Docs](https://img.shields.io/badge/docs-doc.getcantonrs.dev-2B6CB0.svg)](https://doc.getcantonrs.dev)
[![Book](https://img.shields.io/badge/book-Learn%20You%20Some%20Canton-2F855A.svg)](https://learnyousomecanton.com)

[Website](https://getcantonrs.dev) · [Documentation](https://doc.getcantonrs.dev) · [Free 34-Chapter Book](https://learnyousomecanton.com) · [X (@getcantonrs)](https://x.com/getcantonrs)

</div>

---

`canton-rs` replaces multi-container JVM LocalNet stacks with **one native Rust executable**. Run unmodified Daml `.dar` archives, speak standard Ledger API v2 (gRPC & HTTP JSON), manage multi-node clusters with a declarative supervisor, and attach an interactive Canton console—with zero JVM heap overhead.

## Quick Install

### macOS & Linux (`install.sh`)
```sh
curl -fsSL https://getcantonrs.dev/install.sh | sh
```

### Homebrew (macOS & Linux)
```sh
brew install cantonrs/tap/canton-rs
```

### Verify
```sh
canton-rs --version
# canton-rs 0.8.0

canton-rs localnet audit
```

> Pin a specific release with `CANTON_RS_VERSION=v0.8.0 curl -fsSL https://getcantonrs.dev/install.sh | sh`. Prebuilt binaries and `SHA256SUMS` are published on [GitHub Releases](https://github.com/cantonrs/canton-rs/releases).
> `canton-rs` is an independent Rust implementation oracle-tested against the Canton `3.7.2` (PV `36`–`37`) & Splice `0.10.1` protocol baselines.

---

## 60-Second Quick Start

Run from a directory containing your `.dar` file (or clone this repo to use the bundled `contracts/target/sample-contract.dar`):

```sh
# 1. Generate a starter declarative cluster manifest (Sequencer + Mediator + Participant)
canton-rs daemon init -o canton-daemon.yaml

# 2. Check ports, disk, and DAR readiness (read-only)
canton-rs daemon doctor -f canton-daemon.yaml --name dev

# 3. Boot the local cluster in the background (pass --dar ./your-app.dar if outside this repo)
canton-rs daemon up -f canton-daemon.yaml -d --name dev

# 4. Inspect running nodes and export Ledger API / Admin URLs
canton-rs daemon ps --name dev
eval "$(canton-rs daemon env --name dev)"

# 5. Stop and clean up temporary state when done
canton-rs daemon down --name dev --clean-files
```

Other handy day-to-day commands included in `v0.8.0`:
```sh
# Inspect or diff Daml DAR packages & upgrade compatibility
canton-rs dar inspect contracts/target/sample-contract.dar

# Attach an Erlang-style Canton Console REPL over daemon.sock
canton-rs console attach

# Save & restore local cluster state snapshots
canton-rs daemon snapshot save --name dev --out dev.snap
```

---

## Why `canton-rs`?

- **One Binary, Every Role**: Participant, Sequencer (Database & BFT), Mediator, Ledger JSON/gRPC API, Splice services, `pqs` projection, `dpm`, and `script` runner in a single native executable.
- **Unmodified DARs & Standard APIs**: Loads `.dar` packages built with official `damlc` without recompilation and serves standard Ledger API v2.
- **Fast LocalNet DX**: Named multi-instance isolation (`--name`, `--port-offset`), read-only `daemon doctor` (`D1`–`D10`), instant `daemon snapshot` / `restore`, `dar inspect` / `diff` / `check-upgrade`, `canton-rs token` (CIP-0112), `--dev-auth` / `daemon creds`, and `canton-rs console attach`.
- **Brownfield-Safe Evaluation**: Run read-only beside an existing JVM Canton hub using `--port-offset --same-identity --state-in-files` without disrupting production traffic.

---

## Oracle Verification Scope

Correctness is verified against official Canton `3.7.2`, Daml `3.7`, Splice `0.10.1`, Wallet SDK `1.7.0`, and Scribe `3.5.8` oracles—not self-consistent mocks:

| Verification Surface | Oracle Result |
|---|---|
| Ledger JSON API v2 | **382 / 382** differential cases (`0` diffs vs official Canton 3.7.2) |
| Splice 0.10.1 Core DARs | **1,168** scenarios across 4 unmodified DARs (`0` findings) |
| Wallet SDK 1.7.0 | **0** compatibility gaps |
| Scribe 3.5.8 (`GetUpdates` gRPC) | Verified against official Scribe |
| Mixed BFT Consensus | Interoperability verified with official Scala BFT cluster |
| Rust Safety Discipline | `cargo clippy --workspace --all-targets -- -D warnings` (0 warnings), zero production `.unwrap()` |

> **Current Scope (`v0.8.0` Pre-1.0)**: `canton-rs v0.8.0` is intended for LocalNet development, CI testing, and brownfield evaluation. Transaction simulation (`simulate`) and parallel `canton-rs test` are scheduled for an upcoming `0.8.x` / `0.9.0` release.

---

## Protocol Compatibility Target (Oracle-Tested Against)

| Component | Compatibility Target |
|---|---|
| Canton Protocol | `3.7.2` (Protocol Versions `36`–`37`) |
| Daml-LF | `2.3` default (`2.1`–`2.4` stable) |
| Splice | `0.10.1` |
| PostgreSQL | `16` |

---

## Build from Source

Requires Rust `1.85+` (tested on `1.98.1`):

```sh
git clone https://github.com/cantonrs/canton-rs.git
cd canton-rs
cargo build --release --locked -p canton-rs
./target/release/canton-rs --version
```

---

## Ecosystem & Contact

- **Website**: https://getcantonrs.dev
- **Documentation (EN / KO)**: https://doc.getcantonrs.dev
- **Companion Book (EN / KO)**: https://learnyousomecanton.com
- **X (Twitter)**: https://x.com/getcantonrs
- **Contact / Security**: `hello@getcantonrs.dev` (see [SECURITY.md](SECURITY.md))

---

## License & Notice

Licensed under the [Apache License, Version 2.0](LICENSE-APACHE). See [LICENSING.md](LICENSING.md) and [NOTICE](NOTICE) for provenance details.

`canton-rs` is an independent open-source project and is not affiliated with, endorsed by, or sponsored by Digital Asset (Switzerland) GmbH. Canton and Daml are trademarks of their respective owners.
