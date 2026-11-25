# Docker Environment for `canton-rs`

This directory provides a Docker Compose environment to build and run the pure-Rust Canton LocalNet, Ledger HTTP JSON API, PostgreSQL database, and official Daml DAR builder without requiring a local JVM.

---

## 1. Architecture Overview

The Docker stack consists of four services:

```text
+--------------------------------------------------------------------------+
|                          canton-network (bridge)                         |
|                                                                          |
|  +--------------------+         +-------------------------------------+  |
|  |     canton-db      | <------ |           canton-localnet           |  |
|  |   (Postgres 16)    |         | (canton-rs: 1s + 1m + 2p in process)|  |
|  |     Port: 5432     |         | Ports: 5011, 5021, 5018, 5019       |  |
|  +--------------------+         +-------------------------------------+  |
|                                                    ^                     |
|                                                    |                     |
|                                 +-------------------------------------+  |
|                                 |          ledger-json-api            |  |
|                                 |       (HTTP /v1/*, /v2/*)           |  |
|                                 |            Port: 7575               |  |
|                                 +-------------------------------------+  |
|                                                                          |
|  +--------------------+                                                  |
|  |    daml-builder    | (Profile: builder)                               |
|  | (Daml SDK 3.7.1)   | -> Compiles ./contracts to *.dar                 |
|  +--------------------+                                                  |
+--------------------------------------------------------------------------+
```

1. **`canton-db`** (`postgres:16-alpine`):
   - PostgreSQL 16 database for Canton Flyway migrations and persistent state.
   - Port: `5432`
2. **`canton-localnet`** (`docker/Dockerfile.canton-rs`):
   - Four-node in-process cluster powered by the single `canton-rs` binary (1 Sequencer + 1 Mediator + 2 Participants).
   - Lightweight Debian Slim container with zero JVM runtime.
   - Ports: `5011` (Participant 1), `5021` (Participant 2), `5018` (Sequencer), `5019` (Mediator).
3. **`ledger-json-api`** (`docker/Dockerfile.canton-rs`):
   - Daml HTTP JSON API server (`/v1/*`, `/v2/*`).
   - Port: `7575`
4. **`daml-builder`** (`docker/Dockerfile`):
   - Official Daml 3.7.1 SDK container for compiling `contracts/` into `.dar` archives.

---

## 2. Quick Start

### 2.1 Build Images
```bash
# Using the helper script
./scripts/docker-run.sh build

# Or via Make
make docker-build
```

### 2.2 Start the Cluster (LocalNet + Postgres + JSON API)
```bash
./scripts/docker-run.sh up

# Check status and logs
./scripts/docker-run.sh ps
./scripts/docker-run.sh logs
```

### 2.3 Stop and Clean Up
```bash
# Stop containers
./scripts/docker-run.sh down

# Stop containers and remove volumes
./scripts/docker-run.sh clean
```

---

## 3. Compiling Daml Contracts & Inspecting DARs

You can compile and inspect DARs inside containers without installing Java or the Daml SDK on the host:

```bash
# Compile Daml smart contracts (outputs contracts/target/sample-contract.dar)
./scripts/docker-run.sh build-dar

# Inspect the generated DAR using the Rust parser container
./scripts/docker-run.sh inspect-dar contracts/target/sample-contract.dar
```

---

## 4. Ports & Endpoints

| Service | Container Port | Host Binding | Description |
|---|---|---|---|
| `canton-localnet` | `5011` | `localhost:5011` | Participant 1 Ledger API |
| `canton-localnet` | `5021` | `localhost:5021` | Participant 2 Ledger API |
| `canton-localnet` | `5018` | `localhost:5018` | Sequencer Protocol Port |
| `canton-localnet` | `5019` | `localhost:5019` | Mediator Protocol Port |
| `ledger-json-api` | `7575` | `localhost:7575` | Daml Ledger HTTP JSON API |
| `canton-db` | `5432` | `localhost:5432` | PostgreSQL DB |

---

## 5. Host Requirements

Running live containers and official SDK builds requires a host environment with a working Docker daemon (macOS, Linux, or Windows WSL2). Restricted sandboxed VMs without `unshare` or `/dev/kvm` cannot start the Docker daemon.
