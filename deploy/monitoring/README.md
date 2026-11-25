# `canton-rs` Prometheus + Grafana Monitoring Stack (`deploy/monitoring`)

This directory provides a turnkey **Prometheus + Grafana** observability kit that scrapes the OpenMetrics endpoint exposed by `canton-rs daemon` (`GET :9464/metrics`, 26 metric families with institutional cell `group` labels) for real-time dashboards and alerting.

---

## 1. Architecture & Default Ports

Default ports are chosen to avoid conflicts with common local services (`3000`, `3080`, `3901`, `6432`, `6501`, `6502`) and can be overridden via `.env`.

```text
┌──────────────────────────────────────────────────────────┐
│ Host (macOS / Linux) Native Runtime                      │
│   canton-rs daemon up -f examples/case1-dvp-multicell.yaml│
│   (metrics_bind: 127.0.0.1, metrics_port: 9464)          │
└───────────────────────────┬──────────────────────────────┘
                            │ HTTP GET /metrics (2s scrape interval)
                            ▼
┌──────────────────────────────────────────────────────────┐
│ Docker Compose (deploy/monitoring/docker-compose.yml)    │
│  1) Prometheus (:9095 -> 9090) + 6 production alert rules│
│  2) Grafana    (:3300 -> 3000) + 2 provisioned dashboards│
└──────────────────────────────────────────────────────────┘
```

| Component | Default Local URL | Notes |
| :--- | :--- | :--- |
| **Grafana Overview Dashboard** | `http://127.0.0.1:3300/d/canton-rs-overview` | Requires admin password configured in `.env` (anonymous access disabled) |
| **Grafana BFT & Shadow Board** | `http://127.0.0.1:3300/d/canton-rs-bft-shadow` | BFT quorum peers, 2PC approve/reject counts, `--shadow-verify` parity |
| **Prometheus Targets & Alerts** | `http://127.0.0.1:9095/targets` · `/alerts` | Scrape health and 6 production alert rules |
| **`canton-rs` Raw Exporter** | `http://127.0.0.1:9464/metrics` · `/snapshot` | Supervisor OpenMetrics text and JSON snapshot |

> **Security Defaults (`metrics_bind: 127.0.0.1`, Auth Required, Lifecycle Disabled)**: All four manifests in `examples/` and this Compose stack bind to loopback (`127.0.0.1`) by default, with Grafana anonymous access and Prometheus web lifecycle (`--web.enable-lifecycle`) disabled. Copy `.env.example` to `.env` and set `GRAFANA_ADMIN_PASSWORD` before starting. Only enable `metrics_bind: 0.0.0.0` (or `--metrics-bind 0.0.0.0`) inside trusted/firewalled bridge networks where the Prometheus container reaches the host via `host.docker.internal`.

---

## 2. One-Command Demo & Chaos Traffic Test

From the repository root, the following commands start **Prometheus + Grafana**, boot the 6-node Treasury DvP cluster, verify sub-transaction privacy, and inject commit traffic:

```bash
# 1. Start the full stack and run initial transactions (default: Case 1, 6-node DvP)
bash deploy/monitoring/run-demo.sh up dvp

# 2. Open http://127.0.0.1:3300/d/canton-rs-overview in your browser

# 3. Inject additional traffic + 4s @bank-c fault/recovery chaos test
bash deploy/monitoring/run-demo.sh traffic dvp

# 4. Tear down containers and clean temporary state
bash deploy/monitoring/run-demo.sh down dvp
```

You can also run the 4-node BFT cluster (`case2`) or multi-domain bridge (`case3`):

```bash
bash deploy/monitoring/run-demo.sh up bft
bash deploy/monitoring/run-demo.sh traffic bft
bash deploy/monitoring/run-demo.sh down bft
```

---

## 3. Included Enterprise Monitoring Scenarios (`examples/` & `prometheus/`)

1. **`examples/case1-dvp-multicell.yaml` (Multi-Party DvP & Privacy Isolation)**
   - Compares per-cell stacked RSS memory across 5 isolated cells (`sync-core`, `bank-a`, `sec-b`, `bank-c`, `fss-audit`) and verifies active contract isolation (`p-bank-a > 0` vs non-stakeholder `p-bank-c == 0`).
2. **`examples/case2-bft-chaos.yaml` (4-Node BFT Consensus & Quorum Chaos)**
   - Stops `@bft-spare` among `seq-bft-1..4` and visualizes uninterrupted ledger progression under the remaining `3/4` BFT quorum.
3. **`examples/case3-multidomain-bridge.yaml` + `prometheus/prometheus-federation.yml` (Multi-Domain / Multi-AZ Federation)**
   - Aggregates `:9464/metrics` from distributed `canton-rs daemon` instances (`az-seoul-1`, `vpc-bank-a`, `vpc-sec-b`) into a central Prometheus instance.
4. **`examples/case4-org-production-shadow.yaml` + `prometheus/prometheus-hybrid-shadow.yml` (Single-Org Production & JVM Shadow Verification)**
   - Runs alongside an existing Scala JVM hub with `--shadow-verify`, tracking `canton_rs_shadow_verified_tx_total` and alerting on any non-zero `canton_rs_shadow_mismatch_total`.

---

## 4. Provisioned Dashboards & Alert Rules

### Dashboard 1: `Canton-RS Cluster, Cell Footprint & Privacy Overview` (`canton-rs-overview.json`)
- Template variables: `$synchronizer` (synchronizer domain), `$group` (multi-select institutional cell: `bank-a`, `sec-b`, `sync-core`, etc.)
- **6 KPI Cards**: Online nodes, total cluster RSS memory, synchronizer Ping RTT (ms), latest ledger offset, total active contracts (ACS), cumulative mediator 2PC approvals
- **6 Time-Series Panels**:
  1. Node liveness and chaos fault timeline (`canton_rs_node_up`)
  2. Stacked physical memory by institutional cell (`sum by (group) (canton_rs_node_memory_rss_bytes)`)
  3. Per-node CPU usage (`%`)
  4. Active contract counts by party (`canton_rs_acs_active_contracts`)
  5. Participant ledger offset & sequencer head progression
  6. Ledger JSON/gRPC API latency quantiles (`p50` / `p95` / `p99`)

### Dashboard 2: `Canton-RS BFT Consensus, 2PC Mediator & Shadow Verify` (`canton-rs-consensus-and-shadow.json`)
- Tracks BFT quorum peers (`canton_rs_bft_quorum_peers`), connected members, mediator approve/reject/pending quorums, `--shadow-verify` match/mismatch counters, file descriptors (FDs), restart counts, and X-Ray backpressure drops.

### 6 Prometheus Production Alert Rules (`prometheus/alerts.yml`)
- `CantonRsNodeDown` (node, DB, or sequencer session unhealthy for >15s)
- `CantonRsFrequentRestarts` (2+ abnormal restarts within 5 minutes)
- `CantonRsApiP99LatencyHigh` (API `p99` latency > `500ms`)
- `CantonRsMediatorRejectionDetected` (2PC rejection verdict observed)
- `CantonRsBftQuorumDegraded` (BFT quorum connected peers < 3)
- `CantonRsShadowVerifyMismatch` (shadow verification mismatch detected)

---

## 5. Multi-Instance Auto-Discovery (`--observability`, `file_sd_targets`, Official Metric Aliases)

When starting named instances with `canton-rs daemon up --name <name> --observability`, `canton-rs` automatically registers a Prometheus `file_sd_configs` JSON target under the registry `file_sd_targets` directory and cleans it up on `daemon remove --name <name>`.

- **Lightweight Provisioned Dashboard**: [`examples/grafana/canton-rs.json`](../../examples/grafana/canton-rs.json) (`uid: canton-rs-dx-010`, 5s refresh) visualizes API p99 latency, ledger end offset, ACS count, pending mediator quorums, BFT connected peers, and node RSS bytes.
- **Official Canton 3.7.2 Metric Aliases**: The following 3 verified 1:1 aliases are emitted alongside `canton_rs_*` metrics on `/metrics` (the remaining 25 `canton_rs_*` metrics are emitted as native metrics):
  - `canton_rs_mediator_pending_quorums` ↔ `daml_mediator_outstanding_requests`
  - `canton_rs_bft_quorum_peers` ↔ `daml_sequencer_bftordering_p2p_connections_connected`
  - `canton_rs_bft_configured_peers` ↔ `daml_sequencer_bftordering_topology_validators`
