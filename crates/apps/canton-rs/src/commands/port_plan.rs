//! Single source-of-truth role offset table `δ` and fixed port planning for `localnet up --port-base` (`S-DX-002`).
//!
//! [CANTON-NOTE: INVARIANT] `PORT_OFFSETS` is the sole table used by runtime resolution, conflict
//! preflight (`D1`–`D3`), auto-window calculation `W`, and generated reference documentation.

use super::supervisor::doctor::plan::PortEntry;
use super::supervisor::doctor::shift_port;

/// Maximum synchronizers supported by fixed `--port-base` allocation (`s1`..`s10`, `m1`..`m10`).
pub const MAX_PORT_BASE_SYNCHRONIZERS: usize = 10;

/// Maximum participants supported by fixed `--port-base` allocation (`p1`..`p16`).
pub const MAX_PORT_BASE_PARTICIPANTS: usize = 16;

/// One immutable mapping row `ℓ -> δ(ℓ)` inside [`PORT_OFFSETS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortOffsetEntry {
    pub label: &'static str,
    pub offset: u16,
    pub role: &'static str,
}

/// Canonical injective offset table `δ` (`P-A2`).
///
/// Ranges:
/// - `0..99`: synchronizer `s{k}.public`, `s{k}.admin`, `m{k}.admin` (`10 * (k - 1) + {0, 1, 2}`)
/// - `100..115`: participants `p{1..16}.json`
/// - `200..201`: `scan.http`, `splice.http`
/// - `300`: `metrics`
pub const PORT_OFFSETS: &[PortOffsetEntry] = &[
    PortOffsetEntry {
        label: "s1.public",
        offset: 0,
        role: "Sequencer 1 Public API (gRPC)",
    },
    PortOffsetEntry {
        label: "s1.admin",
        offset: 1,
        role: "Sequencer 1 Admin API (gRPC)",
    },
    PortOffsetEntry {
        label: "m1.admin",
        offset: 2,
        role: "Mediator 1 Admin/Status (HTTP)",
    },
    PortOffsetEntry {
        label: "s2.public",
        offset: 10,
        role: "Sequencer 2 Public API (gRPC)",
    },
    PortOffsetEntry {
        label: "s2.admin",
        offset: 11,
        role: "Sequencer 2 Admin API (gRPC)",
    },
    PortOffsetEntry {
        label: "m2.admin",
        offset: 12,
        role: "Mediator 2 Admin/Status (HTTP)",
    },
    PortOffsetEntry {
        label: "s3.public",
        offset: 20,
        role: "Sequencer 3 Public API (gRPC)",
    },
    PortOffsetEntry {
        label: "s3.admin",
        offset: 21,
        role: "Sequencer 3 Admin API (gRPC)",
    },
    PortOffsetEntry {
        label: "m3.admin",
        offset: 22,
        role: "Mediator 3 Admin/Status (HTTP)",
    },
    PortOffsetEntry {
        label: "s4.public",
        offset: 30,
        role: "Sequencer 4 Public API (gRPC)",
    },
    PortOffsetEntry {
        label: "s4.admin",
        offset: 31,
        role: "Sequencer 4 Admin API (gRPC)",
    },
    PortOffsetEntry {
        label: "m4.admin",
        offset: 32,
        role: "Mediator 4 Admin/Status (HTTP)",
    },
    PortOffsetEntry {
        label: "s5.public",
        offset: 40,
        role: "Sequencer 5 Public API (gRPC)",
    },
    PortOffsetEntry {
        label: "s5.admin",
        offset: 41,
        role: "Sequencer 5 Admin API (gRPC)",
    },
    PortOffsetEntry {
        label: "m5.admin",
        offset: 42,
        role: "Mediator 5 Admin/Status (HTTP)",
    },
    PortOffsetEntry {
        label: "s6.public",
        offset: 50,
        role: "Sequencer 6 Public API (gRPC)",
    },
    PortOffsetEntry {
        label: "s6.admin",
        offset: 51,
        role: "Sequencer 6 Admin API (gRPC)",
    },
    PortOffsetEntry {
        label: "m6.admin",
        offset: 52,
        role: "Mediator 6 Admin/Status (HTTP)",
    },
    PortOffsetEntry {
        label: "s7.public",
        offset: 60,
        role: "Sequencer 7 Public API (gRPC)",
    },
    PortOffsetEntry {
        label: "s7.admin",
        offset: 61,
        role: "Sequencer 7 Admin API (gRPC)",
    },
    PortOffsetEntry {
        label: "m7.admin",
        offset: 62,
        role: "Mediator 7 Admin/Status (HTTP)",
    },
    PortOffsetEntry {
        label: "s8.public",
        offset: 70,
        role: "Sequencer 8 Public API (gRPC)",
    },
    PortOffsetEntry {
        label: "s8.admin",
        offset: 71,
        role: "Sequencer 8 Admin API (gRPC)",
    },
    PortOffsetEntry {
        label: "m8.admin",
        offset: 72,
        role: "Mediator 8 Admin/Status (HTTP)",
    },
    PortOffsetEntry {
        label: "s9.public",
        offset: 80,
        role: "Sequencer 9 Public API (gRPC)",
    },
    PortOffsetEntry {
        label: "s9.admin",
        offset: 81,
        role: "Sequencer 9 Admin API (gRPC)",
    },
    PortOffsetEntry {
        label: "m9.admin",
        offset: 82,
        role: "Mediator 9 Admin/Status (HTTP)",
    },
    PortOffsetEntry {
        label: "s10.public",
        offset: 90,
        role: "Sequencer 10 Public API (gRPC)",
    },
    PortOffsetEntry {
        label: "s10.admin",
        offset: 91,
        role: "Sequencer 10 Admin API (gRPC)",
    },
    PortOffsetEntry {
        label: "m10.admin",
        offset: 92,
        role: "Mediator 10 Admin/Status (HTTP)",
    },
    PortOffsetEntry {
        label: "p1.json",
        offset: 100,
        role: "Participant 1 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "p2.json",
        offset: 101,
        role: "Participant 2 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "p3.json",
        offset: 102,
        role: "Participant 3 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "p4.json",
        offset: 103,
        role: "Participant 4 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "p5.json",
        offset: 104,
        role: "Participant 5 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "p6.json",
        offset: 105,
        role: "Participant 6 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "p7.json",
        offset: 106,
        role: "Participant 7 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "p8.json",
        offset: 107,
        role: "Participant 8 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "p9.json",
        offset: 108,
        role: "Participant 9 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "p10.json",
        offset: 109,
        role: "Participant 10 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "p11.json",
        offset: 110,
        role: "Participant 11 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "p12.json",
        offset: 111,
        role: "Participant 12 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "p13.json",
        offset: 112,
        role: "Participant 13 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "p14.json",
        offset: 113,
        role: "Participant 14 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "p15.json",
        offset: 114,
        role: "Participant 15 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "p16.json",
        offset: 115,
        role: "Participant 16 JSON Ledger API (HTTP)",
    },
    PortOffsetEntry {
        label: "scan.http",
        offset: 200,
        role: "Scan app HTTP API",
    },
    PortOffsetEntry {
        label: "splice.http",
        offset: 201,
        role: "Splice apps HTTP API",
    },
    PortOffsetEntry {
        label: "metrics",
        offset: 300,
        role: "Supervisor Prometheus /metrics HTTP",
    },
];

/// Looks up `δ(label)` directly from [`PORT_OFFSETS`].
pub fn lookup_port_offset(label: &str) -> Option<u16> {
    PORT_OFFSETS
        .iter()
        .find(|entry| entry.label == label)
        .map(|entry| entry.offset)
}

/// Computes `W = round_up_1000(max(δ) + 1)` directly from [`PORT_OFFSETS`] (`S-DX-003`).
pub const fn port_window() -> u16 {
    let mut max_delta = 0u16;
    let mut i = 0usize;
    while i < PORT_OFFSETS.len() {
        if PORT_OFFSETS[i].offset > max_delta {
            max_delta = PORT_OFFSETS[i].offset;
        }
        i += 1;
    }
    let span = max_delta + 1;
    span.div_ceil(1000) * 1000
}

fn push_planned_entry(
    entries: &mut Vec<PortEntry>,
    base: u16,
    label: String,
    owner: String,
) -> Result<(), String> {
    let offset = lookup_port_offset(&label)
        .ok_or_else(|| format!("unknown fixed-port role label '{label}'"))?;
    entries.push(PortEntry {
        label,
        owner,
        base,
        offset,
        resolved: shift_port(base, offset),
    });
    Ok(())
}

/// Resolves all role ports needed by `localnet up --port-base <base>` for `D1`–`D3` preflight.
pub fn plan_localnet_ports(
    base: u16,
    synchronizers: usize,
    participants: usize,
    embedded_mediator: bool,
    no_scan: bool,
    no_splice: bool,
) -> Result<Vec<PortEntry>, String> {
    if synchronizers == 0 || synchronizers > MAX_PORT_BASE_SYNCHRONIZERS {
        return Err(format!(
            "--port-base supports 1..={MAX_PORT_BASE_SYNCHRONIZERS} synchronizers, got {synchronizers}"
        ));
    }
    if !(2..=MAX_PORT_BASE_PARTICIPANTS).contains(&participants) {
        return Err(format!(
            "--port-base supports 2..={MAX_PORT_BASE_PARTICIPANTS} participants, got {participants}"
        ));
    }

    let mut entries = Vec::new();
    for i in 1..=synchronizers {
        push_planned_entry(&mut entries, base, format!("s{i}.public"), format!("s{i}"))?;
        push_planned_entry(&mut entries, base, format!("s{i}.admin"), format!("s{i}"))?;
        if !embedded_mediator {
            push_planned_entry(&mut entries, base, format!("m{i}.admin"), format!("m{i}"))?;
        }
    }
    for i in 1..=participants {
        push_planned_entry(&mut entries, base, format!("p{i}.json"), format!("p{i}"))?;
    }
    if !no_scan {
        push_planned_entry(&mut entries, base, "scan.http".into(), "scan".into())?;
    }
    if !no_splice {
        push_planned_entry(&mut entries, base, "splice.http".into(), "splice".into())?;
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::super::supervisor::doctor::shift_port;
    use super::{lookup_port_offset, plan_localnet_ports, port_window, PORT_OFFSETS};

    fn resolve_port(base: u16, label: &str) -> Result<u16, String> {
        let delta = lookup_port_offset(label)
            .ok_or_else(|| format!("unknown fixed-port role label '{label}'"))?;
        shift_port(base, delta)
            .ok_or_else(|| format!("port overflow for {label} ({base} + {delta} > 65535)"))
    }

    fn render_port_offsets_markdown() -> String {
        let mut out = String::new();
        out.push_str(
            "<!-- Auto-generated from `PORT_OFFSETS` in `crates/apps/canton-rs/src/commands/port_plan.rs`. -->\n",
        );
        out.push_str(
            "<!-- Do not edit manually; verified by `port_offsets_doc_matches_const_table`. -->\n\n",
        );
        out.push_str("# 포트 오프셋표 (`δ`, S-DX-002)\n\n");
        out.push_str(&format!(
            "고정 포트 할당 `π_B(ℓ) = B + δ(ℓ)` (`checked_add`, `1024 <= π_B(ℓ) <= 65535`)의 단일 소스 표입니다.\n\
인스턴스 간 자동 포트 창 크기 `W = max(δ) + 1`의 1000 단위 올림값은 **`{}`**입니다.\n\n",
            port_window()
        ));
        out.push_str("| 역할 이름표 (`ℓ`) | 오프셋 (`δ`) | 역할 |\n");
        out.push_str("|---|---:|---|\n");
        for entry in PORT_OFFSETS {
            out.push_str(&format!(
                "| `{}` | `{}` | {} |\n",
                entry.label, entry.offset, entry.role
            ));
        }
        out
    }

    #[test]
    fn sdx002_p02_delta_injective_static() {
        for (i, lhs) in PORT_OFFSETS.iter().enumerate() {
            for (j, rhs) in PORT_OFFSETS.iter().enumerate().skip(i + 1) {
                assert_ne!(
                    lhs.label, rhs.label,
                    "duplicate label at indices {i} and {j}: {}",
                    lhs.label
                );
                assert_ne!(
                    lhs.offset, rhs.offset,
                    "duplicate offset {} between {} and {}",
                    lhs.offset, lhs.label, rhs.label
                );
            }
        }
    }

    #[test]
    fn port_offsets_doc_matches_const_table() {
        let doc_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../doc/devkit-feature-adoption/port-offsets.md");
        let on_disk = std::fs::read_to_string(&doc_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", doc_path.display()));
        assert_eq!(
            on_disk,
            render_port_offsets_markdown(),
            "doc/devkit-feature-adoption/port-offsets.md is out of sync with PORT_OFFSETS"
        );
    }

    #[test]
    fn resolve_port_checks_overflow_and_window() {
        assert_eq!(lookup_port_offset("s1.public"), Some(0));
        assert_eq!(lookup_port_offset("p1.json"), Some(100));
        assert_eq!(lookup_port_offset("metrics"), Some(300));
        assert_eq!(resolve_port(47_000, "p1.json"), Ok(47_100));
        assert!(resolve_port(65_500, "p1.json").is_err());
        assert!(resolve_port(47_000, "unknown.role").is_err());
        assert_eq!(port_window(), 1000);

        let entries = plan_localnet_ports(47_000, 1, 2, false, true, true)
            .expect("valid default 1-sync 2-participant plan");
        let resolved: Vec<(&str, Option<u16>)> = entries
            .iter()
            .map(|e| (e.label.as_str(), e.resolved))
            .collect();
        assert_eq!(
            resolved,
            vec![
                ("s1.public", Some(47_000)),
                ("s1.admin", Some(47_001)),
                ("m1.admin", Some(47_002)),
                ("p1.json", Some(47_100)),
                ("p2.json", Some(47_101)),
            ]
        );
    }
}
