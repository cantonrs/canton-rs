//! Side-effect-free preflight diagnostics (`canton-rs daemon doctor`) and `daemon up` gate (`S-DX-001`).

pub mod checks;
pub mod plan;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::super::exit_code::{EXIT_OK, EXIT_PREFLIGHT};
pub use checks::DoctorHost;
pub use plan::{resolve_doctor_plan, shift_port, DoctorPlan};

/// Schema identifier emitted by `canton-rs daemon doctor --format json`.
pub const DOCTOR_JSON_SCHEMA: &str = "canton-rs.doctor/1";

/// Outcome status of one preflight check `D1..D10`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
    Running,
}

impl CheckStatus {
    /// Human-readable label matching text output columns.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Running => "running",
        }
    }
}

/// Structured result of one check row `(id, status, message, fix)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub id: String,
    pub status: CheckStatus,
    pub message: String,
    pub fix: Option<String>,
}

/// Canonical preflight report shared identically between JSON and text renderers (`D-A4`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub schema: String,
    pub exit_code: i32,
    pub ports: BTreeMap<String, Option<u16>>,
    pub checks: Vec<DoctorCheck>,
}

/// Monotone exit-code function over `D1..D10` results (`D-A2`, `A4`).
pub fn compute_exit_code(checks: &[DoctorCheck]) -> i32 {
    if checks.iter().any(|c| c.status == CheckStatus::Fail) {
        EXIT_PREFLIGHT
    } else {
        EXIT_OK
    }
}

/// Executes all `D1..D10` checks against `plan` and `host` and computes `exit_code`.
pub fn run_doctor(plan: &DoctorPlan, host: &DoctorHost) -> DoctorReport {
    let checks = checks::run_all_checks(plan, host);
    let exit_code = compute_exit_code(&checks);
    let mut ports = BTreeMap::new();
    for entry in &plan.ports {
        ports.insert(entry.label.clone(), entry.resolved);
    }
    DoctorReport {
        schema: DOCTOR_JSON_SCHEMA.to_string(),
        exit_code,
        ports,
        checks,
    }
}

/// Renders deterministic JSON output (`BTreeMap`-ordered keys, roundtrippable into [`DoctorReport`]).
pub fn render_json(report: &DoctorReport) -> Result<String, String> {
    serde_json::to_string_pretty(report).map_err(|e| e.to_string())
}

/// Renders human-readable text output from the exact same [`DoctorReport`] value (`D-A4`).
pub fn render_text(report: &DoctorReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "canton-rs daemon doctor (schema={}, exit={})\n",
        report.schema, report.exit_code
    ));
    for c in &report.checks {
        out.push_str(&format!(
            "[{:<3}] {:<7} {}\n",
            c.id,
            c.status.as_str(),
            c.message
        ));
        if let Some(fix) = &c.fix {
            out.push_str(&format!("      fix: {fix}\n"));
        }
    }
    out
}
