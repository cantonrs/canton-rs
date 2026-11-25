use std::path::Path;

use super::super::topology::{render_enterprise_template_yaml, EnterpriseTemplateKind};
use super::super::{sanitize_argv, DaemonSpec};

/// Preset template kind for `canton-rs daemon init`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitTemplate {
    Default,
    Localnet,
    EnterpriseDvp,
    BftCluster,
    MultiDomain,
    OrgProduction,
}

/// Generates a starter `canton-daemon.yaml` file (`default`, `localnet`, or wrapped from `canton.conf`).
pub fn render_init_yaml(
    template: InitTemplate,
    from_canton_conf: Option<&Path>,
    bootstrap: Option<&Path>,
) -> String {
    if let Some(conf_path) = from_canton_conf {
        let boot = bootstrap
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "bootstrap.sc".to_string());
        let conf_disp = conf_path.display();
        return format!(
            r#"# Auto-generated Mode B wrapper for {conf_disp}
name: hub-beside
canton_conf: {conf_disp}
bootstrap: {boot}
state_dir: ./canton-rs-state
port_offset: 20000
same_identity: false
shadow_verify: false
metrics_port: 9464

services:
  splice-sv:
    role: splice
    ports: ["25020:http"]
    dar_dir: ./tests/oracle/splice-dars
    ledger_of: participant1
    automation_interval_ms: 1000
    restart: unless-stopped
"#
        );
    }

    match template {
        InitTemplate::Default => String::from(
            r#"# canton-daemon.yaml (Mode A: pure declarative cluster)
name: local-dev
synchronizer: dev-sync
state_dir: ./canton-rs-state
metrics_port: 9464

services:
  sequencer1:
    role: sequencer
    ports: ["5018:public", "5019:metrics"]
    restart: unless-stopped

  mediator1:
    role: mediator
    ports: ["5017:admin"]
    depends_on: [sequencer1]
    restart: unless-stopped

  participant1:
    role: participant
    ports: ["7575:json-api", "7576:admin"]
    dars: ["./contracts/target/sample-contract.dar"]
    depends_on: [sequencer1, mediator1]
    restart: unless-stopped
"#,
        ),
        InitTemplate::Localnet => String::from(
            r#"# canton-daemon.yaml (LocalNet persistent dev topology)
name: localnet-dev
synchronizer: localnet-sync
state_dir: ./canton-rs-state
metrics_port: 9464

services:
  sequencer1:
    role: sequencer
    ports: ["5018:public", "5019:metrics"]
    restart: unless-stopped

  mediator1:
    role: mediator
    ports: ["5017:admin"]
    depends_on: [sequencer1]
    restart: unless-stopped

  participant1:
    role: participant
    ports: ["7575:json-api", "7576:admin"]
    dars: ["./contracts/target/sample-contract.dar"]
    depends_on: [sequencer1, mediator1]
    restart: unless-stopped

  participant2:
    role: participant
    ports: ["7585:json-api", "7586:admin"]
    dars: ["./contracts/target/sample-contract.dar"]
    depends_on: [sequencer1, mediator1]
    restart: unless-stopped

  scan1:
    role: scan
    ports: ["5012:http"]
    dars: ["./contracts/target/sample-contract.dar"]
    depends_on: [participant1]
    restart: unless-stopped

  splice-app:
    role: splice
    ports: ["5020:http"]
    dar_dir: ./tests/oracle/splice-dars
    ledger_of: participant1
    automation_interval_ms: 1000
    depends_on: [participant1]
    restart: unless-stopped
"#,
        ),
        InitTemplate::EnterpriseDvp => {
            render_enterprise_template_yaml(EnterpriseTemplateKind::EnterpriseDvp)
        }
        InitTemplate::BftCluster => {
            render_enterprise_template_yaml(EnterpriseTemplateKind::BftCluster)
        }
        InitTemplate::MultiDomain => {
            render_enterprise_template_yaml(EnterpriseTemplateKind::MultiDomain)
        }
        InitTemplate::OrgProduction => {
            render_enterprise_template_yaml(EnterpriseTemplateKind::OrgProduction)
        }
    }
}

/// Formats a normalized `DaemonSpec` for `canton-rs daemon config` with all credentials masked.
pub fn format_masked_config_summary(spec: &DaemonSpec) -> String {
    let mut lines = vec![
        format!("Stack        : {}", spec.name),
        format!("Synchronizer : {}", spec.synchronizer),
        format!("State Dir    : {}", spec.state_dir.display()),
        format!(
            "Metrics      : {}",
            spec.metrics_port.map_or_else(
                || "disabled".into(),
                |p| format!("{}:{p}", spec.metrics_bind)
            )
        ),
        format!("Logging      : {}", spec.logging.summary()),
        format!(
            "X-Ray / Verify: xray={}, trace_rate_limit={}/s, shadow_verify={}",
            spec.xray, spec.trace_rate_limit_per_sec, spec.shadow_verify
        ),
    ];
    if !spec.cells.is_empty() {
        let cell_summary: Vec<String> = spec
            .cells
            .values()
            .map(|c| format!("{}({})", c.name, c.isolation.as_str()))
            .collect();
        lines.push(format!("Cells        : {}", cell_summary.join(", ")));
    }
    if !spec.scenarios.is_empty() {
        let sc_names: Vec<&str> = spec.scenarios.iter().map(|s| s.name.as_str()).collect();
        lines.push(format!("Scenarios    : {}", sc_names.join(", ")));
    }
    lines.push("Services (permanent slot order):".to_string());
    for svc in &spec.services {
        let grp_tag = svc
            .group
            .as_deref()
            .map(|g| format!(" group={g:<14}"))
            .unwrap_or_default();
        lines.push(format!(
            "  [{}] {:<14} role={:<11}{} restart={:<14} ports=[{}] storage={} argv={}",
            svc.slot_id,
            svc.name,
            svc.role.as_str(),
            grp_tag,
            svc.restart.as_str(),
            svc.ports.summary(),
            svc.storage.masked_summary(),
            sanitize_argv(&svc.argv).join(" ")
        ));
    }
    lines.join("\n")
}
