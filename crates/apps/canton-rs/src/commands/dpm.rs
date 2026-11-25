//! DAR inspection and small code generation (`canton-rs dpm`).
//!
//! [CANTON-NOTE: LIMITATION] This is a set of DAR utilities, not a reimplementation of the official `dpm`: the Daml package manager
//! (component install, cache, lock files, argv/env/config precedence) is out of scope for this product (decision of 2026-11-14), so
//! nothing here claims command, option or exit-code parity with `dpm` or `daml`. No node role depends on it.
//! - `inspect-dar <DAR>` (`--json`, `--summary`, `--verbose`): package ids, LF version, module surfaces.
//! - `validate-dar <DAR>`: ZIP boundaries, manifest, SHA-256 package hashes, LF 2.1-2.4 gate, template/choice surface integrity.
//! - `packages upload <DAR>` / `packages list <DAR>`: DAR package management.
//! - `codegen <DAR> --lang <rust|json>`: Rust bindings of every serializable type, template, choice and interface (`lf_eval::codegen`, checked against the official `codegen-js`/`codegen-java`), or the JSON schema of the template surfaces.
//! - `version`: SDK and Canton Rust compatibility lock information.

use std::path::Path;

use clap::{Args, Subcommand};

use super::dpm_mcp::{execute_mcp_server, McpDarArgs};
use super::dpm_tui::{execute_dpm_tui, DpmTuiArgs};
use super::dpm_vision::{
    check_dar_like_upload, execute_audit_pack, execute_fuzz_dar, AuditPackArgs, FuzzDarArgs,
};

#[derive(Args, Debug)]
pub struct DpmArgs {
    #[command(subcommand)]
    pub action: DpmAction,
}

#[derive(Subcommand, Debug)]
pub enum DpmAction {
    /// Display `canton-rs` SDK version and supported Daml-LF build info.
    Version,
    /// Inspect a compiled DAR archive's packages, LF version, and module surfaces.
    InspectDar(InspectDarArgs),
    /// Validate a compiled DAR archive's package hashes, ZIP bounds, LF 2.1-2.4 gate, and template surfaces.
    ValidateDar(ValidateDarArgs),
    /// Generate typed Rust bindings or JSON template schemas from a DAR archive.
    Codegen(CodegenArgs),
    /// Dynamic runtime DAR package upload and listing (`dpm packages`).
    Packages(PackagesArgs),
    /// Create or offline-verify a Selective Audit Capsule (`.audit-pack`) with Blinded Merkle proof & Sequencer Ed25519 signature.
    AuditPack(AuditPackArgs),
    /// Run deterministic multi-party authorization & Stakeholder-isolation fuzzing against a `.dar` archive.
    Fuzz(FuzzDarArgs),
    /// Start the stdio JSON-RPC 2.0 Model Context Protocol (MCP) server for AI coding agent `.dar` verification.
    Mcp(McpDarArgs),
    /// Launch the interactive theme-safe `ratatui` DAR Surface, Privacy Audit & Live Fuzzer TUI (`dpm top`).
    #[command(visible_alias = "top")]
    Tui(DpmTuiArgs),
}

#[derive(Args, Debug)]
pub struct InspectDarArgs {
    /// Path to the `.dar` archive file.
    pub dar_path: String,

    /// Emit machine-readable JSON output (`--json`).
    #[arg(short, long, default_value_t = false)]
    pub json: bool,

    /// Emit single-line summary.
    #[arg(short, long, default_value_t = false)]
    pub summary: bool,
}

#[derive(Args, Debug)]
pub struct ValidateDarArgs {
    /// Path to the `.dar` archive file to validate.
    pub dar_path: String,
}

#[derive(Args, Debug)]
pub struct CodegenArgs {
    /// Path to the `.dar` archive file.
    pub dar_path: String,

    /// Target language for code generation (`rust` or `json`).
    #[arg(long, default_value = "rust")]
    pub lang: String,
}

#[derive(Args, Debug)]
pub struct PackagesArgs {
    /// Path to the `.dar` archive file to upload/register.
    #[arg(long, default_value = "contracts/target/sample-contract.dar")]
    pub dar: String,
}

pub fn execute_dpm(args: DpmArgs) -> Result<(), String> {
    match args.action {
        DpmAction::Version => {
            println!("Daml toolchain lock:               DPM 1.1.1, damlc 3.7.0, daml-script 3.7.0 (no SDK 3.7.2 exists)");
            println!("Canton Protocol Target:            3.7.2 (protocol versions 36, 37)");
            println!("Daml-LF Supported Versions:        2.1, 2.2, 2.3, 2.4");
            println!(
                "Runtime Engine:                    canton-rs {} (Pure Rust Zero-JVM)",
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        DpmAction::InspectDar(i_args) => {
            let archive = lf_archive::parse_dar_file(Path::new(&i_args.dar_path))
                .map_err(|e| format!("Error inspecting DAR '{}': {e}", i_args.dar_path))?;

            let pkg_name = archive
                .package_name
                .clone()
                .or_else(|| archive.manifest_name.clone())
                .unwrap_or_else(|| "unknown-package".to_string());
            let pkg_ver = archive
                .package_version
                .clone()
                .or_else(|| archive.manifest_version.clone())
                .unwrap_or_else(|| "0.0.0".to_string());

            if i_args.summary {
                let dep_count = archive.dalfs.len().saturating_sub(1);
                println!(
                    "Package: {}-{} | ID: {} | LF: {} | Modules: [{}] | DALFs: {} ({} deps)",
                    pkg_name,
                    pkg_ver,
                    archive.main_package_id,
                    archive.lf_version,
                    archive.modules.join(", "),
                    archive.dalfs.len(),
                    dep_count
                );
                return Ok(());
            }

            if i_args.json {
                let json_out = serde_json::json!({
                    "file": i_args.dar_path,
                    "format": "daml-lf",
                    "main_package_id": archive.main_package_id,
                    "lf_version": archive.lf_version,
                    "package_name": pkg_name,
                    "package_version": pkg_ver,
                    "modules": archive.modules,
                    "dalf_count": archive.dalfs.len(),
                    "module_surfaces": archive.module_surfaces,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_out).map_err(|e| e.to_string())?
                );
                return Ok(());
            }

            println!("============================================================");
            println!(" Daml Archive (DAR) Inspection Report");
            println!("============================================================");
            println!(" Archive File:         {}", i_args.dar_path);
            println!(" Package Name:         {}-{}", pkg_name, pkg_ver);
            println!(" Main Package ID:      {}", archive.main_package_id);
            println!(" Daml-LF Version:      {}", archive.lf_version);
            println!(" Modules:              {}", archive.modules.join(", "));
            println!(" Total DALF Packages:  {}", archive.dalfs.len());
            for surface in &archive.module_surfaces {
                println!(" Module Surface:       {}", surface.name);
                for tpl in &surface.templates {
                    println!(
                        "   template {} (fields: {}, choices: {})",
                        tpl.name,
                        tpl.fields.len(),
                        tpl.choices.len()
                    );
                }
            }
            println!("============================================================");
            Ok(())
        }
        DpmAction::ValidateDar(v_args) => {
            let path = Path::new(&v_args.dar_path);
            let archive = lf_archive::parse_dar_file(path)
                .map_err(|e| format!("DAR validation failed: {e}"))?;
            let _world = lf_eval::World::open(path)
                .map_err(|e| format!("LF package graph validation failed: {e}"))?;
            check_dar_like_upload(path).map_err(|e| format!("DAR validation failed: {e}"))?;

            println!("DAR Validation Status: VALID (passes the upload checks; package upgrade compatibility is not checked)");
            println!("Main Package ID:       {}", archive.main_package_id);
            println!("LF Version:            {}", archive.lf_version);
            println!(
                "Verified DALFs:        {} (SHA-256 verified)",
                archive.dalfs.len()
            );
            println!("Verified Modules:      {}", archive.modules.join(", "));
            Ok(())
        }
        DpmAction::Codegen(c_args) => {
            let archive = lf_archive::parse_dar_file(Path::new(&c_args.dar_path))
                .map_err(|e| format!("Codegen DAR load error: {e}"))?;

            match c_args.lang.as_str() {
                "rust" => {
                    // [CANTON-NOTE: SEMANTICS] Every type of the package gets a Rust item or a warning: a type the generator
                    // cannot represent is named on stderr with its reason, and the exit status stays 0 (as the official
                    // generators do for the types they leave out) so a build is not broken by an unused type.
                    let world = lf_eval::World::open(Path::new(&c_args.dar_path))
                        .map_err(|e| format!("Codegen DAR load error: {e}"))?;
                    let generated = lf_eval::codegen::generate_rust(&world)
                        .map_err(|e| format!("Codegen failed: {e}"))?;
                    for skipped in &generated.skipped {
                        eprintln!(
                            "warning: skipped {}:{}: {}",
                            skipped.module, skipped.name, skipped.reason
                        );
                    }
                    print!("{}", generated.code);
                    Ok(())
                }
                "json" => {
                    let schema = serde_json::json!({
                        "package_id": archive.main_package_id,
                        "lf_version": archive.lf_version,
                        "module_surfaces": archive.module_surfaces,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&schema).map_err(|e| e.to_string())?
                    );
                    Ok(())
                }
                other => Err(format!(
                    "Unsupported codegen target language '{other}'. Supported: rust, json"
                )),
            }
        }
        DpmAction::Packages(p_args) => {
            let service = ledger_json_api::service::ExecutionService::try_new()?;
            let info = service
                .load_dar(Path::new(&p_args.dar))
                .map_err(|e| e.to_string())?;
            let resp = service.packages_response();
            println!("Uploaded DAR Package:  {}", info.main_package_id);
            println!("Total Active Packages: {}", resp.packages.len());
            println!("Modules Registered:    {}", resp.modules.join(", "));
            println!("Package Upload Status: SUCCESS");
            Ok(())
        }
        DpmAction::AuditPack(ap_args) => execute_audit_pack(ap_args),
        DpmAction::Fuzz(fz_args) => execute_fuzz_dar(fz_args),
        DpmAction::Mcp(mcp_args) => execute_mcp_server(mcp_args),
        DpmAction::Tui(tui_args) => execute_dpm_tui(tui_args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_dar_refuses_a_dar_the_upload_path_refuses() {
        let dar = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/e2e/fixtures/valid_lf22.dar"
        );
        let res = execute_dpm(DpmArgs {
            action: DpmAction::ValidateDar(ValidateDarArgs {
                dar_path: dar.to_string(),
            }),
        });
        assert!(res.is_err(), "validate-dar must not report VALID");
    }
}
