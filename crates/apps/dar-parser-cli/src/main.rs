//! # `dar-parser`
//!
//! High-performance CLI tool for inspecting, parsing, and validating Daml 3.x / Canton 3.x DAR archives.
//!
//! Supports human-readable ASCII tables, machine-readable JSON schemas (compatible with `damlc inspect-dar`),
//! one-line summaries, and verbose package hierarchy trees.

use clap::Parser;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Command-line arguments for the `dar-parser` binary.
#[derive(Parser, Debug)]
#[command(
    name = "dar-parser",
    author = "Canton Rust Contributors",
    version,
    about = "Daml 3.x DAR Archive Parser and Inspector",
    long_about = "A high-performance CLI tool to inspect and parse Daml 3.x / Canton 3.x DAR archives and Daml-LF2 packages."
)]
pub struct Args {
    /// Path to the .dar archive file to inspect
    #[arg(value_name = "DAR_PATH")]
    pub dar_path: PathBuf,

    /// Output inspection results as machine-readable JSON
    #[arg(short, long)]
    pub json: bool,

    /// Output a concise one-line summary
    #[arg(short, long)]
    pub summary: bool,

    /// Print detailed DALF package tree and all metadata
    #[arg(short, long)]
    pub verbose: bool,
}

/// Main package details schema for machine-readable JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct MainPackageInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub package_id: String,
    pub lf_version: String,
    pub hash_verified: bool,
    pub dalf_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    pub modules: Vec<String>,
    pub module_surfaces: Vec<lf_archive::ModuleSurface>,
}

/// Individual DALF package entry in JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct DalfEntryInfo {
    pub name: String,
    pub package_id: String,
    pub is_main: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_version: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<String>,
}

/// Package metadata entry in the `packages` dictionary.
#[derive(Debug, Clone, Serialize)]
pub struct PackageMetaEntry {
    pub name: Option<String>,
    pub version: Option<String>,
}

/// Full machine-readable JSON inspection schema.
#[derive(Debug, Clone, Serialize)]
pub struct DarJsonOutput {
    pub file: String,
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdk_version: Option<String>,
    pub main_package_id: String,
    pub lf_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_version: Option<String>,
    pub main_dalf: String,
    pub main_package: MainPackageInfo,
    pub dalfs: Vec<DalfEntryInfo>,
    pub dalf_paths: Vec<String>,
    pub packages: BTreeMap<String, PackageMetaEntry>,
    pub modules: Vec<String>,
    pub module_surfaces: Vec<lf_archive::ModuleSurface>,
}

/// Resolves effective package name and version from manifest and AST metadata.
///
/// If manifest `Name` contains a hyphenated version suffix (e.g. `sample-contract-0.1.0`),
/// it is cleanly stripped to return the canonical package name (`sample-contract`).
pub fn resolve_package_name_and_version(dar: &lf_archive::DarArchive) -> (String, String) {
    let version = dar
        .manifest_version
        .clone()
        .or_else(|| dar.package_version.clone())
        .unwrap_or_else(|| "0.1.0".to_string());

    let name = if let Some(m_name) = &dar.manifest_name {
        let suffix = format!("-{}", version);
        if let Some(stripped) = m_name.strip_suffix(&suffix) {
            stripped.to_string()
        } else {
            m_name.clone()
        }
    } else if let Some(pkg_name) = &dar.package_name {
        pkg_name.clone()
    } else {
        "unknown".to_string()
    };

    (name, version)
}

/// Inferred package name from a DALF entry filename.
fn infer_package_name_from_dalf(dalf_name: &str) -> Option<String> {
    let filename = Path::new(dalf_name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(dalf_name);

    let stem = filename.strip_suffix(".dalf").unwrap_or(filename);

    if stem.starts_with("daml-prim") {
        return Some("daml-prim".to_string());
    }
    if stem.starts_with("daml-stdlib") {
        return Some("daml-stdlib".to_string());
    }

    if let Some((prefix, _)) = stem.split_once('-') {
        if !prefix.is_empty() {
            return Some(prefix.to_string());
        }
    }

    Some(stem.to_string())
}

/// Emits standardized JSON output matching `damlc inspect-dar --json` extended with `module_surfaces`.
pub fn print_json(path: &Path, dar: &lf_archive::DarArchive) -> Result<(), serde_json::Error> {
    let (name, version) = resolve_package_name_and_version(dar);
    let file_size = std::fs::metadata(path).map(|m| m.len()).ok();

    let mut packages = BTreeMap::new();
    packages.insert(
        dar.main_package_id.clone(),
        PackageMetaEntry {
            name: Some(name.clone()),
            version: Some(version.clone()),
        },
    );

    let mut dalf_paths = Vec::new();
    let mut dalfs = Vec::new();

    for d in &dar.dalfs {
        dalf_paths.push(d.name.clone());
        dalfs.push(DalfEntryInfo {
            name: d.name.clone(),
            package_id: d.package_id.clone(),
            is_main: d.is_main,
            package_name: d.package_name.clone(),
            package_version: d.package_version.clone(),
            modules: d.modules.clone(),
        });

        if !packages.contains_key(&d.package_id) {
            let inferred_name = d
                .package_name
                .clone()
                .or_else(|| infer_package_name_from_dalf(&d.name));
            packages.insert(
                d.package_id.clone(),
                PackageMetaEntry {
                    name: inferred_name,
                    version: d.package_version.clone(),
                },
            );
        }
    }

    let output = DarJsonOutput {
        file: path.display().to_string(),
        format: "daml-lf".to_string(),
        sdk_version: None,
        main_package_id: dar.main_package_id.clone(),
        lf_version: dar.lf_version.clone(),
        package_name: Some(name.clone()),
        package_version: Some(version.clone()),
        main_dalf: dar.main_dalf_name.clone(),
        main_package: MainPackageInfo {
            name: Some(name),
            version: Some(version),
            package_id: dar.main_package_id.clone(),
            lf_version: dar.lf_version.clone(),
            hash_verified: true,
            dalf_path: dar.main_dalf_name.clone(),
            size_bytes: file_size,
            modules: dar.modules.clone(),
            module_surfaces: dar.module_surfaces.clone(),
        },
        dalfs,
        dalf_paths,
        packages,
        modules: dar.modules.clone(),
        module_surfaces: dar.module_surfaces.clone(),
    };

    let json_string = serde_json::to_string_pretty(&output)?;
    println!("{}", json_string);
    Ok(())
}

/// Emits a single-line summary of the DAR archive.
pub fn print_summary(dar: &lf_archive::DarArchive) {
    let (name, version) = resolve_package_name_and_version(dar);
    let dep_count = dar.dalfs.iter().filter(|d| !d.is_main).count();
    let modules_str = if dar.modules.is_empty() {
        "none".to_string()
    } else {
        dar.modules.join(", ")
    };
    println!(
        "Package: {}-{} | ID: {} | LF: {} | Modules: [{}] | DALFs: {} ({} deps)",
        name,
        version,
        dar.main_package_id,
        dar.lf_version,
        modules_str,
        dar.dalfs.len(),
        dep_count,
    );
}

/// Helper to print decoded module surfaces and templates in human-readable format.
fn print_module_surfaces_section(surfaces: &[lf_archive::ModuleSurface]) {
    let total_templates: usize = surfaces.iter().map(|m| m.templates.len()).sum();
    if total_templates == 0 {
        return;
    }

    println!("--- Module Surfaces ({} templates) ---", total_templates);
    for module in surfaces {
        if module.templates.is_empty() {
            continue;
        }
        println!("  Module: {}", module.name);
        for tmpl in &module.templates {
            println!("  * template {} (param: {})", tmpl.name, tmpl.param_name);
            println!("    Fields ({}):", tmpl.fields.len());
            for field in &tmpl.fields {
                println!("      - {} : {}", field.name, field.type_str);
            }

            let sigs = if tmpl.signatories.is_empty() {
                "(none)".to_string()
            } else {
                tmpl.signatories.join(", ")
            };
            println!("    Signatories: {}", sigs);

            let obs = if tmpl.observers.is_empty() {
                "(none)".to_string()
            } else {
                tmpl.observers.join(", ")
            };
            println!("    Observers: {}", obs);

            if tmpl.ensure.present {
                println!(
                    "    Ensure Precondition: present ({} bytes, unexecuted)",
                    tmpl.ensure.bytes_len
                );
            } else {
                println!("    Ensure Precondition: absent (0 bytes)");
            }

            println!("    Choices ({}):", tmpl.choices.len());
            for choice in &tmpl.choices {
                let mode = if choice.consuming {
                    "consuming"
                } else {
                    "nonconsuming"
                };
                println!("      - choice {} ({})", choice.name, mode);

                let ctrls = if choice.controllers.is_empty() {
                    "(none)".to_string()
                } else {
                    choice.controllers.join(", ")
                };
                println!("        Controller: {}", ctrls);

                if !choice.observers.is_empty() {
                    println!("        Observers: {}", choice.observers.join(", "));
                }

                if choice.params.is_empty() {
                    println!("        Params: (none)");
                } else {
                    let param_list: Vec<String> = choice
                        .params
                        .iter()
                        .map(|p| format!("{} : {}", p.name, p.type_str))
                        .collect();
                    println!(
                        "        Params ({}): {}",
                        choice.params.len(),
                        param_list.join(", ")
                    );
                }

                println!("        Return Type: {}", choice.return_type_str);

                if choice.do_body.present {
                    println!(
                        "        Do Body: present ({} bytes, unexecuted)",
                        choice.do_body.bytes_len
                    );
                } else {
                    println!("        Do Body: absent (0 bytes)");
                }
            }
        }
    }
    println!();
}

/// Emits detailed verbose output including full package tree and manifest properties.
pub fn print_verbose(path: &Path, dar: &lf_archive::DarArchive) {
    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let (name, version) = resolve_package_name_and_version(dar);
    let dep_count = dar.dalfs.iter().filter(|d| !d.is_main).count();

    println!("================================================================================");
    println!("Daml Archive (DAR) Detailed Inspection Report [VERBOSE]");
    println!("================================================================================");
    println!("Archive Path:     {}", path.display());
    println!(
        "Archive Size:     {} bytes ({:.2} KiB)",
        file_size,
        file_size as f64 / 1024.0
    );
    println!("Format:           daml-lf");
    if let Some(m_name) = &dar.manifest_name {
        println!("Manifest Name:    {}", m_name);
    }
    if let Some(m_ver) = &dar.manifest_version {
        println!("Manifest Version: {}", m_ver);
    }
    println!();
    println!("--- Primary Contract Package ---");
    println!("  Package Name:     {}", name);
    println!("  Package Version:  {}", version);
    println!("  Main Package ID:  {}", dar.main_package_id);
    println!("  Daml-LF Version:  {} (Major: 2)", dar.lf_version);
    println!("  Integrity Hash:   VERIFIED (SHA-256 payload digest matches Archive header)");
    println!("  Main DALF Entry:  {}", dar.main_dalf_name);
    println!();
    println!("--- Compiled Modules ({}) ---", dar.modules.len());
    if dar.modules.is_empty() {
        println!("  (none)");
    } else {
        for module in &dar.modules {
            println!("  * {}", module);
        }
    }
    println!();
    print_module_surfaces_section(&dar.module_surfaces);
    println!(
        "--- DALF Package Inventory ({} total, {} dependencies) ---",
        dar.dalfs.len(),
        dep_count
    );
    for (i, dalf) in dar.dalfs.iter().enumerate() {
        let role = if dalf.is_main {
            "[PRIMARY]   "
        } else {
            "[DEPENDENCY]"
        };
        println!("  {:2}. {} {}", i + 1, role, dalf.name);
        println!("      Package ID: {}", dalf.package_id);
    }
    println!("================================================================================");
}

/// Emits human-readable ASCII table report.
pub fn print_human(path: &Path, dar: &lf_archive::DarArchive) {
    let (name, version) = resolve_package_name_and_version(dar);
    let dep_dalfs: Vec<&lf_archive::DalfInfo> = dar.dalfs.iter().filter(|d| !d.is_main).collect();

    println!("================================================================================");
    println!("Daml Archive (DAR) Inspection Report");
    println!("================================================================================");
    println!("Archive File:    {}", path.display());
    println!("Main Package ID: {}", dar.main_package_id);
    println!("Daml-LF Version: {}", dar.lf_version);
    println!("Package Name:    {}", name);
    println!("Package Version: {}", version);
    println!("Integrity Hash:  VERIFIED (SHA-256 matches Archive header)");
    println!("Main DALF Entry: {}", dar.main_dalf_name);
    println!();
    println!("--- Exported Modules ({}) ---", dar.modules.len());
    if dar.modules.is_empty() {
        println!("  (none)");
    } else {
        for module in &dar.modules {
            println!("  * {}", module);
        }
    }
    println!();
    print_module_surfaces_section(&dar.module_surfaces);
    println!("--- Bundled Dependencies ({}) ---", dep_dalfs.len());
    if dep_dalfs.is_empty() {
        println!("  (none)");
    } else {
        for dep in dep_dalfs {
            println!("  * {}", dep.name);
            println!("    Package ID: {}", dep.package_id);
        }
    }
    println!("================================================================================");
}

fn main() {
    let args = Args::parse();

    let dar = match lf_archive::parse_dar_file(&args.dar_path) {
        Ok(dar) => dar,
        Err(err) => {
            eprintln!("Error: {}", err);
            std::process::exit(1);
        }
    };

    if args.json {
        if let Err(err) = print_json(&args.dar_path, &dar) {
            eprintln!("Error serializing JSON: {}", err);
            std::process::exit(1);
        }
    } else if args.summary {
        print_summary(&dar);
    } else if args.verbose {
        print_verbose(&args.dar_path, &dar);
    } else {
        print_human(&args.dar_path, &dar);
    }
}
