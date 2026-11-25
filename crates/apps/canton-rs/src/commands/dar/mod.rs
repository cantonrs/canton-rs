//! Offline DAR inspection, semantic diffing, and participant upgrade checks (`S-DX-006`).
//!
//! Covers:
//! - `canton-rs dar check-upgrade <old> <new>`
//! - `canton-rs dar inspect <dar> [--format text|json]`
//! - `canton-rs dar diff <a> <b> [--format text|json]`

pub mod diff;
pub mod inspect;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use lf_archive::{LoadedDar, PackageSignature};

use self::diff::{diff_loaded_dars, render_diff_text};
use self::inspect::{inspect_loaded_dar, load_dar_verified, render_inspect_text};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum DarFormatArg {
    Text,
    Json,
}

#[derive(Args, Debug)]
pub struct DarArgs {
    #[command(subcommand)]
    pub action: DarAction,
}

#[derive(Subcommand, Debug)]
pub enum DarAction {
    /// Runs the upgrade checks a participant runs when it vets both DARs (Canton's `upgrade-check`): each package
    /// name must form a lineage of valid upgrades, ordered by package version whatever the argument order.
    CheckUpgrade {
        /// The DAR with the earlier version.
        old: PathBuf,
        /// The DAR with the later version.
        new: PathBuf,
    },
    /// Inspects packages, modules, templates, choices, interfaces, and dependencies of a DAR (`S-DX-006`).
    Inspect {
        /// Path to the `.dar` archive.
        dar: PathBuf,
        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value = "text")]
        format: DarFormatArg,
    },
    /// Compares two DARs by package name and attaches upgrade compatibility results (`S-DX-006`).
    Diff {
        /// First `.dar` archive.
        a: PathBuf,
        /// Second `.dar` archive.
        b: PathBuf,
        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value = "text")]
        format: DarFormatArg,
    },
}

pub fn execute_dar(args: DarArgs) -> Result<(), String> {
    match args.action {
        DarAction::CheckUpgrade { old, new } => {
            let load = |p: &std::path::Path| {
                lf_archive::load_dar_file_allow_dev(p)
                    .map_err(|e| format!("Error reading DAR from {}: {e}", p.display()))
            };
            check_upgrade_refs(&[&load(&old)?, &load(&new)?])?;
            println!(
                "Upgrade checks passed for {} and {}.",
                old.display(),
                new.display()
            );
            Ok(())
        }
        DarAction::Inspect { dar, format } => {
            let loaded = load_dar_verified(&dar)?;
            let inspection = inspect_loaded_dar(&loaded)?;
            match format {
                DarFormatArg::Text => println!("{}", render_inspect_text(&inspection)),
                DarFormatArg::Json => {
                    let body = serde_json::to_string_pretty(&inspection)
                        .map_err(|e| format!("failed to serialize DAR inspection JSON: {e}"))?;
                    println!("{body}");
                }
            }
            Ok(())
        }
        DarAction::Diff { a, b, format } => {
            let loaded_a = load_dar_verified(&a)?;
            let loaded_b = load_dar_verified(&b)?;
            let report = diff_loaded_dars(&loaded_a, &loaded_b)?;
            match format {
                DarFormatArg::Text => println!("{}", render_diff_text(&report)),
                DarFormatArg::Json => {
                    let body = serde_json::to_string_pretty(&report)
                        .map_err(|e| format!("failed to serialize DAR diff JSON: {e}"))?;
                    println!("{body}");
                }
            }
            Ok(())
        }
    }
}

/// `UpgradeCheckMain.check`: every package of the DARs is new and vetted, nothing else is known.
pub(crate) fn check_upgrade_refs(dars: &[&LoadedDar]) -> Result<(), String> {
    let mut vetted = BTreeMap::new();
    for dar in dars {
        vetted.extend(PackageSignature::of_dar(dar).map_err(|e| e.to_string())?);
    }
    let all: BTreeSet<String> = vetted.keys().cloned().collect();
    lf_archive::validate_upgrade(&all, &vetted, &BTreeMap::new())
        .map_err(|e| format!("{}: {e}", e.code()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture(name: &str) -> LoadedDar {
        lf_archive::load_dar_file(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../tests/oracle/upgrade")
                .join(name),
        )
        .expect("fixture")
    }

    /// v2 with its main package under a new id and without the choice `Rebuild`.
    fn v2_without_rebuild() -> LoadedDar {
        let mut dar = fixture("upg-2.0.0.dar");
        let main = dar.archive.main_package_id.clone();
        let mut package = dar.packages.remove(&main).expect("main");
        let strings = package.interned_strings.clone();
        package.modules[0].templates[0].choices.retain(|c| {
            usize::try_from(c.name_interned_str)
                .ok()
                .and_then(|i| strings.get(i))
                .is_none_or(|n| n != "Rebuild")
        });
        let lf = dar.package_versions[&main].clone();
        dar.packages.insert("edited".into(), package);
        dar.package_versions.insert("edited".into(), lf);
        dar
    }

    #[test]
    fn a_removed_choice_is_reported_with_the_canton_code() {
        assert_eq!(
            check_upgrade_refs(&[&fixture("upg-1.0.0.dar"), &fixture("upg-2.0.0.dar")]),
            Ok(())
        );
        let err = check_upgrade_refs(&[&fixture("upg-1.0.0.dar"), &v2_without_rebuild()])
            .expect_err("refused");
        assert!(
            err.starts_with(
                "NOT_VALID_UPGRADE_PACKAGE: Upgrade checks indicate that edited (upg v2.0.0) cannot be an upgrade of "
            ) && err.ends_with(
                "Reason: Choice Rebuild appears in package that is being upgraded, but does not appear in the upgrading package."
            ),
            "{err}"
        );
    }
}
