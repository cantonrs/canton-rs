//! S-TX-001 (part 2): the template surface of Daml-LF 2.3 packages names the right parties.
//!
//! Before the surface walk followed `Expr.interned_expr`, the amulet `ValidatorRight` template was reported with
//! signatory `dso`. The expected parties below are the ones the JVM (`daml script --ide-ledger`, scenarios in
//! `tests/oracle/splice-diff/amulet`) showed: a create needs the authority of `user` and `validator`,
//! `ValidatorRight_ArchiveAsValidator` is exercised by `validator`, `ValidatorRight_ArchiveAsUser` by `user`.
use std::path::PathBuf;

#[test]
fn amulet_validator_right_surface_matches_what_the_jvm_enforces() {
    let dar = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/oracle/splice-dars/splice-amulet-0.1.25.dar");
    let info = lf_archive::parse_dar_file(dar).expect("dar");
    let template = info
        .module_surfaces
        .iter()
        .flat_map(|m| m.templates.iter())
        .find(|t| t.name == "ValidatorRight")
        .expect("ValidatorRight");
    let mut signatories = template.signatories.clone();
    signatories.sort();
    assert_eq!(signatories, vec!["user", "validator"]);
    let controllers = |name: &str| {
        let mut c = template
            .choices
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("choice {name}"))
            .controllers
            .clone();
        c.sort();
        c
    };
    assert_eq!(
        controllers("ValidatorRight_ArchiveAsValidator"),
        vec!["validator"]
    );
    assert_eq!(controllers("ValidatorRight_ArchiveAsUser"), vec!["user"]);
    assert_eq!(controllers("Archive"), vec!["user", "validator"]);
}
