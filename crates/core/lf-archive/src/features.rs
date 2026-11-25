//! Daml-LF feature gating of a package as a whole: a package may only use what its LF minor version allows
//! (Canton 3.7.2 `DecodeV2`, which refuses the package while decoding it).

use crate::error::DecodeError;
use crate::proto::daml_lf_2::{package::ImportsSum, Package};

/// The ordinal of `dev`, after every stable LF 2 minor.
pub(crate) const DEV: u32 = u32::MAX;

/// The ordinal of an LF 2 minor version (`dev` after every stable one), `None` for an unknown one.
pub(crate) fn minor_rank(minor: &str) -> Option<u32> {
    if minor == "dev" {
        Some(DEV)
    } else {
        minor.parse().ok()
    }
}

/// A Daml-LF feature and the inclusive range of minor ordinals that have it (`LanguageVersion.Feature`); a range
/// with `min > max` is `VersionRange.Empty`.
#[derive(Clone, Copy)]
pub(crate) struct Feature {
    pub(crate) name: &'static str,
    pub(crate) min: u32,
    pub(crate) max: u32,
}

impl Feature {
    pub(crate) fn enabled_in(self, rank: u32) -> bool {
        self.min <= rank && rank <= self.max
    }
}

const fn feature(name: &'static str, min: u32, max: u32) -> Feature {
    Feature { name, min, max }
}

// [CANTON-NOTE: SEMANTICS] The ranges of Canton 3.7.2 `project/DamlLfFeature.scala` (the same as the shipped
// `daml-lf-features.json`).
pub(crate) const CONTRACT_KEYS: Feature = feature("Contract Keys", 3, DEV);
pub(crate) const FLAT_ARCHIVE: Feature = feature("Flat Archive", 2, DEV);
pub(crate) const PACKAGE_IMPORTS: Feature = feature("Explicit package imports", 2, DEV);
pub(crate) const BIG_NUMERIC: Feature = feature("BigNumeric type", DEV, DEV);
pub(crate) const UNSTABLE: Feature = feature("Unstable, experimental features", DEV, DEV);
pub(crate) const UNPACK: Feature = feature("Unpack", DEV, DEV);
pub(crate) const EXTENDED_INTERFACES: Feature = feature("Guards in interfaces", DEV, DEV);
pub(crate) const CHOICE_FUNCS: Feature =
    feature("choiceController and choiceObserver functions", 1, 0);
pub(crate) const UNSAFE_FROM_INTERFACE: Feature = feature("UnsafeFromInterface builtin", 0, 1);
pub(crate) const EXTENDED_CRYPTO: Feature = feature("Extended crypto primitives", 3, DEV);
pub(crate) const EXTERNAL_CALL: Feature = feature("External Call", 4, DEV);

/// Refuses a package that uses a feature its LF version does not have, as `DecodeV2` refuses it while decoding:
/// the package-level gates here, the type- and expression-level ones in [`crate::expr_features`].
pub fn check_package_features(package: &Package, minor: &str) -> Result<(), DecodeError> {
    let rank =
        minor_rank(minor).ok_or_else(|| DecodeError::UnsupportedMinorVersion(minor.into()))?;
    let unsupported = |feature: Feature, case: Option<&str>| {
        if feature.enabled_in(rank) {
            return Ok(());
        }
        let name = match case {
            Some(case) => format!("{} (case {case})", feature.name),
            None => feature.name.to_string(),
        };
        Err(DecodeError::UnsupportedFeature(format!(
            "{name} is not supported by Daml-LF 2.{minor}"
        )))
    };
    // `decodePackageImports`: either case of the imports field needs package imports.
    match &package.imports_sum {
        Some(ImportsSum::PackageImports(_)) => {
            unsupported(PACKAGE_IMPORTS, Some("PACKAGE_IMPORTS"))?
        }
        Some(ImportsSum::NoImportedPackagesReason(_)) => {
            unsupported(PACKAGE_IMPORTS, Some("NO_IMPORTED_PACKAGES_REASON"))?
        }
        None => {}
    }
    if !package.interned_kinds.is_empty() {
        unsupported(FLAT_ARCHIVE, None)?;
    }
    let keyed = package
        .modules
        .iter()
        .flat_map(|m| &m.templates)
        .any(|t| t.key.is_some());
    if keyed {
        unsupported(CONTRACT_KEYS, None)?;
    }
    crate::expr_features::check_expr_features(package, minor, rank)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::daml_lf_2::{
        def_template::DefKey, DefTemplate, Kind, Module, PackageImports,
    };

    fn keyed_package() -> Package {
        Package {
            modules: vec![Module {
                templates: vec![DefTemplate {
                    key: Some(DefKey::default()),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn contract_keys_need_lf_2_3() {
        for minor in ["1", "2"] {
            let err = check_package_features(&keyed_package(), minor).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("Contract Keys is not supported by Daml-LF 2.{minor}")
            );
        }
        for minor in ["3", "4", "dev"] {
            assert!(check_package_features(&keyed_package(), minor).is_ok());
        }
    }

    /// The gate runs while a DALF is loaded, as `DecodeV2` refuses the package while decoding it.
    #[test]
    fn loading_a_keyed_lf_2_1_package_is_refused() {
        use crate::proto::daml_lf::{archive_payload::Sum, Archive, ArchivePayload, HashFunction};
        use prost::Message;
        let dalf = |minor: &str| {
            let payload = ArchivePayload {
                minor: minor.to_string(),
                sum: Some(Sum::DamlLf2(keyed_package().encode_to_vec())),
                ..Default::default()
            }
            .encode_to_vec();
            Archive {
                hash_function: HashFunction::Sha256 as i32,
                hash: crate::crypto::compute_sha256(&payload),
                payload,
            }
            .encode_to_vec()
        };
        let err = crate::decode::load_dalf(&dalf("1"))
            .err()
            .map(|e| e.to_string());
        assert_eq!(
            err.as_deref(),
            Some("Contract Keys is not supported by Daml-LF 2.1")
        );
        assert!(crate::decode::load_dalf(&dalf("3")).is_ok());
    }

    fn value_package(expr: crate::proto::daml_lf_2::Expr) -> Package {
        use crate::proto::daml_lf_2::DefValue;
        Package {
            modules: vec![Module {
                values: vec![DefValue {
                    expr: Some(expr),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn expr(sum: crate::proto::daml_lf_2::expr::Sum) -> crate::proto::daml_lf_2::Expr {
        crate::proto::daml_lf_2::Expr {
            sum: Some(sum),
            ..Default::default()
        }
    }

    fn refusal(package: &Package, minor: &str) -> Option<String> {
        check_package_features(package, minor)
            .err()
            .map(|e| e.to_string())
    }

    #[test]
    fn bignumeric_builtins_are_dev_only() {
        use crate::proto::daml_lf_2::{expr::Sum, BuiltinFunction};
        let pkg = value_package(expr(Sum::Builtin(BuiltinFunction::AddBignumeric as i32)));
        assert_eq!(
            refusal(&pkg, "4").as_deref(),
            Some("daml_lf_2.BuiltinFunction.ADD_BIGNUMERIC is not supported by Daml-LF 2.4")
        );
        assert_eq!(refusal(&pkg, "dev"), None);
    }

    #[test]
    fn version_ranged_builtins_follow_their_feature() {
        use crate::proto::daml_lf_2::{expr::Sum, BuiltinFunction};
        let validate = value_package(expr(Sum::Builtin(
            BuiltinFunction::Secp256k1ValidateKey as i32,
        )));
        assert_eq!(
            refusal(&validate, "2").as_deref(),
            Some(
                "daml_lf_2.BuiltinFunction.SECP256K1_VALIDATE_KEY is not supported by Daml-LF 2.2"
            )
        );
        assert_eq!(refusal(&validate, "3"), None);
        let call = value_package(expr(Sum::Builtin(BuiltinFunction::ExternalCall as i32)));
        assert!(refusal(&call, "3").is_some());
        assert_eq!(refusal(&call, "4"), None);
    }

    #[test]
    fn bignumeric_type_in_the_type_table_is_dev_only() {
        use crate::proto::daml_lf_2::{r#type, BuiltinType, Type};
        let pkg = Package {
            interned_types: vec![Type {
                sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                    builtin: BuiltinType::Bignumeric as i32,
                    args: vec![],
                })),
            }],
            ..Default::default()
        };
        assert_eq!(
            refusal(&pkg, "2").as_deref(),
            Some("daml_lf_2.BuiltinType.BIGNUMERIC is not supported by Daml-LF 2.2")
        );
        assert_eq!(refusal(&pkg, "dev"), None);
    }

    #[test]
    fn interned_expr_needs_lf_2_2() {
        use crate::proto::daml_lf_2::{expr::Sum, BuiltinCon};
        let mut pkg = value_package(expr(Sum::InternedExpr(0)));
        pkg.interned_exprs = vec![expr(Sum::BuiltinCon(BuiltinCon::ConUnit as i32))];
        assert_eq!(
            refusal(&pkg, "1").as_deref(),
            Some("Flat Archive (case INTERNED_EXPR) is not supported by Daml-LF 2.1")
        );
        assert_eq!(refusal(&pkg, "2"), None);
    }

    /// A gated expression is found behind an interned-expression reference too.
    #[test]
    fn key_updates_need_lf_2_3() {
        use crate::proto::daml_lf_2::{expr::Sum, update, Update};
        let by_key = expr(Sum::Update(Box::new(Update {
            sum: Some(update::Sum::FetchByKey(update::RetrieveByKey::default())),
        })));
        let mut pkg = value_package(expr(Sum::InternedExpr(0)));
        pkg.interned_exprs = vec![by_key];
        assert_eq!(
            refusal(&pkg, "2").as_deref(),
            Some("Contract Keys is not supported by Daml-LF 2.2")
        );
        assert_eq!(refusal(&pkg, "3"), None);
    }

    #[test]
    fn package_imports_and_interned_kinds_need_lf_2_2() {
        let imports = Package {
            imports_sum: Some(ImportsSum::PackageImports(PackageImports::default())),
            ..Default::default()
        };
        assert!(check_package_features(&imports, "1").is_err());
        assert!(check_package_features(&imports, "2").is_ok());
        let kinds = Package {
            interned_kinds: vec![Kind::default()],
            ..Default::default()
        };
        assert!(check_package_features(&kinds, "1").is_err());
        assert!(check_package_features(&kinds, "2").is_ok());
        assert!(check_package_features(&Package::default(), "1").is_ok());
    }
}
