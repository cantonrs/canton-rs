//! Daml-LF Package Typecheck, Serializability, and Validation Order.
//!
//! Enforces:
//! - Exact failure order matching official Daml engine (AT-A08):
//!   1. Version gate check
//!   2. Interned table bounds check
//!   3. Type resolution check
//!   4. Template & Choice serializability check

use lf_archive::proto::daml_lf_2::{self, BuiltinType, Package, Type};
use lf_archive::SUPPORTED_LF2_MINORS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    VersionGateFailed(String),
    InternedTableOOB { index: i32, table: &'static str },
    UnresolvedTypeCon(String),
    UnresolvedValue(String),
    NonSerializableType(String),
    DuplicateModule(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionGateFailed(msg) => write!(f, "LF version gate failed: {msg}"),
            Self::InternedTableOOB { index, table } => {
                write!(f, "interned table {table} out of bounds: {index}")
            }
            Self::UnresolvedTypeCon(ty) => write!(f, "unresolved type constructor: {ty}"),
            Self::UnresolvedValue(val) => write!(f, "unresolved value: {val}"),
            Self::NonSerializableType(ty) => write!(f, "type is not serializable: {ty}"),
            Self::DuplicateModule(mod_name) => write!(f, "duplicate module name: {mod_name}"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validates package typecheck and serializability adhering strictly to official failure order (AT-A08).
///
/// [CANTON-NOTE: LIMITATION] The failure order stated above was NOT measured against the JVM when this was written.
/// S-LF-009 measured it: the JVM refuses malformed tables, type forms and duplicate modules while *decoding*
/// (`DAR_PARSE_ERROR`, implemented in `lf_archive::interned`) and only then type-checks (`DAR_VALIDATION_ERROR`:
/// `ETypeMismatch`, `EFieldTypeMismatch`). This function is only a small stub of the later phase; it type-checks
/// nothing and its order must not be read as the JVM's. The package validator is `lf_archive::typecheck` (S-LF-016).
pub fn validate_package_strict(
    minor_version: &str,
    package: &Package,
) -> Result<(), ValidationError> {
    // 1. Version gate
    if !SUPPORTED_LF2_MINORS.contains(&minor_version) {
        return Err(ValidationError::VersionGateFailed(format!(
            "unsupported minor version {minor_version}, supported: {SUPPORTED_LF2_MINORS:?}"
        )));
    }

    // 2. Interned table bounds check
    let str_count = package.interned_strings.len() as i32;
    for dname in &package.interned_dotted_names {
        for &seg in &dname.segments_interned_str {
            if seg < 0 || seg >= str_count {
                return Err(ValidationError::InternedTableOOB {
                    index: seg,
                    table: "interned_strings in dotted_name",
                });
            }
        }
    }

    // 3. Module structure
    let dname_count = package.interned_dotted_names.len() as i32;
    for module in &package.modules {
        for dt in &module.data_types {
            if dt.name_interned_dname < 0 || dt.name_interned_dname >= dname_count {
                return Err(ValidationError::InternedTableOOB {
                    index: dt.name_interned_dname,
                    table: "interned_dotted_names in data_type",
                });
            }
        }
    }

    // 4. Serializability check
    for ty in &package.interned_types {
        check_type_serializable(ty)?;
    }

    Ok(())
}

fn check_type_serializable(ty: &Type) -> Result<(), ValidationError> {
    let Some(sum) = &ty.sum else {
        return Ok(());
    };

    match sum {
        daml_lf_2::r#type::Sum::Var(_) => {
            // Unbound type variable cannot be serialized
            Err(ValidationError::NonSerializableType("type variable".into()))
        }
        daml_lf_2::r#type::Sum::Builtin(b) => {
            if b.builtin == BuiltinType::Update as i32 {
                Err(ValidationError::NonSerializableType(
                    "Update effect type".into(),
                ))
            } else if b.builtin == BuiltinType::AnyException as i32 {
                Err(ValidationError::NonSerializableType("AnyException".into()))
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_at_a08_version_gate_fails_before_interned_bounds() {
        let pkg = Package {
            modules: Vec::new(),
            interned_strings: Vec::new(),
            interned_dotted_names: Vec::new(),
            metadata: None,
            interned_types: Vec::new(),
            ..Default::default()
        };

        // Unknown minor version triggers VersionGateFailed first
        let res = validate_package_strict("99", &pkg);
        assert!(matches!(res, Err(ValidationError::VersionGateFailed(_))));
    }

    #[test]
    fn test_at_a08_interned_bounds_fails_before_serializability() {
        let mut pkg = Package {
            modules: Vec::new(),
            interned_strings: vec!["ValidStr".into()],
            interned_dotted_names: Vec::new(),
            metadata: None,
            interned_types: Vec::new(),
            ..Default::default()
        };
        // Out of bounds dotted name reference
        pkg.interned_dotted_names
            .push(daml_lf_2::InternedDottedName {
                segments_interned_str: vec![999], // OOB!
            });

        let res = validate_package_strict("1", &pkg);
        assert!(matches!(res, Err(ValidationError::InternedTableOOB { .. })));
    }

    #[test]
    fn test_at_a08_non_serializable_update_rejected() {
        let mut pkg = Package {
            modules: Vec::new(),
            interned_strings: Vec::new(),
            interned_dotted_names: Vec::new(),
            metadata: None,
            interned_types: Vec::new(),
            ..Default::default()
        };

        // Interned type with Update effect
        pkg.interned_types.push(Type {
            sum: Some(daml_lf_2::r#type::Sum::Builtin(
                daml_lf_2::r#type::Builtin {
                    builtin: BuiltinType::Update as i32,
                    args: Vec::new(),
                },
            )),
        });

        let res = validate_package_strict("1", &pkg);
        assert_eq!(
            res,
            Err(ValidationError::NonSerializableType(
                "Update effect type".into()
            ))
        );
    }
}
