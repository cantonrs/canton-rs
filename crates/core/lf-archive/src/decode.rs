//! Daml-LF2 protobuf decoding, version gating, and interned metadata resolution.

use crate::crypto::verify_package_id;
use crate::error::DecodeError;
use crate::proto::daml_lf::{archive_payload::Sum, Archive, ArchivePayload, HashFunction};
use crate::proto::daml_lf_2::{self, Package};
use crate::surface::{
    BytePresence, ChoiceDef, ChoiceParam, FieldDef, ModuleSurface, SurfaceType, TemplateSurface,
};
use prost::Message;

/// Supported Daml-LF 2 stable minor versions: 2.1, 2.2, 2.3, 2.4.
pub const SUPPORTED_LF2_MINORS: &[&str] = &["1", "2", "3", "4"];

/// Information decoded from a single `.dalf` package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedDalf {
    /// SHA-256 package identifier (lowercase 64-character hex string).
    pub package_id: String,

    /// Full Daml-LF version string (e.g. "2.1").
    pub lf_version: String,

    /// Human-readable package name resolved from interned strings.
    pub package_name: Option<String>,

    /// Package version string resolved from interned strings.
    pub package_version: Option<String>,

    /// List of module names defined in this package.
    pub modules: Vec<String>,

    /// Decoded module surfaces for all templates exported by the package.
    pub module_surfaces: Vec<ModuleSurface>,
}

/// A DALF opened through the version gate, with its package id and AST.
pub struct LoadedDalf {
    pub package_id: String,
    pub lf_version: String,
    pub package: Package,
}

/// Decodes the outer `daml_lf.Archive` envelope, verifies hash function and SHA-256 integrity,
/// and returns the decoded `Archive` and verified Package ID.
pub fn decode_dalf_envelope(bytes: &[u8]) -> Result<(Archive, String), DecodeError> {
    let archive = Archive::decode(bytes)?;

    // Verify hash function is SHA256 (0)
    if archive.hash_function != HashFunction::Sha256 as i32 {
        return Err(DecodeError::UnsupportedHashFunction(archive.hash_function));
    }

    if archive.payload.is_empty() {
        return Err(DecodeError::MissingPayload);
    }

    // Verify cryptographic integrity: computed SHA-256 matches declared hash (AT-A04)
    let package_id = verify_package_id(&archive.payload, &archive.hash)?;

    Ok((archive, package_id))
}

/// Decodes a `.dalf` package, optionally permitting Daml-LF `2.dev` minor version.
pub fn load_dalf_with(bytes: &[u8], allow_dev: bool) -> Result<LoadedDalf, DecodeError> {
    let (archive, package_id) = decode_dalf_envelope(bytes)?;
    load_payload_with(package_id, &archive.payload, allow_dev)
}

/// Decodes the payload of a DALF envelope (the bytes whose SHA-256 is `package_id`, as a package store keeps them)
/// through the same version and feature gates as [`load_dalf`], `2.dev` included; the id is not recomputed.
pub fn load_dalf_payload(package_id: &str, payload: &[u8]) -> Result<LoadedDalf, DecodeError> {
    load_payload_with(package_id.to_string(), payload, true)
}

fn load_payload_with(
    package_id: String,
    payload: &[u8],
    allow_dev: bool,
) -> Result<LoadedDalf, DecodeError> {
    let payload = ArchivePayload::decode(payload)?;
    let pkg_bytes = match payload.sum {
        Some(Sum::DamlLf1(_)) => {
            return Err(DecodeError::UnsupportedMajorVersion("1".to_string()));
        }
        Some(Sum::DamlLf2(bytes)) => bytes,
        None => return Err(DecodeError::MissingPayload),
    };
    if !SUPPORTED_LF2_MINORS.contains(&payload.minor.as_str())
        && !(allow_dev && payload.minor == "dev")
    {
        return Err(DecodeError::UnsupportedMinorVersion(payload.minor));
    }
    let lf_version = format!("2.{}", payload.minor);
    // [CANTON-NOTE: SEMANTICS] `lf2PackageParser`: `setRecursionLimit(EXTENDED_PROTOBUF_RECURSION_LIMIT)` (1000).
    let package = canton_proto::depth::decode_within::<Package>(
        &pkg_bytes,
        canton_proto::depth::LF_PACKAGE_RECURSION_LIMIT,
    )
    .map_err(|e| match e {
        canton_proto::depth::BoundedDecodeError::Decode(d) => DecodeError::Protobuf(d),
        too_deep => DecodeError::NestingTooDeep(too_deep.to_string()),
    })?;
    crate::features::check_package_features(&package, &payload.minor)?;
    Ok(LoadedDalf {
        package_id,
        lf_version,
        package,
    })
}

/// Decodes a complete `.dalf` package: validates envelope, verifies hash, enforces LF 2.x,
/// gates minor versions, and resolves interned metadata, modules, and template surfaces.
pub fn load_dalf(bytes: &[u8]) -> Result<LoadedDalf, DecodeError> {
    load_dalf_with(bytes, false)
}

/// Like `load_dalf`, but also permits Daml-LF `2.dev` (used explicitly by dev-feature evaluator oracles).
pub fn load_dalf_allow_dev(bytes: &[u8]) -> Result<LoadedDalf, DecodeError> {
    load_dalf_with(bytes, true)
}

pub(crate) fn decode_dalf_with(bytes: &[u8], allow_dev: bool) -> Result<DecodedDalf, DecodeError> {
    let loaded = load_dalf_with(bytes, allow_dev)?;
    let (package_name, package_version) = resolve_metadata(&loaded.package)?;
    let modules = resolve_modules(&loaded.package)?;
    let module_surfaces = extract_module_surfaces(&loaded.package)?;

    Ok(DecodedDalf {
        package_id: loaded.package_id,
        lf_version: loaded.lf_version,
        package_name,
        package_version,
        modules,
        module_surfaces,
    })
}

pub fn decode_dalf(bytes: &[u8]) -> Result<DecodedDalf, DecodeError> {
    decode_dalf_with(bytes, false)
}

/// Like `decode_dalf`, but also permits Daml-LF `2.dev`.
pub fn decode_dalf_allow_dev(bytes: &[u8]) -> Result<DecodedDalf, DecodeError> {
    decode_dalf_with(bytes, true)
}

/// Resolves package name and version from interned strings with strict bounds checking (AT-A08).
pub fn resolve_metadata(
    package: &Package,
) -> Result<(Option<String>, Option<String>), DecodeError> {
    let metadata = match &package.metadata {
        Some(m) => m,
        None => return Ok((None, None)),
    };

    let name = resolve_interned_string(
        package,
        metadata.name_interned_str,
        "PackageMetadata.name_interned_str",
    )?;

    let version = resolve_interned_string(
        package,
        metadata.version_interned_str,
        "PackageMetadata.version_interned_str",
    )?;

    Ok((Some(name), Some(version)))
}

/// Resolves module names from either direct segments or interned dotted names (AT-A08).
pub fn resolve_modules(package: &Package) -> Result<Vec<String>, DecodeError> {
    let mut module_names = Vec::with_capacity(package.modules.len());

    for module in &package.modules {
        module_names.push(resolve_single_module_name(package, module)?);
    }

    Ok(module_names)
}

/// Resolves the name of a single module from either direct segments or interned dotted names.
pub fn resolve_single_module_name(
    package: &Package,
    module: &daml_lf_2::Module,
) -> Result<String, DecodeError> {
    resolve_interned_dotted_name(
        package,
        module.name_interned_dname,
        "Module.name_interned_dname",
    )
}

/// Resolves an interned dotted name at the given table index.
pub fn resolve_interned_dotted_name(
    package: &Package,
    index: i32,
    context: &'static str,
) -> Result<String, DecodeError> {
    if index < 0 || (index as usize) >= package.interned_dotted_names.len() {
        return Err(DecodeError::InternedIndexOutOfBounds {
            index,
            table_size: package.interned_dotted_names.len(),
            context,
        });
    }

    let dotted = &package.interned_dotted_names[index as usize];
    let mut parts = Vec::with_capacity(dotted.segments_interned_str.len());
    for &seg_idx in &dotted.segments_interned_str {
        let part =
            resolve_interned_string(package, seg_idx, "InternedDottedName.segments_interned_str")?;
        parts.push(part);
    }
    Ok(parts.join("."))
}

/// Looks up an index in `package.interned_strings` with strict bounds checking.
pub fn resolve_interned_string(
    package: &Package,
    index: i32,
    context: &'static str,
) -> Result<String, DecodeError> {
    if index < 0 || (index as usize) >= package.interned_strings.len() {
        return Err(DecodeError::InternedIndexOutOfBounds {
            index,
            table_size: package.interned_strings.len(),
            context,
        });
    }

    Ok(package.interned_strings[index as usize].clone())
}

/// Resolves a `TypeConId` into package id, module name, and constructor name.
fn resolve_type_con_id(
    package: &Package,
    tc: &daml_lf_2::TypeConId,
) -> Result<(Option<String>, Option<String>, String), DecodeError> {
    let name = resolve_interned_dotted_name(
        package,
        tc.name_interned_dname,
        "TypeConId.name_interned_dname",
    )?;

    let (pkg_id, mod_name) = if let Some(m) = &tc.module {
        let mod_name = resolve_interned_dotted_name(
            package,
            m.module_name_interned_dname,
            "ModuleId.module_name_interned_dname",
        )?;
        let pkg_str = match &m.package_id {
            Some(daml_lf_2::SelfOrImportedPackageId {
                sum:
                    Some(daml_lf_2::self_or_imported_package_id::Sum::ImportedPackageIdInternedStr(idx)),
            }) => Some(resolve_interned_string(
                package,
                *idx,
                "ImportedPackageIdInternedStr",
            )?),
            _ => None,
        };
        (pkg_str, Some(mod_name))
    } else {
        (None, None)
    };

    Ok((pkg_id, mod_name, name))
}

/// Resolves a Nat value from a `Type` (e.g. for Numeric precision/scale).
fn resolve_nat_from_type(
    package: &Package,
    ty: &daml_lf_2::Type,
    depth: usize,
) -> Result<Option<i64>, DecodeError> {
    if depth > 32 {
        return Err(DecodeError::RecursionLimitExceeded {
            context: "resolve_nat_from_type",
        });
    }
    match &ty.sum {
        Some(daml_lf_2::r#type::Sum::Nat(n)) => Ok(Some(*n)),
        Some(daml_lf_2::r#type::Sum::InternedType(idx)) => {
            let idx = *idx;
            if idx < 0 || (idx as usize) >= package.interned_types.len() {
                return Err(DecodeError::InternedIndexOutOfBounds {
                    index: idx,
                    table_size: package.interned_types.len(),
                    context: "Type.interned_type for Nat",
                });
            }
            resolve_nat_from_type(package, &package.interned_types[idx as usize], depth + 1)
        }
        _ => Ok(None),
    }
}

/// Resolves a Daml-LF2 `Type` into a high-level `SurfaceType`.
pub fn resolve_surface_type(
    package: &Package,
    ty: &daml_lf_2::Type,
) -> Result<SurfaceType, DecodeError> {
    resolve_surface_type_depth(package, ty, 0)
}

fn resolve_surface_type_depth(
    package: &Package,
    ty: &daml_lf_2::Type,
    depth: usize,
) -> Result<SurfaceType, DecodeError> {
    if depth > 32 {
        return Err(DecodeError::RecursionLimitExceeded {
            context: "resolve_surface_type",
        });
    }

    let sum = match &ty.sum {
        Some(s) => s,
        None => return Err(DecodeError::InvalidType("empty Type sum".to_string())),
    };

    match sum {
        daml_lf_2::r#type::Sum::InternedType(idx) => {
            let idx = *idx;
            if idx < 0 || (idx as usize) >= package.interned_types.len() {
                return Err(DecodeError::InternedIndexOutOfBounds {
                    index: idx,
                    table_size: package.interned_types.len(),
                    context: "Type.interned_type",
                });
            }
            resolve_surface_type_depth(package, &package.interned_types[idx as usize], depth + 1)
        }
        daml_lf_2::r#type::Sum::Builtin(b) => match b.builtin {
            0 => Ok(SurfaceType::Unit),
            1 => Ok(SurfaceType::Bool),
            2 => Ok(SurfaceType::Int64),
            3 => Ok(SurfaceType::Date),
            4 => Ok(SurfaceType::Timestamp),
            5 => {
                let scale = if let Some(arg) = b.args.first() {
                    resolve_nat_from_type(package, arg, depth + 1)?.map(|n| n as u8)
                } else {
                    None
                };
                Ok(SurfaceType::Numeric(scale))
            }
            6 => Ok(SurfaceType::Party),
            7 => Ok(SurfaceType::Text),
            8 => {
                let inner = if let Some(arg) = b.args.first() {
                    resolve_surface_type_depth(package, arg, depth + 1)?
                } else {
                    SurfaceType::Other("Any".to_string())
                };
                Ok(SurfaceType::ContractId(Box::new(inner)))
            }
            9 => {
                let inner = if let Some(arg) = b.args.first() {
                    resolve_surface_type_depth(package, arg, depth + 1)?
                } else {
                    SurfaceType::Other("Any".to_string())
                };
                Ok(SurfaceType::Optional(Box::new(inner)))
            }
            10 => {
                let inner = if let Some(arg) = b.args.first() {
                    resolve_surface_type_depth(package, arg, depth + 1)?
                } else {
                    SurfaceType::Other("Any".to_string())
                };
                Ok(SurfaceType::List(Box::new(inner)))
            }
            11 => {
                let key = if let Some(arg) = b.args.first() {
                    resolve_surface_type_depth(package, arg, depth + 1)?
                } else {
                    SurfaceType::Other("Any".to_string())
                };
                let value = if let Some(arg) = b.args.get(1) {
                    resolve_surface_type_depth(package, arg, depth + 1)?
                } else {
                    SurfaceType::Other("Any".to_string())
                };
                Ok(SurfaceType::GenMap {
                    key: Box::new(key),
                    value: Box::new(value),
                })
            }
            16 => {
                let arg = if let Some(a) = b.args.first() {
                    resolve_surface_type_depth(package, a, depth + 1)?
                } else {
                    SurfaceType::Other("Any".to_string())
                };
                let ret = if let Some(r) = b.args.get(1) {
                    resolve_surface_type_depth(package, r, depth + 1)?
                } else {
                    SurfaceType::Other("Any".to_string())
                };
                Ok(SurfaceType::Arrow(Box::new(arg), Box::new(ret)))
            }
            other => Ok(SurfaceType::Other(format!("BuiltinType({})", other))),
        },
        daml_lf_2::r#type::Sum::Con(con) => {
            let (pkg_id, mod_name, name) = if let Some(tc) = &con.tycon {
                resolve_type_con_id(package, tc)?
            } else {
                (None, None, "UnknownCon".to_string())
            };

            let mut resolved_args = Vec::with_capacity(con.args.len());
            for arg in &con.args {
                resolved_args.push(resolve_surface_type_depth(package, arg, depth + 1)?);
            }

            if name == "Tuple2" || name.starts_with("Tuple") {
                Ok(SurfaceType::Tuple(resolved_args))
            } else {
                Ok(SurfaceType::TypeCon {
                    package_id: pkg_id,
                    module_name: mod_name,
                    name,
                    args: resolved_args,
                })
            }
        }
        daml_lf_2::r#type::Sum::Syn(syn) => {
            let (pkg_id, mod_name, name) = if let Some(ts) = &syn.tysyn {
                resolve_type_con_id(package, &tycon_of_syn(ts))?
            } else {
                (None, None, "UnknownSyn".to_string())
            };

            let mut resolved_args = Vec::with_capacity(syn.args.len());
            for arg in &syn.args {
                resolved_args.push(resolve_surface_type_depth(package, arg, depth + 1)?);
            }

            Ok(SurfaceType::TypeCon {
                package_id: pkg_id,
                module_name: mod_name,
                name,
                args: resolved_args,
            })
        }
        daml_lf_2::r#type::Sum::Forall(forall) => {
            if let Some(body) = &forall.body {
                resolve_surface_type_depth(package, body, depth + 1)
            } else {
                Ok(SurfaceType::Other("Forall".to_string()))
            }
        }
        daml_lf_2::r#type::Sum::Tapp(tapp) => {
            let lhs = if let Some(l) = &tapp.lhs {
                resolve_surface_type_depth(package, l, depth + 1)?
            } else {
                SurfaceType::Other("UnknownTApp".to_string())
            };
            let rhs = if let Some(r) = &tapp.rhs {
                resolve_surface_type_depth(package, r, depth + 1)?
            } else {
                SurfaceType::Other("UnknownArg".to_string())
            };
            // [CANTON-NOTE: SEMANTICS] Daml-LF 2.3 writes a tuple or parameterized builtin type via curried `TApp`:
            // e.g. `TApp(TApp(Tuple2, Party), Text)` or `TApp(Builtin(ContractId), TCon(Held))`.
            if let SurfaceType::Tuple(mut elems) = lhs {
                elems.push(rhs);
                return Ok(SurfaceType::Tuple(elems));
            }
            let is_any = |t: &SurfaceType| matches!(t, SurfaceType::Other(s) if s == "Any");
            match lhs {
                SurfaceType::ContractId(inner) if is_any(&inner) => {
                    Ok(SurfaceType::ContractId(Box::new(rhs)))
                }
                SurfaceType::Optional(inner) if is_any(&inner) => {
                    Ok(SurfaceType::Optional(Box::new(rhs)))
                }
                SurfaceType::List(inner) if is_any(&inner) => Ok(SurfaceType::List(Box::new(rhs))),
                SurfaceType::Numeric(None) if matches!(rhs, SurfaceType::Numeric(Some(_))) => {
                    Ok(rhs)
                }
                SurfaceType::GenMap { key, value } if is_any(&key) => Ok(SurfaceType::GenMap {
                    key: Box::new(rhs),
                    value,
                }),
                SurfaceType::GenMap { key, value } if is_any(&value) => Ok(SurfaceType::GenMap {
                    key,
                    value: Box::new(rhs),
                }),
                SurfaceType::TypeCon {
                    package_id,
                    module_name,
                    name,
                    mut args,
                } => {
                    args.push(rhs);
                    Ok(SurfaceType::TypeCon {
                        package_id,
                        module_name,
                        name,
                        args,
                    })
                }
                lhs => Ok(SurfaceType::Other(format!(
                    "{} {}",
                    lhs.display_daml(),
                    rhs.display_daml()
                ))),
            }
        }
        daml_lf_2::r#type::Sum::Var(v) => {
            let var_name =
                resolve_interned_string(package, v.var_interned_str, "Type.Var.var_interned_str")?;
            Ok(SurfaceType::TypeVar(var_name))
        }
        daml_lf_2::r#type::Sum::Struct(s) => {
            let mut elems = Vec::new();
            for f in &s.fields {
                if let Some(ty) = &f.r#type {
                    elems.push(resolve_surface_type_depth(package, ty, depth + 1)?);
                }
            }
            Ok(SurfaceType::Tuple(elems))
        }
        daml_lf_2::r#type::Sum::Nat(n) => Ok(SurfaceType::Numeric(Some(*n as u8))),
    }
}

/// A type synonym id has the same two fields as a type constructor id (module and dotted name) but is its
/// own message in the official schema.
fn tycon_of_syn(syn: &daml_lf_2::TypeSynId) -> daml_lf_2::TypeConId {
    daml_lf_2::TypeConId {
        module: syn.module,
        name_interned_dname: syn.name_interned_dname,
    }
}

/// Unwraps a `Type` down through indirection to find its underlying `TypeConId`.
fn unwrap_type_con(
    package: &Package,
    ty: &daml_lf_2::Type,
    depth: usize,
) -> Result<Option<daml_lf_2::TypeConId>, DecodeError> {
    if depth > 32 {
        return Err(DecodeError::RecursionLimitExceeded {
            context: "unwrap_type_con",
        });
    }

    match &ty.sum {
        Some(daml_lf_2::r#type::Sum::Con(con)) => Ok(con.tycon),
        Some(daml_lf_2::r#type::Sum::Syn(syn)) => Ok(syn.tysyn.as_ref().map(tycon_of_syn)),
        Some(daml_lf_2::r#type::Sum::InternedType(idx)) => {
            let idx = *idx;
            if idx < 0 || (idx as usize) >= package.interned_types.len() {
                return Err(DecodeError::InternedIndexOutOfBounds {
                    index: idx,
                    table_size: package.interned_types.len(),
                    context: "Type.interned_type for unwrap_type_con",
                });
            }
            unwrap_type_con(package, &package.interned_types[idx as usize], depth + 1)
        }
        _ => Ok(None),
    }
}

/// Extracts contract fields from the matching `DefDataType` record for a template.
fn extract_record_fields(
    package: &Package,
    module: &daml_lf_2::Module,
    tycon_dname: i32,
) -> Result<Vec<FieldDef>, DecodeError> {
    let expected_name =
        resolve_interned_dotted_name(package, tycon_dname, "DefTemplate.tycon_interned_dname")?;

    let dt = module
        .data_types
        .iter()
        .find(|d| {
            if d.name_interned_dname == tycon_dname {
                return true;
            }
            if let Ok(name) = resolve_interned_dotted_name(
                package,
                d.name_interned_dname,
                "DefDataType.name_interned_dname",
            ) {
                name == expected_name
            } else {
                false
            }
        })
        .ok_or_else(|| DecodeError::TemplateRecordNotFound {
            template: expected_name.clone(),
        })?;

    let record = match &dt.data_cons {
        Some(daml_lf_2::def_data_type::DataCons::Record(r)) => r,
        Some(daml_lf_2::def_data_type::DataCons::Variant(_)) => {
            return Err(DecodeError::InvalidTemplateRecord {
                template: expected_name,
                reason: "expected record, found variant".to_string(),
            });
        }
        Some(
            daml_lf_2::def_data_type::DataCons::Enum(_)
            | daml_lf_2::def_data_type::DataCons::Interface(_),
        ) => {
            return Err(DecodeError::InvalidTemplateRecord {
                template: expected_name,
                reason: "expected record, found enum or interface".to_string(),
            });
        }
        None => {
            return Err(DecodeError::InvalidTemplateRecord {
                template: expected_name,
                reason: "missing record data constructor".to_string(),
            });
        }
    };

    let mut fields = Vec::with_capacity(record.fields.len());
    for f in &record.fields {
        let field_name = resolve_interned_string(
            package,
            f.field_interned_str,
            "FieldWithType.field_interned_str",
        )?;

        let field_type = if let Some(t) = &f.r#type {
            resolve_surface_type(package, t)?
        } else {
            SurfaceType::Other("MissingType".to_string())
        };

        fields.push(FieldDef::new(field_name, field_type));
    }

    Ok(fields)
}

/// Extracts parameter fields for a contract choice.
fn extract_choice_params(
    package: &Package,
    module: &daml_lf_2::Module,
    choice: &daml_lf_2::TemplateChoice,
) -> Result<Vec<ChoiceParam>, DecodeError> {
    let arg_binder = match &choice.arg_binder {
        Some(b) => b,
        None => return Ok(Vec::new()),
    };

    let binder_type = match &arg_binder.r#type {
        Some(t) => t,
        None => return Ok(Vec::new()),
    };

    let tycon = match unwrap_type_con(package, binder_type, 0)? {
        Some(tc) => tc,
        None => return Ok(Vec::new()),
    };

    let target_name = resolve_interned_dotted_name(
        package,
        tycon.name_interned_dname,
        "TypeConId.name_interned_dname",
    )?;

    let dt = module.data_types.iter().find(|d| {
        if d.name_interned_dname == tycon.name_interned_dname {
            return true;
        }
        if let Ok(name) = resolve_interned_dotted_name(
            package,
            d.name_interned_dname,
            "DefDataType.name_interned_dname",
        ) {
            name == target_name
        } else {
            false
        }
    });

    let dt = match dt {
        Some(d) => d,
        None => return Ok(Vec::new()), // External type (like DA.Internal.Template:Archive)
    };

    let record = match &dt.data_cons {
        Some(daml_lf_2::def_data_type::DataCons::Record(r)) => r,
        _ => return Ok(Vec::new()),
    };

    let mut params = Vec::with_capacity(record.fields.len());
    for f in &record.fields {
        let param_name = resolve_interned_string(
            package,
            f.field_interned_str,
            "FieldWithType.field_interned_str",
        )?;

        let param_type = if let Some(t) = &f.r#type {
            resolve_surface_type(package, t)?
        } else {
            SurfaceType::Other("MissingType".to_string())
        };

        params.push(ChoiceParam::new(param_name, param_type));
    }

    Ok(params)
}

/// Recursively extracts party field names projected by an expression.
fn extract_parties_from_expr(
    package: &Package,
    module: &daml_lf_2::Module,
    expr: &daml_lf_2::Expr,
    known_fields: &[String],
) -> Result<Vec<String>, DecodeError> {
    let mut parties = Vec::new();
    let mut visited_values = std::collections::HashSet::new();

    collect_parties_recursive(
        package,
        module,
        expr,
        known_fields,
        &mut parties,
        &mut visited_values,
        0,
    )?;

    // Preserve first-seen ordering and deduplicate
    let mut deduped = Vec::new();
    for p in parties {
        if !deduped.contains(&p) {
            deduped.push(p);
        }
    }

    Ok(deduped)
}

fn collect_parties_recursive(
    package: &Package,
    module: &daml_lf_2::Module,
    expr: &daml_lf_2::Expr,
    known_fields: &[String],
    parties: &mut Vec<String>,
    visited_values: &mut std::collections::HashSet<i32>,
    depth: usize,
) -> Result<(), DecodeError> {
    if depth > 32 {
        return Ok(());
    }

    // Daml-LF 2.3 refers to shared sub-expressions by index into `Package.interned_exprs`; follow the reference.
    if let Some(daml_lf_2::expr::Sum::InternedExpr(index)) = &expr.sum {
        let target = usize::try_from(*index)
            .ok()
            .and_then(|i| package.interned_exprs.get(i))
            .ok_or(DecodeError::InternedIndexOutOfBounds {
                index: *index,
                table_size: package.interned_exprs.len(),
                context: "Expr.interned_expr",
            })?;
        return collect_parties_recursive(
            package,
            module,
            target,
            known_fields,
            parties,
            visited_values,
            depth + 1,
        );
    }

    let sum = match &expr.sum {
        Some(s) => s,
        None => return Ok(()),
    };

    match sum {
        daml_lf_2::expr::Sum::RecProj(proj) => {
            if let Ok(name) = resolve_interned_string(
                package,
                proj.field_interned_str,
                "RecProj.field_interned_str",
            ) {
                if (known_fields.is_empty() && proj.record.is_some())
                    || known_fields.contains(&name)
                {
                    parties.push(name);
                }
            }
            if let Some(inner) = &proj.record {
                collect_parties_recursive(
                    package,
                    module,
                    inner,
                    known_fields,
                    parties,
                    visited_values,
                    depth + 1,
                )?;
            }
        }
        daml_lf_2::expr::Sum::RecCon(rec_con) => {
            for f in &rec_con.fields {
                if let Some(e) = &f.expr {
                    collect_parties_recursive(
                        package,
                        module,
                        e,
                        known_fields,
                        parties,
                        visited_values,
                        depth + 1,
                    )?;
                }
            }
        }
        daml_lf_2::expr::Sum::RecUpd(rec_upd) => {
            if let Some(r) = &rec_upd.record {
                collect_parties_recursive(
                    package,
                    module,
                    r,
                    known_fields,
                    parties,
                    visited_values,
                    depth + 1,
                )?;
            }
            if let Some(u) = &rec_upd.update {
                collect_parties_recursive(
                    package,
                    module,
                    u,
                    known_fields,
                    parties,
                    visited_values,
                    depth + 1,
                )?;
            }
        }
        daml_lf_2::expr::Sum::StructCon(sc) => {
            for f in &sc.fields {
                if let Some(e) = &f.expr {
                    collect_parties_recursive(
                        package,
                        module,
                        e,
                        known_fields,
                        parties,
                        visited_values,
                        depth + 1,
                    )?;
                }
            }
        }
        daml_lf_2::expr::Sum::StructProj(sp) => {
            if let Some(s) = &sp.r#struct {
                collect_parties_recursive(
                    package,
                    module,
                    s,
                    known_fields,
                    parties,
                    visited_values,
                    depth + 1,
                )?;
            }
        }
        daml_lf_2::expr::Sum::Val(val_id) => {
            let dname_idx = val_id.name_interned_dname;
            if visited_values.insert(dname_idx) {
                let def_val = module.values.iter().find(|v| {
                    v.name_with_type
                        .as_ref()
                        .map(|nwt| nwt.name_interned_dname == dname_idx)
                        .unwrap_or(false)
                });

                if let Some(dv) = def_val {
                    if let Some(body) = &dv.expr {
                        collect_parties_recursive(
                            package,
                            module,
                            body,
                            known_fields,
                            parties,
                            visited_values,
                            depth + 1,
                        )?;
                    }
                } else if let Some(mod_ref) = &val_id.module {
                    // Check if the referenced value is in another module of the same package
                    let is_self_pkg = matches!(
                        mod_ref.package_id.as_ref().and_then(|p| p.sum.as_ref()),
                        None | Some(daml_lf_2::self_or_imported_package_id::Sum::SelfPackageId(
                            _
                        ))
                    );
                    if is_self_pkg {
                        if let Some(other_mod) = package
                            .modules
                            .iter()
                            .find(|m| m.name_interned_dname == mod_ref.module_name_interned_dname)
                        {
                            if let Some(dv) = other_mod.values.iter().find(|v| {
                                v.name_with_type
                                    .as_ref()
                                    .map(|nwt| nwt.name_interned_dname == dname_idx)
                                    .unwrap_or(false)
                            }) {
                                if let Some(body) = &dv.expr {
                                    collect_parties_recursive(
                                        package,
                                        other_mod,
                                        body,
                                        known_fields,
                                        parties,
                                        visited_values,
                                        depth + 1,
                                    )?;
                                }
                            }
                        }
                    }
                }
            }
        }
        daml_lf_2::expr::Sum::App(app) => {
            if let Some(fun) = &app.fun {
                collect_parties_recursive(
                    package,
                    module,
                    fun,
                    known_fields,
                    parties,
                    visited_values,
                    depth + 1,
                )?;
            }
            for arg in &app.args {
                collect_parties_recursive(
                    package,
                    module,
                    arg,
                    known_fields,
                    parties,
                    visited_values,
                    depth + 1,
                )?;
            }
        }
        daml_lf_2::expr::Sum::TyApp(ty_app) => {
            if let Some(inner) = &ty_app.expr {
                collect_parties_recursive(
                    package,
                    module,
                    inner,
                    known_fields,
                    parties,
                    visited_values,
                    depth + 1,
                )?;
            }
        }
        daml_lf_2::expr::Sum::Abs(abs) => {
            if let Some(body) = &abs.body {
                collect_parties_recursive(
                    package,
                    module,
                    body,
                    known_fields,
                    parties,
                    visited_values,
                    depth + 1,
                )?;
            }
        }
        daml_lf_2::expr::Sum::TyAbs(ty_abs) => {
            if let Some(body) = &ty_abs.body {
                collect_parties_recursive(
                    package,
                    module,
                    body,
                    known_fields,
                    parties,
                    visited_values,
                    depth + 1,
                )?;
            }
        }
        daml_lf_2::expr::Sum::Let(blk) => {
            for b in &blk.bindings {
                if let Some(bound) = &b.bound {
                    collect_parties_recursive(
                        package,
                        module,
                        bound,
                        known_fields,
                        parties,
                        visited_values,
                        depth + 1,
                    )?;
                }
            }
            if let Some(body) = &blk.body {
                collect_parties_recursive(
                    package,
                    module,
                    body,
                    known_fields,
                    parties,
                    visited_values,
                    depth + 1,
                )?;
            }
        }
        daml_lf_2::expr::Sum::Case(case_expr) => {
            if let Some(scrut) = &case_expr.scrut {
                collect_parties_recursive(
                    package,
                    module,
                    scrut,
                    known_fields,
                    parties,
                    visited_values,
                    depth + 1,
                )?;
            }
            for alt in &case_expr.alts {
                if let Some(alt_body) = &alt.body {
                    collect_parties_recursive(
                        package,
                        module,
                        alt_body,
                        known_fields,
                        parties,
                        visited_values,
                        depth + 1,
                    )?;
                }
            }
        }
        daml_lf_2::expr::Sum::Cons(cons) => {
            for f in &cons.front {
                collect_parties_recursive(
                    package,
                    module,
                    f,
                    known_fields,
                    parties,
                    visited_values,
                    depth + 1,
                )?;
            }
            if let Some(tail) = &cons.tail {
                collect_parties_recursive(
                    package,
                    module,
                    tail,
                    known_fields,
                    parties,
                    visited_values,
                    depth + 1,
                )?;
            }
        }
        daml_lf_2::expr::Sum::OptionalSome(opt_some) => {
            if let Some(val) = &opt_some.value {
                collect_parties_recursive(
                    package,
                    module,
                    val,
                    known_fields,
                    parties,
                    visited_values,
                    depth + 1,
                )?;
            }
        }
        _ => {}
    }

    Ok(())
}

/// Decodes all module surfaces for templates exported by the package.
pub fn extract_module_surfaces(package: &Package) -> Result<Vec<ModuleSurface>, DecodeError> {
    let mut surfaces = Vec::new();

    for module in &package.modules {
        let module_name = resolve_single_module_name(package, module)?;

        if module.templates.is_empty() {
            surfaces.push(ModuleSurface {
                name: module_name,
                templates: Vec::new(),
            });
            continue;
        }

        let mut templates = Vec::with_capacity(module.templates.len());

        for tmpl in &module.templates {
            let tmpl_name = resolve_interned_dotted_name(
                package,
                tmpl.tycon_interned_dname,
                "DefTemplate.tycon_interned_dname",
            )?;

            let param_name = if tmpl.param_interned_str >= 0 {
                resolve_interned_string(package, tmpl.param_interned_str, "param_interned_str")
                    .unwrap_or_else(|_| "this".to_string())
            } else {
                "this".to_string()
            };

            // 1. Extract record fields
            let fields = extract_record_fields(package, module, tmpl.tycon_interned_dname)?;
            let field_names: Vec<String> = fields.iter().map(|f| f.name.clone()).collect();

            // 2. Extract signatories
            let mut signatories = if let Some(sig) = &tmpl.signatories {
                let mut s = extract_parties_from_expr(package, module, sig, &field_names)?;
                if s.is_empty() {
                    s = extract_parties_from_expr(package, module, sig, &[])?;
                }
                s
            } else {
                Vec::new()
            };
            if signatories.is_empty()
                && tmpl.signatories.is_some()
                && !tmpl.choices.is_empty()
                && !field_names.is_empty()
            {
                signatories.push(field_names[0].clone());
            }
            if signatories.is_empty() {
                return Err(DecodeError::MissingSignatory(tmpl_name));
            }

            // 3. Extract observers
            let observers = if let Some(obs) = &tmpl.observers {
                let mut o = extract_parties_from_expr(package, module, obs, &field_names)?;
                if o.is_empty() {
                    o = extract_parties_from_expr(package, module, obs, &[])?;
                }
                o
            } else {
                Vec::new()
            };

            // 4. Precondition bytecode presence (unexecuted)
            let ensure = match &tmpl.precond {
                Some(p) => BytePresence::present(p.encoded_len()),
                None => BytePresence::absent(),
            };

            // 5. Choices
            let mut choices = Vec::with_capacity(tmpl.choices.len());
            for ch in &tmpl.choices {
                let ch_name = resolve_interned_string(
                    package,
                    ch.name_interned_str,
                    "TemplateChoice.name_interned_str",
                )?;

                let params = extract_choice_params(package, module, ch)?;
                let mut param_names: Vec<String> = params.iter().map(|p| p.name.clone()).collect();
                let mut all_fields = field_names.clone();
                all_fields.append(&mut param_names);

                let mut controllers = if let Some(ctrl) = &ch.controllers {
                    let mut c = extract_parties_from_expr(package, module, ctrl, &all_fields)?;
                    if c.is_empty() {
                        c = extract_parties_from_expr(package, module, ctrl, &[])?;
                    }
                    c
                } else {
                    Vec::new()
                };

                // Defense-in-depth: if Archive choice or compiled choice with helper controller delegates to signatories
                if controllers.is_empty()
                    && (ch_name == "Archive" || (ch.controllers.is_some() && ch.update.is_some()))
                {
                    controllers = signatories.clone();
                }

                if controllers.is_empty() {
                    return Err(DecodeError::UnresolvedChoiceController(ch_name));
                }

                let choice_observers = if let Some(cobs) = &ch.observers {
                    extract_parties_from_expr(package, module, cobs, &all_fields)?
                } else {
                    Vec::new()
                };

                let return_type = if let Some(ret) = &ch.ret_type {
                    resolve_surface_type(package, ret)?
                } else {
                    SurfaceType::Unit
                };
                let return_type_str = return_type.display_daml();

                let do_body = match &ch.update {
                    Some(u) => BytePresence::present(u.encoded_len()),
                    None => BytePresence::absent(),
                };

                choices.push(ChoiceDef {
                    name: ch_name,
                    consuming: ch.consuming,
                    controllers,
                    observers: choice_observers,
                    params,
                    return_type,
                    return_type_str,
                    do_body,
                });
            }

            templates.push(TemplateSurface {
                name: tmpl_name,
                param_name,
                fields,
                signatories,
                observers,
                choices,
                ensure,
            });
        }

        surfaces.push(ModuleSurface {
            name: module_name,
            templates,
        });
    }

    Ok(surfaces)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_minors() {
        assert!(SUPPORTED_LF2_MINORS.contains(&"1"));
        assert!(SUPPORTED_LF2_MINORS.contains(&"2"));
        assert!(SUPPORTED_LF2_MINORS.contains(&"3"));
        assert!(SUPPORTED_LF2_MINORS.contains(&"4"));
        assert!(!SUPPORTED_LF2_MINORS.contains(&"99"));
        assert!(!SUPPORTED_LF2_MINORS.contains(&"dev"));
    }
}
