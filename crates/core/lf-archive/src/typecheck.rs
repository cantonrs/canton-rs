//! Full Canton 3.7.2-equivalent Daml-LF v2 package validator (U-11, AT-L01).
//!
//! Mirrors Canton's `com.digitalasset.daml.lf.validation.Validation`:
//! 1. `DependencyVersion`: a package cannot depend on a package with a higher LF minor version.
//! 2. `Collision`: case-insensitive dotted-name uniqueness across modules, data types, fields,
//!    variant/enum constructors, interfaces, and choices (preserving Haskell's single
//!    `(variant_constructor, record)` exception).
//! 3. `Recursion`: acyclicity of intra-package module imports and type-synonym definitions.
//! 4. `Typing`: full kind checking (`*`, `Nat`, `k1 -> k2`, rejecting `Nat` on RHS of arrows),
//!    type-synonym expansion, capture-avoiding `TypeSubst`, de-Bruijn `AlphaEquiv`, exhaustive
//!    case pattern checking, all builtin functions/literals/constructors, all `Update` forms,
//!    exceptions, templates, keys, and interfaces (`requires` closure, method/view checks).
//! 5. `Serializability`: `serializable` data types, template payloads/choices/keys, exceptions,
//!    interface views/choices.

mod builtins;
mod decode;
mod dependencies;
mod expr_typing;
mod module_checks;
mod types;
mod typing_env;
mod update_typing;

pub(crate) use decode::{
    decode_choice, decode_data_type, decode_type, decode_type_params, dotted_string, err,
    interned_str, resolve_type_con_id, DecodedDataCons, DecodedDataType,
};
pub(crate) use types::{Ident, LKind, LType};

use std::collections::{BTreeSet, HashMap};

use crate::proto::daml_lf_2::Package;

use decode::{
    DecodedException, DecodedImplements, DecodedInterface, DecodedKey, DecodedTemplate,
    DecodedTypeSyn, DecodedValue,
};

/// `DA.Types:Tuple2` stable package identifier (`StablePackagesV2.Tuple2` in Canton 3.7.2).
const STABLE_TUPLE2_PKG: &str = "5aee9b21b8e9a4c4975b5f4c4198e6e6e8469df49e2010820e792f393db870f4";

/// Maximum recursion guard for resolving interned tables and expanding type synonyms.
const MAX_RESOLVE_DEPTH: usize = 256;

/// A validation error found in a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeError {
    pub kind: &'static str,
    pub package_id: String,
    pub detail: String,
}

impl std::fmt::Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} in package {}: {}",
            self.kind, self.package_id, self.detail
        )
    }
}

impl std::error::Error for TypeError {}

#[derive(Debug, Clone)]
enum NamedEntityKind {
    ModDef,
    RecDef,
    VarDef,
    EnumDef,
    SynDef,
    Field,
    VarCon,
    EnumCon,
    Interface,
    Choice,
    InterfaceChoice,
}

#[derive(Debug, Clone)]
struct NamedEntity {
    kind: NamedEntityKind,
    pretty: String,
    upper_segments: Vec<String>,
}

struct Validator<'a> {
    packages: &'a HashMap<String, Package>,
    versions: &'a HashMap<String, String>,
    data_types: HashMap<Ident, DecodedDataType>,
    type_syns: HashMap<Ident, DecodedTypeSyn>,
    values: HashMap<Ident, DecodedValue>,
    templates: HashMap<Ident, DecodedTemplate<'a>>,
    interfaces: HashMap<Ident, DecodedInterface<'a>>,
    exceptions: HashMap<Ident, DecodedException<'a>>,
}

fn check_kind(pkg_id: &str, kind: &LKind) -> Result<(), TypeError> {
    let mut stack = vec![];
    let mut cur = kind;
    loop {
        match cur {
            LKind::Arrow(param, result) => {
                if matches!(**result, LKind::Nat) {
                    return Err(err(
                        pkg_id,
                        "ENatKindRightOfArrow",
                        format!("invalid kind {}", kind.pretty()),
                    ));
                }
                stack.push(&**result);
                cur = param;
            }
            LKind::Star | LKind::Nat => {
                if let Some(next) = stack.pop() {
                    cur = next;
                } else {
                    return Ok(());
                }
            }
        }
    }
}

fn topo_check<'a>(
    pkg_id: &str,
    err_kind: &'static str,
    nodes: impl Iterator<Item = &'a str>,
    edges: &HashMap<String, BTreeSet<String>>,
) -> Result<(), TypeError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Visiting,
        Visited,
    }
    fn dfs(
        pkg_id: &str,
        err_kind: &'static str,
        node: &str,
        edges: &HashMap<String, BTreeSet<String>>,
        state: &mut HashMap<String, State>,
    ) -> Result<(), TypeError> {
        match state.get(node).copied() {
            Some(State::Visited) => return Ok(()),
            Some(State::Visiting) => {
                return Err(err(
                    pkg_id,
                    err_kind,
                    format!("dependency cycle involving {node}"),
                ));
            }
            None => {}
        }
        state.insert(node.to_string(), State::Visiting);
        if let Some(deps) = edges.get(node) {
            for next in deps {
                dfs(pkg_id, err_kind, next, edges, state)?;
            }
        }
        state.insert(node.to_string(), State::Visited);
        Ok(())
    }

    let mut state = HashMap::new();
    for node in nodes {
        dfs(pkg_id, err_kind, node, edges, &mut state)?;
    }
    Ok(())
}

impl<'a> Validator<'a> {
    fn new(
        packages: &'a HashMap<String, Package>,
        versions: &'a HashMap<String, String>,
    ) -> Result<Self, TypeError> {
        let mut data_types = HashMap::new();
        let mut type_syns = HashMap::new();
        let mut values = HashMap::new();
        let mut templates = HashMap::new();
        let mut interfaces = HashMap::new();
        let mut exceptions = HashMap::new();

        let mut pkg_ids: Vec<&String> = packages.keys().collect();
        pkg_ids.sort();

        for pkg_id in pkg_ids {
            let pkg = &packages[pkg_id];
            for module in &pkg.modules {
                let mod_name =
                    dotted_string(pkg_id, pkg, module.name_interned_dname, "Module.name")?;

                for def in &module.data_types {
                    let (name, data_type) = decode_data_type(pkg_id, pkg, &mod_name, def)?;
                    data_types.insert(
                        Ident {
                            pkg: pkg_id.clone(),
                            module: mod_name.clone(),
                            name,
                        },
                        data_type,
                    );
                }

                for syn in &module.synonyms {
                    let name =
                        dotted_string(pkg_id, pkg, syn.name_interned_dname, "DefTypeSyn.name")?;
                    let params = decode_type_params(pkg_id, pkg, &syn.params)?;
                    let replacement = decode_type(pkg_id, pkg, syn.r#type.as_ref(), 0)?;
                    type_syns.insert(
                        Ident {
                            pkg: pkg_id.clone(),
                            module: mod_name.clone(),
                            name,
                        },
                        DecodedTypeSyn {
                            params,
                            replacement,
                        },
                    );
                }

                for val in &module.values {
                    let nwt = val.name_with_type.as_ref().ok_or_else(|| {
                        err(
                            pkg_id,
                            "EUnknownDefinition",
                            "DefValue missing name_with_type",
                        )
                    })?;
                    let name =
                        dotted_string(pkg_id, pkg, nwt.name_interned_dname, "DefValue.name")?;
                    let typ = decode_type(pkg_id, pkg, nwt.r#type.as_ref(), 0)?;
                    values.insert(
                        Ident {
                            pkg: pkg_id.clone(),
                            module: mod_name.clone(),
                            name,
                        },
                        DecodedValue { typ },
                    );
                }

                for tmpl in &module.templates {
                    let name =
                        dotted_string(pkg_id, pkg, tmpl.tycon_interned_dname, "DefTemplate.tycon")?;
                    let param =
                        interned_str(pkg_id, pkg, tmpl.param_interned_str, "DefTemplate.param")?
                            .to_string();
                    let mut choices = Vec::with_capacity(tmpl.choices.len());
                    for ch in &tmpl.choices {
                        choices.push(decode_choice(pkg_id, pkg, ch)?);
                    }
                    let key = if let Some(k) = &tmpl.key {
                        Some(DecodedKey {
                            typ: decode_type(pkg_id, pkg, k.r#type.as_ref(), 0)?,
                            body: k.key_expr.as_ref(),
                            maintainers: k.maintainers.as_ref(),
                        })
                    } else {
                        None
                    };
                    let mut implements = Vec::with_capacity(tmpl.implements.len());
                    for imp in &tmpl.implements {
                        let iface = resolve_type_con_id(pkg_id, pkg, imp.interface.as_ref())?;
                        let mut methods = Vec::new();
                        let view = imp.body.as_ref().and_then(|b| b.view.as_ref());
                        if let Some(body) = &imp.body {
                            for m in &body.methods {
                                let mname = interned_str(
                                    pkg_id,
                                    pkg,
                                    m.method_interned_name,
                                    "InterfaceInstance.method",
                                )?
                                .to_string();
                                methods.push((mname, m.value.as_ref()));
                            }
                        }
                        implements.push(DecodedImplements {
                            iface,
                            view,
                            methods,
                        });
                    }
                    templates.insert(
                        Ident {
                            pkg: pkg_id.clone(),
                            module: mod_name.clone(),
                            name,
                        },
                        DecodedTemplate {
                            param,
                            precond: tmpl.precond.as_ref(),
                            signatories: tmpl.signatories.as_ref(),
                            observers: tmpl.observers.as_ref(),
                            choices,
                            key,
                            implements,
                        },
                    );
                }

                for iface in &module.interfaces {
                    let name = dotted_string(
                        pkg_id,
                        pkg,
                        iface.tycon_interned_dname,
                        "DefInterface.tycon",
                    )?;
                    let param =
                        interned_str(pkg_id, pkg, iface.param_interned_str, "DefInterface.param")?
                            .to_string();
                    let view = decode_type(pkg_id, pkg, iface.view.as_ref(), 0)?;
                    let mut requires = Vec::with_capacity(iface.requires.len());
                    for req in &iface.requires {
                        requires.push(resolve_type_con_id(pkg_id, pkg, Some(req))?);
                    }
                    let mut methods = Vec::with_capacity(iface.methods.len());
                    for m in &iface.methods {
                        let mname = interned_str(
                            pkg_id,
                            pkg,
                            m.method_interned_name,
                            "InterfaceMethod.name",
                        )?
                        .to_string();
                        let mtype = decode_type(pkg_id, pkg, m.r#type.as_ref(), 0)?;
                        methods.push((mname, mtype));
                    }
                    let mut choices = Vec::with_capacity(iface.choices.len());
                    for ch in &iface.choices {
                        choices.push(decode_choice(pkg_id, pkg, ch)?);
                    }
                    interfaces.insert(
                        Ident {
                            pkg: pkg_id.clone(),
                            module: mod_name.clone(),
                            name,
                        },
                        DecodedInterface {
                            requires,
                            param,
                            view,
                            methods,
                            choices,
                        },
                    );
                }

                for exc in &module.exceptions {
                    let name =
                        dotted_string(pkg_id, pkg, exc.name_interned_dname, "DefException.name")?;
                    exceptions.insert(
                        Ident {
                            pkg: pkg_id.clone(),
                            module: mod_name.clone(),
                            name,
                        },
                        DecodedException {
                            message: exc.message.as_ref(),
                        },
                    );
                }
            }
        }

        Ok(Self {
            packages,
            versions,
            data_types,
            type_syns,
            values,
            templates,
            interfaces,
            exceptions,
        })
    }

    fn is_dev(&self, pkg_id: &str) -> bool {
        self.versions
            .get(pkg_id)
            .is_some_and(|v| v == "2.dev" || v == "dev")
    }
}

/// Validates a set of Daml-LF packages without explicit LF version metadata (all unknown versions
/// default to LF `2.4`, non-dev).
pub fn check_packages(packages: &HashMap<String, Package>) -> Result<(), TypeError> {
    let empty_versions = HashMap::new();
    check_packages_with_versions(packages, &empty_versions)
}

/// Validates a set of Daml-LF packages with explicit per-package LF version strings (e.g. `"2.1"`,
/// `"2.3"`, `"2.dev"`), used for `DependencyVersion` checks and `2.dev` feature gating (`Any`/`TypeRep`).
pub fn check_packages_with_versions(
    packages: &HashMap<String, Package>,
    versions: &HashMap<String, String>,
) -> Result<(), TypeError> {
    // [CANTON-NOTE: INVARIANT] Run on a 16 MiB stack so unoptimized debug builds or 2 MiB
    // Tokio / `cargo test` worker threads cannot stack-overflow on deep Splice expressions.
    std::thread::scope(|s| {
        match std::thread::Builder::new()
            .name("lf-typecheck".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn_scoped(s, || check_packages_with_versions_inner(packages, versions))
        {
            Ok(handle) => match handle.join() {
                Ok(res) => res,
                Err(_) => Err(err(
                    "",
                    "EValidationPanic",
                    "typechecker worker thread panicked",
                )),
            },
            Err(_) => check_packages_with_versions_inner(packages, versions),
        }
    })
}

fn check_packages_with_versions_inner(
    packages: &HashMap<String, Package>,
    versions: &HashMap<String, String>,
) -> Result<(), TypeError> {
    let validator = Validator::new(packages, versions)?;
    let mut ids: Vec<&String> = packages.keys().collect();
    ids.sort();
    for id in ids {
        validator.check_package(id, &packages[id])?;
    }
    Ok(())
}
