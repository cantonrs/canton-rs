//! Machine: entering expressions, literals, and package, type-constructor and value resolution.

use lf_archive::proto::daml_lf_2;
use lf_archive::proto::daml_lf_2::{expr, Expr, Package, Type};
use lf_archive::{resolve_interned_dotted_name, resolve_interned_string};

use crate::env::{Env, TypeEnv};
use crate::eval_error::EvalError;
use crate::value::Value;
use crate::value_order::CtorRank;
use crate::world::parse_numeric;
use crate::{Control, Machine, SCRIPT_DANGEROUS_CAST};

impl<'a> Machine<'a> {
    pub(super) fn enter(&mut self, expr: Expr, env: Env, type_env: TypeEnv, package_id: String) {
        self.env = env;
        self.type_env = type_env;
        self.package_id = package_id;
        self.control = Control::Expr(expr);
    }

    pub(super) fn enter_run(
        &mut self,
        expr: Expr,
        env: Env,
        type_env: TypeEnv,
        package_id: String,
    ) {
        self.env = env;
        self.type_env = type_env;
        self.package_id = package_id;
        self.control = Control::Run(expr);
    }

    pub(super) fn package(&self) -> Result<&Package, EvalError> {
        self.world
            .packages
            .get(&self.package_id)
            .ok_or_else(|| EvalError::MissingDef {
                module: self.package_id.clone(),
                name: "package".to_string(),
            })
    }

    pub(super) fn literal(&self, lit: daml_lf_2::BuiltinLit) -> Result<Value, EvalError> {
        let Some(sum) = lit.sum else {
            return Err(EvalError::unsupported());
        };
        match sum {
            daml_lf_2::builtin_lit::Sum::Int64(number) => Ok(Value::Int64(number)),
            // A failure category (`failWithStatus`): carried as its enum number and only passed on to
            // FAIL_WITH_STATUS, which does not use it.
            daml_lf_2::builtin_lit::Sum::FailureCategory(category) => {
                Ok(Value::Int64(i64::from(category)))
            }
            daml_lf_2::builtin_lit::Sum::RoundingMode(mode) => {
                if (0..=7).contains(&mode) {
                    Ok(Value::Int64(i64::from(mode)))
                } else {
                    Err(EvalError::Archive(format!("unknown RoundingMode {mode}")))
                }
            }
            daml_lf_2::builtin_lit::Sum::TextInternedStr(index) => {
                let package = self.package()?;
                let text = resolve_interned_string(package, index, "BuiltinLit")
                    .map_err(|err| EvalError::Archive(err.to_string()))?;
                Ok(Value::Text(text))
            }
            daml_lf_2::builtin_lit::Sum::NumericInternedStr(index) => {
                let package = self.package()?;
                let text = resolve_interned_string(package, index, "BuiltinLit")
                    .map_err(|err| EvalError::Archive(err.to_string()))?;
                let (coeff, scale) = parse_numeric(&text)?;
                Ok(Value::Numeric { coeff, scale })
            }
            _ => Err(EvalError::unsupported()),
        }
    }

    /// The id of the package a module reference points to. `Self` (or no reference) is the package of the code
    /// being evaluated; a Daml-LF 2.1 package names another package by an interned string, a 2.3 package by an
    /// index into its import table (`Package.imports`).
    fn package_of_reference(
        &self,
        package: &Package,
        reference: Option<&daml_lf_2::SelfOrImportedPackageId>,
        context: &'static str,
    ) -> Result<String, EvalError> {
        use daml_lf_2::self_or_imported_package_id::Sum as Reference;
        match reference.and_then(|r| r.sum.as_ref()) {
            Some(Reference::SelfPackageId(_)) | None => Ok(self.package_id.clone()),
            Some(Reference::ImportedPackageIdInternedStr(index)) => {
                resolve_interned_string(package, *index, context)
                    .map_err(|err| EvalError::Archive(err.to_string()))
            }
            Some(Reference::PackageImportId(index)) => match &package.imports_sum {
                Some(daml_lf_2::package::ImportsSum::PackageImports(imports)) => {
                    usize::try_from(*index)
                        .ok()
                        .and_then(|i| imports.imported_packages.get(i))
                        .cloned()
                        .ok_or_else(|| {
                            EvalError::Archive(format!(
                                "{context}: import index {index} is outside the import table of {}",
                                imports.imported_packages.len()
                            ))
                        })
                }
                _ => Err(EvalError::Archive(format!(
                    "{context}: import index {index} but the package has no import table"
                ))),
            },
        }
    }

    /// Like `resolve_tycon_id` but also returns the package the type lives in. A `Self`
    /// package id means "the package of the code currently being evaluated", which is NOT
    /// necessarily the DAR's main package (we may be inside a dependency's value).
    pub(super) fn resolve_tycon_ref(
        &self,
        id: &daml_lf_2::TypeConId,
    ) -> Result<(String, String), EvalError> {
        let package = self.package()?;
        let module = id.module.as_ref().ok_or(EvalError::unsupported())?;
        let package_id =
            self.package_of_reference(package, module.package_id.as_ref(), "TypeConId.package")?;
        Ok((package_id, self.resolve_tycon_id(id)?))
    }

    pub(super) fn resolve_tycon_id(&self, id: &daml_lf_2::TypeConId) -> Result<String, EvalError> {
        let package = self.package()?;
        let module = id.module.as_ref().ok_or(EvalError::unsupported())?;
        let module_name = resolve_interned_dotted_name(
            package,
            module.module_name_interned_dname,
            "TypeConId.module",
        )
        .map_err(|err| EvalError::Archive(err.to_string()))?;
        let type_name =
            resolve_interned_dotted_name(package, id.name_interned_dname, "TypeConId.name")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
        Ok(format!("{module_name}:{type_name}"))
    }

    /// The rank of `constructor` in the enum or variant `id` (Speedy `constructorRank`).
    pub(super) fn constructor_rank(
        &self,
        id: &daml_lf_2::TypeConId,
        constructor: &str,
    ) -> Result<CtorRank, EvalError> {
        let package = self.package()?;
        let module = id.module.as_ref().ok_or(EvalError::unsupported())?;
        let package_id =
            self.package_of_reference(package, module.package_id.as_ref(), "TypeConId.package")?;
        let module_name = resolve_interned_dotted_name(
            package,
            module.module_name_interned_dname,
            "TypeConId.module",
        )
        .map_err(|err| EvalError::Archive(err.to_string()))?;
        let type_name =
            resolve_interned_dotted_name(package, id.name_interned_dname, "TypeConId.name")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
        self.world
            .constructor_rank(&package_id, &module_name, &type_name, constructor)
    }

    pub(super) fn resolve_type_tycon(&self, ty: &Type) -> Result<String, EvalError> {
        let package = self.package()?;
        match ty.sum.as_ref().ok_or(EvalError::unsupported())? {
            daml_lf_2::r#type::Sum::Con(con) => {
                let id = con.tycon.as_ref().ok_or(EvalError::unsupported())?;
                let plain = self.resolve_tycon_id(id)?;
                // [CANTON-NOTE: SEMANTICS] An exception type is named by `Module:Name` unless another loaded package defines
                // an exception of the same name; then the package id is part of the name, so `FromAnyException` and the
                // `message` lookup tell the two apart (U-8).
                if self.world.exception_owners(&plain)?.len() > 1 {
                    let module = id.module.as_ref().ok_or(EvalError::unsupported())?;
                    let package_id = self.package_of_reference(
                        package,
                        module.package_id.as_ref(),
                        "TypeConId.package",
                    )?;
                    return Ok(format!("{package_id}#{plain}"));
                }
                Ok(plain)
            }
            daml_lf_2::r#type::Sum::InternedType(idx) => {
                let interned = package
                    .interned_types
                    .get(*idx as usize)
                    .ok_or(EvalError::unsupported())?;
                self.resolve_type_tycon(interned)
            }
            _ => Err(EvalError::unsupported()),
        }
    }

    /// The package, cache key `(package id, module, name)` and expression of a top-level value.
    #[allow(
        clippy::type_complexity,
        reason = "protocol or ledger hook signature uses an inline composite type"
    )] // [CANTON-NOTE: STYLE] a one-off triple, named only in this signature
    pub(super) fn locate_val(
        &self,
        id: &daml_lf_2::ValueId,
    ) -> Result<(String, (String, String, String), Expr), EvalError> {
        let package = self.package()?;
        let module = id.module.as_ref().ok_or(EvalError::unsupported())?;
        let package_id =
            self.package_of_reference(package, module.package_id.as_ref(), "ValueId.package")?;
        let module_name = resolve_interned_dotted_name(
            package,
            module.module_name_interned_dname,
            "ValueId.module",
        )
        .map_err(|err| EvalError::Archive(err.to_string()))?;
        let value_name =
            resolve_interned_dotted_name(package, id.name_interned_dname, "ValueId.name")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
        let key = (package_id.clone(), module_name.clone(), value_name.clone());
        if module_name == "Daml.Script.Internal.LowLevel" && value_name == "dangerousCast" {
            // [CANTON-NOTE: SEMANTICS] The script runner's own replacement: the identity on values (the values of a script are
            // `LedgerValue`s that are really the speedy values of the types they stand for).
            let cast = Expr {
                sum: Some(expr::Sum::Builtin(SCRIPT_DANGEROUS_CAST)),
                ..Default::default()
            };
            return Ok((package_id, key, cast));
        }
        let expr = self
            .world
            .find_expr(&package_id, &module_name, &value_name)?;
        Ok((package_id, key, expr))
    }
}

/// Name of an `Update` variant, for the "not implemented" error (`ExerciseByKey`, `FetchByKey`, ...).
pub(super) fn update_form_name(sum: &daml_lf_2::update::Sum) -> &'static str {
    use daml_lf_2::update::Sum;
    match sum {
        Sum::Pure(_) => "Pure",
        Sum::Block(_) => "Block",
        Sum::Create(_) => "Create",
        Sum::CreateInterface(_) => "CreateInterface",
        Sum::Exercise(_) => "Exercise",
        Sum::ExerciseInterface(_) => "ExerciseInterface",
        Sum::ExerciseByKey(_) => "ExerciseByKey",
        Sum::Fetch(_) => "Fetch",
        Sum::FetchInterface(_) => "FetchInterface",
        Sum::FetchByKey(_) => "FetchByKey",
        Sum::QueryNByKey(_) => "QueryNByKey",
        Sum::LedgerTimeLt(_) => "LedgerTimeLt",
        Sum::UnpackTemplate(_) => "UnpackTemplate",
        Sum::UnpackInterface(_) => "UnpackInterface",
        Sum::EmbedExpr(_) => "EmbedExpr",
        Sum::TryCatch(_) => "TryCatch",
        Sum::GetTime(_) => "GetTime",
    }
}

/// The id of the package a module reference found in `package` (whose own id is `self_id`) points to.
pub(crate) fn package_of_reference_in(
    package: &Package,
    self_id: &str,
    reference: Option<&daml_lf_2::SelfOrImportedPackageId>,
    context: &'static str,
) -> Result<String, EvalError> {
    use daml_lf_2::self_or_imported_package_id::Sum as Reference;
    match reference.and_then(|r| r.sum.as_ref()) {
        Some(Reference::SelfPackageId(_)) | None => Ok(self_id.to_string()),
        Some(Reference::ImportedPackageIdInternedStr(index)) => {
            resolve_interned_string(package, *index, context)
                .map_err(|err| EvalError::Archive(err.to_string()))
        }
        Some(Reference::PackageImportId(index)) => match &package.imports_sum {
            Some(daml_lf_2::package::ImportsSum::PackageImports(imports)) => {
                usize::try_from(*index)
                    .ok()
                    .and_then(|i| imports.imported_packages.get(i))
                    .cloned()
                    .ok_or_else(|| {
                        EvalError::Archive(format!(
                            "{context}: import index {index} is outside the import table of {}",
                            imports.imported_packages.len()
                        ))
                    })
            }
            _ => Err(EvalError::Archive(format!(
                "{context}: import index {index} but the package has no import table"
            ))),
        },
    }
}

/// `(package id, "Module:Name")` of a type constructor id found in `package` (whose own id is `self_id`).
pub(crate) fn resolve_con_in(
    package: &Package,
    self_id: &str,
    id: &daml_lf_2::TypeConId,
) -> Result<(String, String), EvalError> {
    let module = id.module.as_ref().ok_or(EvalError::unsupported())?;
    let package_id = package_of_reference_in(
        package,
        self_id,
        module.package_id.as_ref(),
        "TypeConId.package",
    )?;
    let module_name = resolve_interned_dotted_name(
        package,
        module.module_name_interned_dname,
        "TypeConId.module",
    )
    .map_err(|err| EvalError::Archive(err.to_string()))?;
    let name = resolve_interned_dotted_name(package, id.name_interned_dname, "TypeConId.name")
        .map_err(|err| EvalError::Archive(err.to_string()))?;
    Ok((package_id, format!("{module_name}:{name}")))
}

pub(crate) fn split_module_name(id: &str) -> Result<(&str, &str), EvalError> {
    id.split_once(':')
        .ok_or_else(|| EvalError::Host(format!("id {id} is not Module:Name")))
}

/// The instance a template declares for an interface (`implements`).
pub(crate) struct InterfaceInstance<'a> {
    /// Package that defines the template (its interned tables resolve the instance's names).
    pub(crate) package: &'a Package,
    pub(crate) template: &'a daml_lf_2::DefTemplate,
    pub(crate) body: &'a daml_lf_2::InterfaceInstanceBody,
}
