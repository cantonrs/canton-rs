//! Daml-LF archive loading (`World`), top-level value evaluation cache, and CLI argument/numeric codecs.

use std::collections::HashMap;
use std::path::Path;

use lf_archive::proto::daml_lf_2::{self, Expr, Package};
use lf_archive::{
    load_dar_file, load_dar_file_allow_dev, resolve_interned_dotted_name, resolve_interned_string,
    resolve_single_module_name, LoadedDar,
};

use crate::{
    constructor_order, resolve_con_in, split_module_name, Control, CtorRank, Env, EvalError,
    InterfaceInstance, Kont, Ledger, Machine, UpdateHost, Value,
};

pub struct World {
    pub(crate) main_package_id: String,
    pub(crate) packages: HashMap<String, Package>,
    /// Top-level values already evaluated, by `(package id, module, name)` (S-SCRIPT-002).
    ///
    /// [CANTON-NOTE: SEMANTICS] A top-level value of Daml-LF is closed and pure, and Speedy evaluates each one once and keeps it
    /// (`SEVal` caching). Without this, every reference re-evaluated it: the type-class dictionaries of `Script` refer to each other,
    /// so `mapA` over n elements cost about 4^n (measured: 3 elements 0.13 s, 6 elements 8.6 s, 12 never finished).
    pub(crate) val_cache: ValCache,
    /// The constructors of each enum or variant looked up so far, by `(package id, module, type)`.
    pub(crate) ctor_cache: CtorCache,
}

/// The constructor names of enum and variant types in declaration order ([`World::constructor_rank`]); derived from
/// the packages, so cloning or comparing a world ignores it.
#[derive(Default)]
pub struct CtorCache(std::sync::Mutex<HashMap<DataTypeRef, std::sync::Arc<Vec<String>>>>);

/// `(package id, module, type name)` of a data type.
type DataTypeRef = (String, String, String);

/// The cache of evaluated top-level values ([`World`]); not part of what a world *is*, so cloning or comparing ignores it.
#[derive(Default)]
pub struct ValCache(std::sync::Mutex<HashMap<(String, String, String), Value>>);

impl ValCache {
    pub(crate) fn get(&self, key: &(String, String, String)) -> Option<Value> {
        self.0.lock().ok()?.get(key).cloned()
    }

    pub(crate) fn put(&self, key: (String, String, String), value: Value) {
        if let Ok(mut cache) = self.0.lock() {
            cache.insert(key, value);
        }
    }

    pub(crate) fn clear(&self) {
        if let Ok(mut cache) = self.0.lock() {
            cache.clear();
        }
    }
}

impl World {
    pub fn open(path: &Path) -> Result<Self, EvalError> {
        Self::from_loaded(load_dar_file(path).map_err(|err| EvalError::Archive(err.to_string()))?)
    }

    /// Opens a DAR permitting Daml-LF `2.dev` minor versions (used for `2.dev`-only language oracle tests).
    pub fn open_allow_dev(path: &Path) -> Result<Self, EvalError> {
        Self::from_loaded(
            load_dar_file_allow_dev(path).map_err(|err| EvalError::Archive(err.to_string()))?,
        )
    }

    /// Builds a `World` directly from a pre-parsed [`LoadedDar`].
    pub fn from_loaded(loaded: LoadedDar) -> Result<Self, EvalError> {
        constructor_order::register_packages(&loaded.packages);
        Ok(Self {
            main_package_id: loaded.archive.main_package_id,
            packages: loaded.packages,
            val_cache: ValCache::default(),
            ctor_cache: CtorCache::default(),
        })
    }

    /// Builds a `World` by cloning packages from a borrowed pre-parsed [`LoadedDar`]
    /// without re-reading or re-decoding `.dalf` entries from disk/ZIP.
    pub fn from_loaded_ref(loaded: &LoadedDar) -> Result<Self, EvalError> {
        constructor_order::register_packages(&loaded.packages);
        Ok(Self {
            main_package_id: loaded.archive.main_package_id.clone(),
            packages: loaded.packages.clone(),
            val_cache: ValCache::default(),
            ctor_cache: CtorCache::default(),
        })
    }

    /// Adds all packages from a pre-parsed [`LoadedDar`] without changing `main_package_id`.
    pub fn add_loaded_dar(&mut self, loaded: &LoadedDar) -> Vec<String> {
        constructor_order::register_packages(&loaded.packages);
        let mut ids: Vec<String> = loaded.packages.keys().cloned().collect();
        ids.sort();
        for (id, pkg) in &loaded.packages {
            self.packages
                .entry(id.clone())
                .or_insert_with(|| pkg.clone());
        }
        // packages are only added, never replaced, so cached values stay right; dropped anyway to keep the cache bounded by use
        self.val_cache.clear();
        ids
    }

    /// Adds all packages from another DAR archive into this evaluation world without changing `main_package_id`.
    pub fn add_dar(&mut self, path: &Path) -> Result<Vec<String>, EvalError> {
        let loaded = load_dar_file(path).map_err(|err| EvalError::Archive(err.to_string()))?;
        Ok(self.add_loaded_dar(&loaded))
    }

    /// Whether `package_id` is loaded in this world.
    pub fn has_package(&self, package_id: &str) -> bool {
        self.packages.contains_key(package_id)
    }

    /// Resolves the package id defining `module:name` (trying `package_hint`, then `main_package_id`, then all loaded packages).
    pub fn template_package(
        &self,
        package_hint: Option<&str>,
        module: &str,
        name: &str,
    ) -> Option<String> {
        if let Some(pkg) = package_hint {
            if self.packages.contains_key(pkg)
                && self.template_exists(pkg, module, name).unwrap_or(false)
            {
                return Some(pkg.to_string());
            }
        }
        if self
            .template_exists(&self.main_package_id, module, name)
            .unwrap_or(false)
        {
            return Some(self.main_package_id.clone());
        }
        self.package_ids()
            .into_iter()
            .find(|id| self.template_exists(id, module, name).unwrap_or(false))
    }

    /// The ids of every package of the DAR (the main one and its dependencies).
    pub fn package_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.packages.keys().cloned().collect();
        ids.sort();
        ids
    }

    pub fn main_package_id(&self) -> &str {
        &self.main_package_id
    }

    pub fn eval(&self, module: &str, name: &str, args: &[Value]) -> Result<Value, EvalError> {
        let expr = self.find_expr(&self.main_package_id, module, name)?;
        let mut machine = Machine {
            world: self,
            control: Control::Expr(expr),
            env: Env::new(),
            type_env: Vec::new(),
            package_id: self.main_package_id.clone(),
            kont: Vec::new(),
            steps: 0,
            host: None,
            ledger: Ledger::Off,
        };
        if !args.is_empty() {
            machine.kont.push(Kont::ApplyValues {
                args: args.to_vec(),
            });
        }
        machine.run_closed()
    }

    pub fn eval_template_precond(
        &self,
        module: &str,
        template: &str,
        this_val: &Value,
    ) -> Result<bool, EvalError> {
        // Callers of this main-package shortcut have no enclosing `try`, so an escaped exception is final.
        self.eval_template_precond_in(&self.main_package_id, module, template, this_val)
            .map_err(EvalError::into_uncaught)
    }

    /// The `_in` family takes an explicit package id. Nested exercises can target a
    /// template from a dependency package, so the main-package shortcuts above are not
    /// enough for them; they remain as thin wrappers for existing callers.
    pub fn eval_template_precond_in(
        &self,
        package_id: &str,
        module: &str,
        template: &str,
        this_val: &Value,
    ) -> Result<bool, EvalError> {
        let (package, tmpl) = self.find_template(package_id, module, template)?;
        let Some(precond) = &tmpl.precond else {
            return Ok(true);
        };
        let param_name =
            resolve_interned_string(package, tmpl.param_interned_str, "DefTemplate.param")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
        let mut machine = Machine {
            world: self,
            control: Control::Expr(precond.clone()),
            env: Env::from(vec![(param_name, this_val.clone())]),
            type_env: Vec::new(),
            package_id: package_id.to_string(),
            kont: Vec::new(),
            steps: 0,
            host: None,
            ledger: Ledger::On,
        };
        // [CANTON-NOTE: SEMANTICS] damlc compiles `ensure` so that a false precondition *throws* `PreconditionFailed`
        // (with the payload in its message) instead of returning `False`. That exception must stay a catchable
        // `Thrown` here, not be flattened to `UnhandledException`, so that a Daml `try` around a `create` can catch it
        // (measured on JVM 3.7.2: `rbEnsure` in tests/oracle/key-diff). The root (`Engine::atomically`) flattens it.
        match machine.run()? {
            Value::Bool(b) => Ok(b),
            _ => Err(EvalError::unsupported()),
        }
    }

    pub fn eval_template_signatories(
        &self,
        module: &str,
        template: &str,
        this_val: &Value,
    ) -> Result<Vec<String>, EvalError> {
        self.eval_template_signatories_in(&self.main_package_id, module, template, this_val)
    }

    pub fn eval_template_signatories_in(
        &self,
        package_id: &str,
        module: &str,
        template: &str,
        this_val: &Value,
    ) -> Result<Vec<String>, EvalError> {
        let (package, tmpl) = self.find_template(package_id, module, template)?;
        let expr = tmpl
            .signatories
            .as_ref()
            .ok_or_else(|| EvalError::MissingDef {
                module: module.to_string(),
                name: format!("{template}.signatories"),
            })?;
        let param_name =
            resolve_interned_string(package, tmpl.param_interned_str, "DefTemplate.param")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
        self.eval_party_list(
            package_id,
            expr.clone(),
            Env::from(vec![(param_name, this_val.clone())]),
        )
    }

    pub fn eval_template_observers(
        &self,
        module: &str,
        template: &str,
        this_val: &Value,
    ) -> Result<Vec<String>, EvalError> {
        self.eval_template_observers_in(&self.main_package_id, module, template, this_val)
    }

    pub fn eval_template_observers_in(
        &self,
        package_id: &str,
        module: &str,
        template: &str,
        this_val: &Value,
    ) -> Result<Vec<String>, EvalError> {
        let (package, tmpl) = self.find_template(package_id, module, template)?;
        let Some(expr) = &tmpl.observers else {
            return Ok(Vec::new());
        };
        let param_name =
            resolve_interned_string(package, tmpl.param_interned_str, "DefTemplate.param")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
        self.eval_party_list(
            package_id,
            expr.clone(),
            Env::from(vec![(param_name, this_val.clone())]),
        )
    }

    /// Whether the template declares a key, answered from the template alone (no contract arguments are decoded).
    pub fn template_has_key(
        &self,
        package_id: &str,
        module: &str,
        template: &str,
    ) -> Result<bool, EvalError> {
        let (_, tmpl) = self.find_template(package_id, module, template)?;
        Ok(tmpl.key.is_some())
    }

    /// The key of a contract of a template with a key, and its maintainers: `key_expr` evaluated with `this` bound,
    /// then the `maintainers` function applied to that key. `None` if the template has no key.
    pub fn eval_template_key_in(
        &self,
        package_id: &str,
        module: &str,
        template: &str,
        this_val: &Value,
    ) -> Result<Option<(Value, Vec<String>)>, EvalError> {
        let (package, tmpl) = self.find_template(package_id, module, template)?;
        let Some(def) = &tmpl.key else {
            return Ok(None);
        };
        let key_expr = def.key_expr.clone().ok_or(EvalError::unsupported())?;
        let param_name =
            resolve_interned_string(package, tmpl.param_interned_str, "DefTemplate.param")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
        let key = self.eval_expr_in(
            package_id,
            key_expr,
            Env::from(vec![(param_name, this_val.clone())]),
        )?;
        let maintainers = self.eval_key_maintainers_in(package_id, module, template, &key)?;
        Ok(Some((key, maintainers)))
    }

    /// The maintainers function of a template's key applied to `key`.
    pub fn eval_key_maintainers_in(
        &self,
        package_id: &str,
        module: &str,
        template: &str,
        key: &Value,
    ) -> Result<Vec<String>, EvalError> {
        let (_, tmpl) = self.find_template(package_id, module, template)?;
        let def = tmpl.key.as_ref().ok_or(EvalError::unsupported())?;
        let maintainers = def.maintainers.clone().ok_or(EvalError::unsupported())?;
        let func = self.eval_expr_in(package_id, maintainers, Env::new())?;
        let mut machine = Machine {
            world: self,
            control: Control::Value(func),
            env: Env::new(),
            type_env: Vec::new(),
            package_id: package_id.to_string(),
            kont: vec![Kont::ApplyValues {
                args: vec![key.clone()],
            }],
            steps: 0,
            host: None,
            ledger: Ledger::On,
        };
        match machine.run_closed()? {
            Value::List(items) => items
                .iter()
                .map(|item| match item {
                    Value::Party(p) => Ok(p.clone()),
                    _ => Err(EvalError::unsupported()),
                })
                .collect(),
            _ => Err(EvalError::unsupported()),
        }
    }

    /// The rank of `constructor` in the enum or variant `module:name` of `package_id` (Speedy `constructorRank`).
    pub(crate) fn constructor_rank(
        &self,
        package_id: &str,
        module: &str,
        name: &str,
        constructor: &str,
    ) -> Result<CtorRank, EvalError> {
        let key = (package_id.to_string(), module.to_string(), name.to_string());
        let cached = self
            .ctor_cache
            .0
            .lock()
            .ok()
            .and_then(|cache| cache.get(&key).cloned());
        let constructors = match cached {
            Some(constructors) => constructors,
            None => {
                let constructors =
                    std::sync::Arc::new(self.constructors(package_id, module, name)?);
                if let Ok(mut cache) = self.ctor_cache.0.lock() {
                    cache.insert(key, std::sync::Arc::clone(&constructors));
                }
                constructors
            }
        };
        constructors
            .iter()
            .position(|c| c == constructor)
            .and_then(|rank| u32::try_from(rank).ok())
            .map(CtorRank::known)
            .ok_or_else(|| {
                EvalError::Archive(format!("{module}:{name} has no constructor {constructor}"))
            })
    }

    /// The constructor names of the enum or variant `module:name` of `package_id`, in declaration order.
    fn constructors(
        &self,
        package_id: &str,
        module: &str,
        name: &str,
    ) -> Result<Vec<String>, EvalError> {
        let archive = |err: lf_archive::DecodeError| EvalError::Archive(err.to_string());
        let package = self
            .packages
            .get(package_id)
            .ok_or_else(|| EvalError::MissingDef {
                module: package_id.to_string(),
                name: "package".to_string(),
            })?;
        for candidate in &package.modules {
            if resolve_single_module_name(package, candidate).map_err(archive)? != module {
                continue;
            }
            for data in &candidate.data_types {
                let data_name = resolve_interned_dotted_name(
                    package,
                    data.name_interned_dname,
                    "DefDataType.name",
                )
                .map_err(archive)?;
                if data_name != name {
                    continue;
                }
                return match &data.data_cons {
                    Some(daml_lf_2::def_data_type::DataCons::Variant(fields)) => fields
                        .fields
                        .iter()
                        .map(|f| {
                            resolve_interned_string(
                                package,
                                f.field_interned_str,
                                "variant constructor",
                            )
                            .map_err(archive)
                        })
                        .collect(),
                    Some(daml_lf_2::def_data_type::DataCons::Enum(e)) => e
                        .constructors_interned_str
                        .iter()
                        .map(|i| {
                            resolve_interned_string(package, *i, "enum constructor")
                                .map_err(archive)
                        })
                        .collect(),
                    _ => Err(EvalError::Archive(format!(
                        "{module}:{name} is not a variant or an enum"
                    ))),
                };
            }
        }
        Err(EvalError::MissingDef {
            module: module.to_string(),
            name: name.to_string(),
        })
    }

    /// The ids of the packages that define an exception type `Module:Name`, in id order.
    pub(crate) fn exception_owners(&self, tycon: &str) -> Result<Vec<String>, EvalError> {
        let Some((module, name)) = tycon.split_once(':') else {
            return Ok(Vec::new());
        };
        let mut ids: Vec<&String> = self.packages.keys().collect();
        ids.sort();
        let mut owners = Vec::new();
        for id in ids {
            let package = &self.packages[id];
            for candidate in &package.modules {
                let module_name = resolve_single_module_name(package, candidate)
                    .map_err(|err| EvalError::Archive(err.to_string()))?;
                if module_name != module {
                    continue;
                }
                for def in &candidate.exceptions {
                    let def_name = resolve_interned_dotted_name(
                        package,
                        def.name_interned_dname,
                        "DefException.name",
                    )
                    .map_err(|err| EvalError::Archive(err.to_string()))?;
                    if def_name == name {
                        owners.push(id.clone());
                    }
                }
            }
        }
        Ok(owners)
    }

    /// The `message` definition of the exception type `tycon` and the package it lives in.
    ///
    /// [CANTON-NOTE: SEMANTICS] `tycon` is `Module:Name` when only one package defines such an exception, and
    /// `<package id>#Module:Name` when several do (see `Machine::resolve_type_tycon`), so two packages that both define
    /// an exception of the same name are told apart. A plain name searches `current_package` first, then the others.
    /// `None` when no package defines such an exception.
    pub(crate) fn find_exception_message(
        &self,
        current_package: &str,
        tycon: &str,
    ) -> Result<Option<(String, Expr)>, EvalError> {
        let (only, plain) = match tycon.split_once('#') {
            Some((package_id, plain)) => (Some(package_id), plain),
            None => (None, tycon),
        };
        let mut owners = self.exception_owners(plain)?;
        if let Some(only) = only {
            owners.retain(|id| id == only);
        }
        owners.sort_by_key(|id| id.as_str() != current_package);
        let Some(id) = owners.first() else {
            return Ok(None);
        };
        let (module, name) = plain.split_once(':').ok_or(EvalError::unsupported())?;
        let package = &self.packages[id];
        for candidate in &package.modules {
            let module_name = resolve_single_module_name(package, candidate)
                .map_err(|err| EvalError::Archive(err.to_string()))?;
            if module_name != module {
                continue;
            }
            for def in &candidate.exceptions {
                let def_name = resolve_interned_dotted_name(
                    package,
                    def.name_interned_dname,
                    "DefException.name",
                )
                .map_err(|err| EvalError::Archive(err.to_string()))?;
                if def_name == name {
                    return Ok(def.message.clone().map(|m| (id.clone(), m)));
                }
            }
        }
        Ok(None)
    }

    fn eval_expr_in(&self, package_id: &str, expr: Expr, env: Env) -> Result<Value, EvalError> {
        let mut machine = Machine {
            world: self,
            control: Control::Expr(expr),
            env,
            type_env: Vec::new(),
            package_id: package_id.to_string(),
            kont: Vec::new(),
            steps: 0,
            host: None,
            ledger: Ledger::On,
        };
        machine.run_closed()
    }

    pub fn eval_choice_controllers(
        &self,
        module: &str,
        template: &str,
        choice_name: &str,
        this_val: &Value,
        arg_val: &Value,
    ) -> Result<Vec<String>, EvalError> {
        self.eval_choice_controllers_in(
            &self.main_package_id,
            module,
            template,
            choice_name,
            this_val,
            arg_val,
        )
    }

    pub fn eval_choice_controllers_in(
        &self,
        package_id: &str,
        module: &str,
        template: &str,
        choice_name: &str,
        this_val: &Value,
        arg_val: &Value,
    ) -> Result<Vec<String>, EvalError> {
        let (package, tmpl, choice) =
            self.find_choice(package_id, module, template, choice_name)?;
        let expr = choice
            .controllers
            .as_ref()
            .ok_or_else(|| EvalError::MissingDef {
                module: module.to_string(),
                name: format!("{template}.{choice_name}.controllers"),
            })?;
        let param_name =
            resolve_interned_string(package, tmpl.param_interned_str, "DefTemplate.param")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
        let arg_binder = choice.arg_binder.as_ref().ok_or(EvalError::unsupported())?;
        let arg_name = resolve_interned_string(
            package,
            arg_binder.var_interned_str,
            "TemplateChoice.arg_binder",
        )
        .map_err(|err| EvalError::Archive(err.to_string()))?;
        self.eval_party_list(
            package_id,
            expr.clone(),
            Env::from(vec![
                (param_name, this_val.clone()),
                (arg_name, arg_val.clone()),
            ]),
        )
    }

    /// The observers of a choice (`choice ... observer ...`): the parties that see the exercise besides the contract's stakeholders and the actors. Empty
    /// for a choice without an observer clause.
    pub fn eval_choice_observers_in(
        &self,
        package_id: &str,
        module: &str,
        template: &str,
        choice_name: &str,
        this_val: &Value,
        arg_val: &Value,
    ) -> Result<Vec<String>, EvalError> {
        let (package, tmpl, choice) =
            self.find_choice(package_id, module, template, choice_name)?;
        let Some(expr) = choice.observers.as_ref() else {
            return Ok(Vec::new());
        };
        let param_name =
            resolve_interned_string(package, tmpl.param_interned_str, "DefTemplate.param")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
        let arg_binder = choice.arg_binder.as_ref().ok_or(EvalError::unsupported())?;
        let arg_name = resolve_interned_string(
            package,
            arg_binder.var_interned_str,
            "TemplateChoice.arg_binder",
        )
        .map_err(|err| EvalError::Archive(err.to_string()))?;
        self.eval_party_list(
            package_id,
            expr.clone(),
            Env::from(vec![
                (param_name, this_val.clone()),
                (arg_name, arg_val.clone()),
            ]),
        )
    }

    /// Whether `package_id` defines template `module:template`. Only a *missing* definition
    /// is `Ok(false)`; a package that fails to decode stays an error so a damaged archive is
    /// never reported as "no such template".
    pub fn template_exists(
        &self,
        package_id: &str,
        module: &str,
        template: &str,
    ) -> Result<bool, EvalError> {
        match self.find_template(package_id, module, template) {
            Ok(_) => Ok(true),
            Err(EvalError::MissingDef { .. }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Whether the template defines `choice_name` (including the implicit `Archive`, which
    /// the compiler materializes as an ordinary choice in the DAR). Same error policy as
    /// `template_exists`.
    pub fn choice_exists(
        &self,
        package_id: &str,
        module: &str,
        template: &str,
        choice_name: &str,
    ) -> Result<bool, EvalError> {
        match self.find_choice(package_id, module, template, choice_name) {
            Ok(_) => Ok(true),
            Err(EvalError::MissingDef { .. }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// The `consuming` flag of a choice. Consuming choices archive their contract
    /// *before* the body runs, so the body cannot fetch or re-exercise `self`.
    pub fn choice_is_consuming(
        &self,
        package_id: &str,
        module: &str,
        template: &str,
        choice_name: &str,
    ) -> Result<bool, EvalError> {
        let (_, _, choice) = self.find_choice(package_id, module, template, choice_name)?;
        Ok(choice.consuming)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn eval_choice_update(
        &self,
        module: &str,
        template: &str,
        choice_name: &str,
        self_cid: &str,
        this_val: &Value,
        arg_val: &Value,
        host: &mut dyn UpdateHost,
    ) -> Result<Value, EvalError> {
        self.eval_choice_update_in(
            &self.main_package_id,
            module,
            template,
            choice_name,
            self_cid,
            this_val,
            arg_val,
            host,
        )
        // Root entry point (nobody above can catch): flatten an escaped exception.
        .map_err(EvalError::into_uncaught)
    }

    /// Run a choice body as an `Update` against `host`.
    ///
    /// An exception that escapes the body is returned as `EvalError::Thrown`, NOT flattened:
    /// this is also the entry point a host uses for nested exercises, and the parent's `try`
    /// must still be able to catch it. Root callers apply `EvalError::into_uncaught`.
    ///
    /// Each call is a fresh `Machine` with its own `STEP_LIMIT`; a nested exercise made by
    /// the host re-enters this function, so the limit is per choice body, not per
    /// transaction. Hosts must bound nesting depth themselves (see `engine::Engine`).
    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn eval_choice_update_in(
        &self,
        package_id: &str,
        module: &str,
        template: &str,
        choice_name: &str,
        self_cid: &str,
        this_val: &Value,
        arg_val: &Value,
        host: &mut dyn UpdateHost,
    ) -> Result<Value, EvalError> {
        let (package, tmpl, choice) =
            self.find_choice(package_id, module, template, choice_name)?;
        let expr = choice
            .update
            .as_ref()
            .ok_or_else(|| EvalError::MissingDef {
                module: module.to_string(),
                name: format!("{template}.{choice_name}.update"),
            })?;
        let param_name =
            resolve_interned_string(package, tmpl.param_interned_str, "DefTemplate.param")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
        let self_name = resolve_interned_string(
            package,
            choice.self_binder_interned_str,
            "TemplateChoice.self_binder",
        )
        .map_err(|err| EvalError::Archive(err.to_string()))?;
        let arg_binder = choice.arg_binder.as_ref().ok_or(EvalError::unsupported())?;
        let arg_name = resolve_interned_string(
            package,
            arg_binder.var_interned_str,
            "TemplateChoice.arg_binder",
        )
        .map_err(|err| EvalError::Archive(err.to_string()))?;

        let mut machine = Machine {
            world: self,
            // Run, not Expr: the choice body is an Update and must be *executed*. In plain
            // Expr mode it would merely evaluate to an inert `Value::Action`.
            control: Control::Run(expr.clone()),
            env: Env::from(vec![
                (param_name, this_val.clone()),
                (self_name, Value::ContractId(self_cid.to_string())),
                (arg_name, arg_val.clone()),
            ]),
            type_env: Vec::new(),
            package_id: package_id.to_string(),
            kont: Vec::new(),
            steps: 0,
            host: Some(host),
            ledger: Ledger::On,
        };
        machine.run()
    }

    /// Run a top-level definition that denotes an `Update` function (optionally reached
    /// through record fields, e.g. a `HasExercise` dictionary's `exercise`) against `host`.
    /// This is how real DAR values such as `$fHasExercise…` can be driven as root updates.
    /// Like `eval_choice_update_in`, an escaped exception stays `EvalError::Thrown`; the
    /// host that drives the root (e.g. `Engine`) flattens it.
    pub fn run_update_val(
        &self,
        module: &str,
        name: &str,
        fields: &[&str],
        args: &[Value],
        host: &mut dyn UpdateHost,
    ) -> Result<Value, EvalError> {
        let expr = self.find_expr(&self.main_package_id, module, name)?;
        let mut machine = Machine {
            world: self,
            control: Control::Expr(expr),
            env: Env::new(),
            type_env: Vec::new(),
            package_id: self.main_package_id.clone(),
            kont: Vec::new(),
            steps: 0,
            host: Some(host),
            ledger: Ledger::On,
        };
        // The continuation stack is LIFO: the last push is consumed first. Wanted order
        // after evaluating the value: project fields, apply args, then run the result.
        machine.kont.push(Kont::Run);
        if !args.is_empty() {
            machine.kont.push(Kont::ApplyValues {
                args: args.to_vec(),
            });
        }
        for field in fields.iter().rev() {
            machine.kont.push(Kont::FieldProj {
                field: (*field).to_string(),
            });
        }
        machine.run()
    }

    fn eval_party_list(
        &self,
        package_id: &str,
        expr: Expr,
        env: Env,
    ) -> Result<Vec<String>, EvalError> {
        let mut machine = Machine {
            world: self,
            control: Control::Expr(expr),
            env,
            type_env: Vec::new(),
            package_id: package_id.to_string(),
            kont: Vec::new(),
            steps: 0,
            host: None,
            ledger: Ledger::On,
        };
        match machine.run_closed()? {
            Value::List(items) => {
                let mut parties = Vec::with_capacity(items.len());
                for item in &items {
                    match item {
                        Value::Party(p) => parties.push(p.clone()),
                        _ => return Err(EvalError::unsupported()),
                    }
                }
                Ok(parties)
            }
            _ => Err(EvalError::unsupported()),
        }
    }

    fn find_template<'a>(
        &'a self,
        package_id: &str,
        module: &str,
        template: &str,
    ) -> Result<(&'a Package, &'a daml_lf_2::DefTemplate), EvalError> {
        let package = self
            .packages
            .get(package_id)
            .ok_or_else(|| EvalError::MissingDef {
                module: module.to_string(),
                name: template.to_string(),
            })?;
        for candidate in &package.modules {
            let module_name = resolve_single_module_name(package, candidate)
                .map_err(|err| EvalError::Archive(err.to_string()))?;
            if module_name != module {
                continue;
            }
            for tmpl in &candidate.templates {
                let tmpl_name = resolve_interned_dotted_name(
                    package,
                    tmpl.tycon_interned_dname,
                    "DefTemplate.tycon",
                )
                .map_err(|err| EvalError::Archive(err.to_string()))?;
                if tmpl_name == template {
                    return Ok((package, tmpl));
                }
            }
        }
        Err(EvalError::MissingDef {
            module: module.to_string(),
            name: template.to_string(),
        })
    }

    fn find_choice<'a>(
        &'a self,
        package_id: &str,
        module: &str,
        template: &str,
        choice_name: &str,
    ) -> Result<
        (
            &'a Package,
            &'a daml_lf_2::DefTemplate,
            &'a daml_lf_2::TemplateChoice,
        ),
        EvalError,
    > {
        let (package, tmpl) = self.find_template(package_id, module, template)?;
        for choice in &tmpl.choices {
            let name = resolve_interned_string(package, choice.name_interned_str, "Choice.name")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
            if name == choice_name {
                return Ok((package, tmpl, choice));
            }
        }
        Err(EvalError::MissingDef {
            module: module.to_string(),
            name: format!("{template}.{choice_name}"),
        })
    }

    fn find_interface<'a>(
        &'a self,
        package_id: &str,
        interface_id: &str,
    ) -> Result<(&'a Package, &'a daml_lf_2::DefInterface), EvalError> {
        let (module, name) = split_module_name(interface_id)?;
        let package = self
            .packages
            .get(package_id)
            .ok_or_else(|| EvalError::MissingDef {
                module: module.to_string(),
                name: name.to_string(),
            })?;
        for candidate in &package.modules {
            let module_name = resolve_single_module_name(package, candidate)
                .map_err(|err| EvalError::Archive(err.to_string()))?;
            if module_name != module {
                continue;
            }
            for iface in &candidate.interfaces {
                let iface_name = resolve_interned_dotted_name(
                    package,
                    iface.tycon_interned_dname,
                    "DefInterface.tycon",
                )
                .map_err(|err| EvalError::Archive(err.to_string()))?;
                if iface_name == name {
                    return Ok((package, iface));
                }
            }
        }
        Err(EvalError::MissingDef {
            module: module.to_string(),
            name: name.to_string(),
        })
    }

    /// The instance that template `template_id` (`"Module:Type"` in `package_id`) declares for the interface
    /// `interface_id` in `interface_package_id`, or `None` when it does not implement it.
    pub(crate) fn interface_instance(
        &self,
        package_id: &str,
        template_id: &str,
        interface_package_id: &str,
        interface_id: &str,
    ) -> Result<Option<InterfaceInstance<'_>>, EvalError> {
        let (module, template) = split_module_name(template_id)?;
        let (package, tmpl) = self.find_template(package_id, module, template)?;
        for implements in &tmpl.implements {
            let Some(con) = implements.interface.as_ref() else {
                continue;
            };
            let (pkg, id) = resolve_con_in(package, package_id, con)?;
            if pkg == interface_package_id && id == interface_id {
                let body = implements.body.as_ref().ok_or(EvalError::unsupported())?;
                return Ok(Some(InterfaceInstance {
                    package,
                    template: tmpl,
                    body,
                }));
            }
        }
        Ok(None)
    }

    /// Whether `interface_id` (`"Module:Name"`) is an interface defined in package `package_id`.
    pub fn interface_exists(&self, package_id: &str, interface_id: &str) -> bool {
        self.find_interface(package_id, interface_id).is_ok()
    }

    /// Whether the template implements the interface.
    pub fn template_implements(
        &self,
        package_id: &str,
        template_id: &str,
        interface_package_id: &str,
        interface_id: &str,
    ) -> Result<bool, EvalError> {
        Ok(self
            .interface_instance(package_id, template_id, interface_package_id, interface_id)?
            .is_some())
    }

    /// All interfaces `(interface_package_id, "Module:Interface")` implemented by template
    /// `template_id` (`"Module:Type"`) in `package_id`, in declaration order.
    pub fn template_implemented_interfaces(
        &self,
        package_id: &str,
        template_id: &str,
    ) -> Result<Vec<(String, String)>, EvalError> {
        let (module, template) = split_module_name(template_id)?;
        let (package, tmpl) = self.find_template(package_id, module, template)?;
        let mut out = Vec::with_capacity(tmpl.implements.len());
        for implements in &tmpl.implements {
            let Some(con) = implements.interface.as_ref() else {
                continue;
            };
            out.push(resolve_con_in(package, package_id, con)?);
        }
        Ok(out)
    }

    /// Choice `choice` of an interface, with the interface definition and its package.
    fn find_interface_choice<'a>(
        &'a self,
        interface_package_id: &str,
        interface_id: &str,
        choice_name: &str,
    ) -> Result<
        (
            &'a Package,
            &'a daml_lf_2::DefInterface,
            &'a daml_lf_2::TemplateChoice,
        ),
        EvalError,
    > {
        let (package, iface) = self.find_interface(interface_package_id, interface_id)?;
        for choice in &iface.choices {
            let name = resolve_interned_string(package, choice.name_interned_str, "Choice.name")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
            if name == choice_name {
                return Ok((package, iface, choice));
            }
        }
        Err(EvalError::MissingDef {
            module: interface_id.to_string(),
            name: choice_name.to_string(),
        })
    }

    /// Controllers of an interface choice, evaluated on the interface value `this_val`.
    pub fn eval_interface_choice_controllers_in(
        &self,
        interface_package_id: &str,
        interface_id: &str,
        choice_name: &str,
        this_val: &Value,
        arg_val: &Value,
    ) -> Result<Vec<String>, EvalError> {
        let (package, iface, choice) =
            self.find_interface_choice(interface_package_id, interface_id, choice_name)?;
        let expr = choice
            .controllers
            .as_ref()
            .ok_or_else(|| EvalError::MissingDef {
                module: interface_id.to_string(),
                name: format!("{choice_name}.controllers"),
            })?;
        let param_name =
            resolve_interned_string(package, iface.param_interned_str, "DefInterface.param")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
        let arg_binder = choice.arg_binder.as_ref().ok_or(EvalError::unsupported())?;
        let arg_name = resolve_interned_string(
            package,
            arg_binder.var_interned_str,
            "TemplateChoice.arg_binder",
        )
        .map_err(|err| EvalError::Archive(err.to_string()))?;
        self.eval_party_list(
            interface_package_id,
            expr.clone(),
            Env::from(vec![
                (param_name, this_val.clone()),
                (arg_name, arg_val.clone()),
            ]),
        )
    }

    /// The observers of an interface choice (empty without an observer clause); see [`World::eval_choice_observers_in`].
    pub fn eval_interface_choice_observers_in(
        &self,
        interface_package_id: &str,
        interface_id: &str,
        choice_name: &str,
        this_val: &Value,
        arg_val: &Value,
    ) -> Result<Vec<String>, EvalError> {
        let (package, iface, choice) =
            self.find_interface_choice(interface_package_id, interface_id, choice_name)?;
        let Some(expr) = choice.observers.as_ref() else {
            return Ok(Vec::new());
        };
        let param_name =
            resolve_interned_string(package, iface.param_interned_str, "DefInterface.param")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
        let arg_binder = choice.arg_binder.as_ref().ok_or(EvalError::unsupported())?;
        let arg_name = resolve_interned_string(
            package,
            arg_binder.var_interned_str,
            "TemplateChoice.arg_binder",
        )
        .map_err(|err| EvalError::Archive(err.to_string()))?;
        self.eval_party_list(
            interface_package_id,
            expr.clone(),
            Env::from(vec![
                (param_name, this_val.clone()),
                (arg_name, arg_val.clone()),
            ]),
        )
    }

    pub fn interface_choice_is_consuming(
        &self,
        interface_package_id: &str,
        interface_id: &str,
        choice_name: &str,
    ) -> Result<bool, EvalError> {
        let (_, _, choice) =
            self.find_interface_choice(interface_package_id, interface_id, choice_name)?;
        Ok(choice.consuming)
    }

    /// Run the body of an interface choice against `host`.
    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn eval_interface_choice_update_in(
        &self,
        interface_package_id: &str,
        interface_id: &str,
        choice_name: &str,
        self_cid: &str,
        this_val: &Value,
        arg_val: &Value,
        host: &mut dyn UpdateHost,
    ) -> Result<Value, EvalError> {
        let (package, iface, choice) =
            self.find_interface_choice(interface_package_id, interface_id, choice_name)?;
        let expr = choice
            .update
            .as_ref()
            .ok_or_else(|| EvalError::MissingDef {
                module: interface_id.to_string(),
                name: format!("{choice_name}.update"),
            })?;
        let param_name =
            resolve_interned_string(package, iface.param_interned_str, "DefInterface.param")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
        let self_name = resolve_interned_string(
            package,
            choice.self_binder_interned_str,
            "TemplateChoice.self_binder",
        )
        .map_err(|err| EvalError::Archive(err.to_string()))?;
        let arg_binder = choice.arg_binder.as_ref().ok_or(EvalError::unsupported())?;
        let arg_name = resolve_interned_string(
            package,
            arg_binder.var_interned_str,
            "TemplateChoice.arg_binder",
        )
        .map_err(|err| EvalError::Archive(err.to_string()))?;
        let mut machine = Machine {
            world: self,
            control: Control::Run(expr.clone()),
            env: Env::from(vec![
                (param_name, this_val.clone()),
                (self_name, Value::ContractId(self_cid.to_string())),
                (arg_name, arg_val.clone()),
            ]),
            type_env: Vec::new(),
            package_id: interface_package_id.to_string(),
            kont: Vec::new(),
            steps: 0,
            host: Some(host),
            ledger: Ledger::On,
        };
        machine.run()
    }

    /// The view of the interface `interface_id` (in `interface_package_id`) of a contract of template
    /// `template_id` in `package_id` whose payload is `payload`.
    pub fn eval_interface_view_in(
        &self,
        package_id: &str,
        template_id: &str,
        interface_package_id: &str,
        interface_id: &str,
        payload: &Value,
    ) -> Result<Value, EvalError> {
        let inst = self
            .interface_instance(package_id, template_id, interface_package_id, interface_id)?
            .ok_or_else(|| {
                EvalError::Host(format!("{template_id} does not implement {interface_id}"))
            })?;
        let param = resolve_interned_string(
            inst.package,
            inst.template.param_interned_str,
            "DefTemplate.param",
        )
        .map_err(|err| EvalError::Archive(err.to_string()))?;
        let view = inst.body.view.clone().ok_or(EvalError::unsupported())?;
        let mut machine = Machine {
            world: self,
            control: Control::Expr(view),
            env: Env::from(vec![(param, payload.clone())]),
            type_env: Vec::new(),
            package_id: package_id.to_string(),
            kont: Vec::new(),
            steps: 0,
            host: None,
            ledger: Ledger::On,
        };
        machine.run_closed()
    }

    /// Apply a function value to arguments without a host, as part of a transaction (`exercise_interface` guards).
    pub fn apply_closed(&self, func: &Value, args: Vec<Value>) -> Result<Value, EvalError> {
        self.apply_in(Ledger::On, func, args)
    }

    /// Apply a function value to arguments off ledger, as a Daml script does between its submissions.
    pub fn apply_off_ledger(&self, func: &Value, args: Vec<Value>) -> Result<Value, EvalError> {
        self.apply_in(Ledger::Off, func, args)
    }

    fn apply_in(&self, ledger: Ledger, func: &Value, args: Vec<Value>) -> Result<Value, EvalError> {
        let mut machine = Machine {
            world: self,
            control: Control::Value(func.clone()),
            env: Env::new(),
            type_env: Vec::new(),
            package_id: self.main_package_id.clone(),
            kont: vec![Kont::ApplyValues { args }],
            steps: 0,
            host: None,
            ledger,
        };
        machine.run_closed()
    }

    pub(crate) fn find_expr(
        &self,
        package_id: &str,
        module: &str,
        name: &str,
    ) -> Result<Expr, EvalError> {
        let package = self
            .packages
            .get(package_id)
            .ok_or_else(|| EvalError::MissingDef {
                module: module.to_string(),
                name: name.to_string(),
            })?;
        for candidate in &package.modules {
            let module_name = resolve_single_module_name(package, candidate)
                .map_err(|err| EvalError::Archive(err.to_string()))?;
            if module_name != module {
                continue;
            }
            for value in &candidate.values {
                let Some(named) = &value.name_with_type else {
                    continue;
                };
                let value_name = resolve_interned_dotted_name(
                    package,
                    named.name_interned_dname,
                    "DefValue.name",
                )
                .map_err(|err| EvalError::Archive(err.to_string()))?;
                if value_name == name {
                    return value.expr.clone().ok_or_else(|| EvalError::MissingDef {
                        module: module.to_string(),
                        name: name.to_string(),
                    });
                }
            }
        }
        Err(EvalError::MissingDef {
            module: module.to_string(),
            name: name.to_string(),
        })
    }
}

pub fn parse_arg(text: &str) -> Result<Value, EvalError> {
    if let Some(rest) = text.strip_prefix("i:") {
        let number = rest
            .parse::<i64>()
            .map_err(|_| EvalError::Arithmetic(format!("bad int {rest}")))?;
        return Ok(Value::Int64(number));
    }
    if let Some(rest) = text.strip_prefix("t:") {
        return Ok(Value::Text(rest.to_string()));
    }
    if let Some(rest) = text.strip_prefix("p:") {
        return Ok(Value::Party(rest.to_string()));
    }
    if let Some(rest) = text.strip_prefix("b:") {
        return Ok(Value::Bool(rest == "true"));
    }
    if let Some(rest) = text.strip_prefix("n:") {
        let (coeff, scale) = parse_numeric(rest)?;
        return Ok(Value::Numeric { coeff, scale });
    }
    Err(EvalError::Arithmetic(format!("bad argument {text}")))
}

pub fn render(value: &Value) -> Result<String, EvalError> {
    match value {
        Value::Int64(number) => Ok(number.to_string()),
        Value::Bool(bit) => Ok(bit.to_string()),
        Value::Text(text) => Ok(quote_text(text)),
        Value::Party(party) => Ok(format!("'{party}'")),
        Value::ContractId(cid) => Ok(cid.clone()),
        Value::Numeric { coeff, scale } => Ok(render_numeric(*coeff, *scale)),
        Value::BigNumeric(bn) => Ok(bn.to_plain_string()),
        Value::Unit => Ok("()".to_string()),
        Value::Optional(None) => Ok("None".to_string()),
        Value::Optional(Some(inner)) => Ok(format!("Some({})", render(inner)?)),
        Value::List(items) => {
            let rendered = items.iter().map(render).collect::<Result<Vec<_>, _>>()?;
            Ok(format!("[{}]", rendered.join(", ")))
        }
        Value::TypeRep { key, .. } => Ok(format!("TypeRep({key})")),
        _ => Err(EvalError::unsupported()),
    }
}

fn quote_text(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

pub fn parse_numeric(text: &str) -> Result<(i128, u8), EvalError> {
    let negative = text.starts_with('-');
    let text = text.trim_start_matches(['+', '-']);
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    if frac.len() > u8::MAX as usize || whole.is_empty() && frac.is_empty() {
        return Err(EvalError::Arithmetic(format!("bad numeric {text}")));
    }
    let digits = format!("{whole}{frac}");
    let trimmed = digits.trim_start_matches('0');
    let coeff = if trimmed.is_empty() {
        0
    } else {
        trimmed
            .parse::<i128>()
            .map_err(|_| EvalError::Arithmetic(format!("bad numeric {text}")))?
    };
    Ok((if negative { -coeff } else { coeff }, frac.len() as u8))
}

pub fn render_numeric(coeff: i128, scale: u8) -> String {
    let negative = coeff < 0;
    let digits = coeff.unsigned_abs().to_string();
    let scale = scale as usize;
    let body = if scale == 0 {
        digits
    } else if digits.len() > scale {
        let split = digits.len() - scale;
        format!("{}.{}", &digits[..split], &digits[split..])
    } else {
        let zeros = "0".repeat(scale - digits.len());
        format!("0.{zeros}{digits}")
    };
    if negative {
        format!("-{body}")
    } else {
        body
    }
}
