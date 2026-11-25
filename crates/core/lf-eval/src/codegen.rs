//! Rust bindings generated from a DAR (G10, AT-K05): every serializable data type, template, choice and interface of the main package and
//! of the dependency types they reach, as Rust source that reads and writes the Daml-LF JSON encoding (`typed_json`).
//!
//! [CANTON-NOTE: SEMANTICS] What is generated, and what is said about what is not, follows the official generators measured on the same
//! DAR (`scripts/oracle-codegen.sh`, `tests/oracle/codegen/official/`): `codegen-js` emits every serializable type of every module and
//! silently leaves out a type that holds a value it cannot represent (`Any`, `AnyTemplate`, functions); `codegen-java` emits only what a
//! template reaches. This generator takes the `codegen-js` rule for the set of types, and never leaves a type out silently: each one is
//! in [`Generated::skipped`] with the reason, and the caller reports it.
//!
//! [CANTON-NOTE: SEMANTICS] The JSON encoding is the one `typed_json` reads: a record is an object by field name, a variant
//! `{"tag", "value"}`, an enum its constructor, `Int64` and `Numeric` strings, an `Optional` of an `Optional` `[]`/`[x]`.
//!
//! [CANTON-NOTE: LIMITATION] `Date`, `Timestamp` and `Numeric` are strings in the generated types, not calendar or decimal types. An
//! `Optional` nested more than twice, a higher-kinded type parameter and a type synonym are skipped with their reason.
use std::collections::{BTreeMap, BTreeSet};

use lf_archive::proto::daml_lf_2::def_data_type::DataCons;

use crate::typed_json::{dotted, string, LfType, Types};
use crate::World;

/// A Daml type the generator did not emit, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub module: String,
    pub name: String,
    pub reason: String,
}

/// What a generation produced.
#[derive(Clone, Debug, Default)]
pub struct Generated {
    /// The Rust source of the bindings (one module tree, `runtime` included).
    pub code: String,
    /// `Module:Name` of every Daml type, template and interface that has a Rust item, in the main package.
    pub items: Vec<String>,
    pub skipped: Vec<Skipped>,
}

const RUST_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for",
    "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where",
    "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "gen",
];
/// Keywords that cannot be written as a raw identifier.
const NO_RAW: &[&str] = &["crate", "self", "Self", "super"];

/// A Rust identifier for `name` that is never a keyword: a raw identifier where Rust allows one, a trailing `_` where it does not.
fn ident(name: &str) -> String {
    if RUST_KEYWORDS.contains(&name) {
        if NO_RAW.contains(&name) {
            format!("{name}_")
        } else {
            format!("r#{name}")
        }
    } else {
        name.to_string()
    }
}

/// `fooBar` -> `foo_bar`, `HTTPServer` -> `http_server`.
fn snake(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::new();
    for (i, c) in chars.iter().enumerate() {
        if c.is_uppercase() {
            let prev_lower =
                i > 0 && (chars[i - 1].is_lowercase() || chars[i - 1].is_ascii_digit());
            let next_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            if i > 0 && (prev_lower || (next_lower && chars[i - 1].is_uppercase())) {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(*c);
        }
    }
    out
}

/// A module-name part: snake case, a keyword gets a trailing `_` (a module cannot be a raw `r#self`).
fn module_part(part: &str) -> String {
    let s = snake(part);
    if RUST_KEYWORDS.contains(&s.as_str()) {
        format!("{s}_")
    } else {
        s
    }
}

/// Where a data type lives in the generated module tree and what it is called.
#[derive(Clone, Debug)]
struct Placed {
    path: Vec<String>,
    name: String,
}

type DataKey = (String, String, String); // (package id, module, daml type name)

struct Gen<'w> {
    types: Types<'w>,
    world: &'w World,
    main: String,
    placed: BTreeMap<DataKey, Placed>,
    /// A data type that cannot be generated, with the reason.
    unsupported: BTreeMap<DataKey, String>,
    /// Data types to generate (main package: all; dependencies: reachable ones).
    wanted: BTreeSet<DataKey>,
}

impl<'w> Gen<'w> {
    fn package_path(&self, package_id: &str, module: &str) -> Vec<String> {
        let mut path = Vec::new();
        if package_id != self.main {
            path.push("deps".to_string());
            path.push(format!("pkg_{}", &package_id[..8.min(package_id.len())]));
        }
        path.extend(module.split('.').map(module_part));
        path
    }

    /// The generic parameters of a data type and its constructors.
    fn data(&self, key: &DataKey) -> Result<&'w lf_archive::proto::daml_lf_2::DefDataType, String> {
        Ok(self.types.data(&key.0, &key.1, &key.2)?.1)
    }

    /// Does the type hold something the generator cannot represent? The reason, if it does.
    fn problem(&mut self, ty: &LfType, depth: usize, seen: &mut Vec<DataKey>) -> Option<String> {
        match ty {
            LfType::Unsupported(what) => Some(format!(
                "a field of a type the generator cannot represent ({what})"
            )),
            LfType::Partial(..) => {
                Some("a type constructor applied to too few arguments (higher kind)".into())
            }
            LfType::Optional(inner) => {
                let nested = depth + 1;
                if nested > 2 {
                    return Some("an Optional nested more than twice".into());
                }
                let inner_depth = if matches!(**inner, LfType::Optional(_)) {
                    nested
                } else {
                    0
                };
                self.problem(inner, inner_depth, seen)
            }
            LfType::List(t) | LfType::TextMap(t) => self.problem(t, 0, seen),
            LfType::GenMap(k, v) => self
                .problem(k, 0, seen)
                .or_else(|| self.problem(v, 0, seen)),
            LfType::Con {
                package_id,
                module,
                name,
                args,
            } => {
                let key = (package_id.clone(), module.clone(), name.clone());
                if let Some(reason) = self.type_problem(&key, seen) {
                    return Some(format!("{module}:{name}: {reason}"));
                }
                args.iter().find_map(|a| self.problem(a, 0, seen))
            }
            _ => None,
        }
    }

    /// Why a data type cannot be generated (its fields are looked at, recursively).
    fn type_problem(&mut self, key: &DataKey, seen: &mut Vec<DataKey>) -> Option<String> {
        if let Some(reason) = self.unsupported.get(key) {
            return Some(reason.clone());
        }
        if seen.contains(key) {
            return None; // a recursive reference: judged by the other fields
        }
        seen.push(key.clone());
        let found = self.type_problem_fields(key, seen);
        seen.pop();
        if let Some(reason) = &found {
            self.unsupported.insert(key.clone(), reason.clone());
        }
        found
    }

    fn type_problem_fields(&mut self, key: &DataKey, seen: &mut Vec<DataKey>) -> Option<String> {
        let def = match self.data(key) {
            Ok(def) => def,
            Err(e) => return Some(e),
        };
        let package = match self.types.package(&key.0) {
            Ok(p) => p,
            Err(e) => return Some(e),
        };
        let field_types: Vec<_> = match def.data_cons.as_ref() {
            Some(DataCons::Record(r)) => r.fields.iter().map(|f| f.r#type.as_ref()).collect(),
            Some(DataCons::Variant(v)) => v.fields.iter().map(|f| f.r#type.as_ref()).collect(),
            Some(DataCons::Enum(_)) => Vec::new(),
            Some(DataCons::Interface(_)) | None => {
                return Some("an interface or a type without constructors".into())
            }
        };
        let _ = package;
        for t in field_types {
            let Some(t) = t else {
                return Some("a field without a type".into());
            };
            let lf = match self.types.resolve(&key.0, t) {
                Ok(lf) => lf,
                Err(e) => return Some(e),
            };
            if let Some(reason) = self.problem(&lf, 0, seen) {
                return Some(reason);
            }
        }
        None
    }

    /// Does `from` reach `target` through fields that make the type infinitely large without a `Box` (no list, map or box on the way)?
    fn reaches_directly(
        &self,
        from: &DataKey,
        target: &DataKey,
        visited: &mut BTreeSet<DataKey>,
    ) -> bool {
        if !visited.insert(from.clone()) {
            return false;
        }
        let Ok(def) = self.data(from) else {
            return false;
        };
        let types: Vec<_> = match def.data_cons.as_ref() {
            Some(DataCons::Record(r)) => {
                r.fields.iter().filter_map(|f| f.r#type.as_ref()).collect()
            }
            Some(DataCons::Variant(v)) => {
                v.fields.iter().filter_map(|f| f.r#type.as_ref()).collect()
            }
            _ => return false,
        };
        types.into_iter().any(|t| {
            self.types
                .resolve(&from.0, t)
                .is_ok_and(|lf| self.type_reaches(&lf, target, visited))
        })
    }

    fn type_reaches(&self, ty: &LfType, target: &DataKey, visited: &mut BTreeSet<DataKey>) -> bool {
        match ty {
            LfType::Optional(inner) => self.type_reaches(inner, target, visited),
            LfType::Con {
                package_id,
                module,
                name,
                args,
            } => {
                let key = (package_id.clone(), module.clone(), name.clone());
                &key == target
                    || self.reaches_directly(&key, target, visited)
                    || args.iter().any(|a| self.type_reaches(a, target, visited))
            }
            _ => false,
        }
    }

    /// The Rust type of `ty`, written from the module `at`. `boxed_for` is the data type being defined: a direct reference back to it
    /// (through other types, without a list or a map) is boxed.
    fn rust_type(
        &self,
        ty: &LfType,
        at: &[String],
        owner: Option<&DataKey>,
        params: &[String],
    ) -> String {
        let runtime = |name: &str| relative(at, &["runtime".to_string()], name);
        match ty {
            LfType::Unit => runtime("Unit"),
            LfType::Bool => "bool".into(),
            LfType::Int64 => runtime("Int64"),
            LfType::Text => "String".into(),
            LfType::Party => runtime("Party"),
            LfType::Timestamp => runtime("Timestamp"),
            LfType::Date => runtime("Date"),
            LfType::ContractId => runtime("ContractId"),
            LfType::Numeric(_) => runtime("Numeric"),
            LfType::List(t) => format!("Vec<{}>", self.rust_type(t, at, owner, params)),
            LfType::Optional(inner) => {
                if let LfType::Optional(innermost) = &**inner {
                    format!(
                        "{}<{}>",
                        runtime("Optional2"),
                        self.rust_type(innermost, at, owner, params)
                    )
                } else {
                    format!("Option<{}>", self.rust_type(inner, at, owner, params))
                }
            }
            LfType::TextMap(t) => format!(
                "std::collections::BTreeMap<String, {}>",
                self.rust_type(t, at, owner, params)
            ),
            LfType::GenMap(k, v) => format!(
                "Vec<({}, {})>",
                self.rust_type(k, at, owner, params),
                self.rust_type(v, at, owner, params)
            ),
            LfType::Con {
                package_id,
                module,
                name,
                args,
            } => {
                let key = (package_id.clone(), module.clone(), name.clone());
                let Some(placed) = self.placed.get(&key) else {
                    return "()".into();
                };
                let args: Vec<String> = args
                    .iter()
                    .map(|a| self.rust_type(a, at, owner, params))
                    .collect();
                let generic = if args.is_empty() {
                    String::new()
                } else {
                    format!("<{}>", args.join(", "))
                };
                let path = relative(at, &placed.path, &placed.name);
                let boxed = owner.is_some_and(|o| {
                    self.reaches_directly(&key, o, &mut BTreeSet::new()) || &key == o
                });
                if boxed {
                    format!("Box<{path}{generic}>")
                } else {
                    format!("{path}{generic}")
                }
            }
            LfType::Var(v) => param_name(v, params),
            LfType::Nat(_) | LfType::Partial(..) | LfType::Unsupported(_) => "()".into(),
        }
    }
}

/// A type parameter as a Rust generic (`a` -> `A`); a variable that is not a parameter of the type is `()`.
fn param_name(v: &str, params: &[String]) -> String {
    if params.iter().any(|p| p == v) {
        v.to_uppercase()
    } else {
        "()".into()
    }
}

/// The path to item `name` in module `to` as written inside module `from` (both relative to the root of the generated tree).
fn relative(from: &[String], to: &[String], name: &str) -> String {
    if from == to {
        return name.to_string();
    }
    let mut out = "super::".repeat(from.len());
    for part in to {
        out.push_str(part);
        out.push_str("::");
    }
    out.push_str(name);
    out
}

fn type_name(daml_name: &str) -> String {
    daml_name.replace('.', "")
}

fn field_ident(name: &str, used: &mut BTreeSet<String>) -> (String, String) {
    let mut snake = snake(name);
    while used.contains(&snake) {
        snake.push('_');
    }
    used.insert(snake.clone());
    (ident(&snake), name.to_string())
}

/// The runtime every generated tree carries: the scalar wrappers and the JSON encodings the Daml-LF JSON format asks for.
const RUNTIME: &str = r#"pub mod runtime {
    //! The wrappers the generated types are written with.
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// A party id.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct Party(pub String);

    /// A decimal as the text the JSON encoding uses.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct Numeric(pub String);

    /// A timestamp as its RFC 3339 text.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct Timestamp(pub String);

    /// A date as `YYYY-MM-DD`.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct Date(pub String);

    /// The unit value: `{}`.
    #[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Unit {}

    /// A contract id.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct ContractId(pub String);

    /// An `Int64`, written as a string and read from a string or a number.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Int64(pub i64);

    impl Serialize for Int64 {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&self.0.to_string())
        }
    }

    impl<'de> Deserialize<'de> for Int64 {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            #[derive(Deserialize)]
            #[serde(untagged)]
            enum Wire {
                Text(String),
                Number(i64),
            }
            match Wire::deserialize(deserializer)? {
                Wire::Number(n) => Ok(Int64(n)),
                Wire::Text(t) => t.parse().map(Int64).map_err(D::Error::custom),
            }
        }
    }

    /// An `Optional (Optional t)`: `null`, `[]` and `[x]` tell `None`, `Some None` and `Some (Some x)` apart.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Optional2<T>(pub Option<Option<T>>);

    impl<T> Default for Optional2<T> {
        fn default() -> Self {
            Optional2(None)
        }
    }

    impl<T: Serialize> Serialize for Optional2<T> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            match &self.0 {
                None => serializer.serialize_none(),
                Some(None) => Vec::<&T>::new().serialize(serializer),
                Some(Some(x)) => vec![x].serialize(serializer),
            }
        }
    }

    impl<'de, T: Deserialize<'de>> Deserialize<'de> for Optional2<T> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            match Option::<Vec<T>>::deserialize(deserializer)? {
                None => Ok(Optional2(None)),
                Some(mut items) => match items.len() {
                    0 => Ok(Optional2(Some(None))),
                    1 => Ok(Optional2(Some(items.pop()))),
                    n => Err(D::Error::custom(format!("an optional of an optional holds at most one value, not {n}"))),
                },
            }
        }
    }

    /// A template: where it is declared and what its key is.
    pub trait Template {
        const PACKAGE_ID: &'static str;
        const MODULE: &'static str;
        const ENTITY: &'static str;
        type Key;
    }

    /// A choice of the template or interface `C`.
    pub trait Choice<C> {
        const NAME: &'static str;
        const CONSUMING: bool;
        type Result;
    }

    /// An interface: where it is declared and what its view is.
    pub trait Interface {
        const PACKAGE_ID: &'static str;
        const MODULE: &'static str;
        const ENTITY: &'static str;
        type View;
    }
}
"#;

/// Generates the Rust bindings of the main package of `world`.
pub fn generate_rust(world: &World) -> Result<Generated, String> {
    let main = world.main_package_id().to_string();
    let mut gen = Gen {
        types: Types::new(world),
        world,
        main: main.clone(),
        placed: BTreeMap::new(),
        unsupported: BTreeMap::new(),
        wanted: BTreeSet::new(),
    };
    let package = gen.types.package(&main)?;
    // the data types of the main package, all of them
    let mut roots: Vec<DataKey> = Vec::new();
    for m in &package.modules {
        let module = dotted(package, m.name_interned_dname)?;
        for d in &m.data_types {
            roots.push((
                main.clone(),
                module.clone(),
                dotted(package, d.name_interned_dname)?,
            ));
        }
    }
    // dependency types reached from them, transitively
    let mut queue = roots.clone();
    let mut seen: BTreeSet<DataKey> = roots.iter().cloned().collect();
    while let Some(key) = queue.pop() {
        let Ok(def) = gen.data(&key) else { continue };
        let types: Vec<_> = match def.data_cons.as_ref() {
            Some(DataCons::Record(r)) => r.fields.iter().filter_map(|f| f.r#type.clone()).collect(),
            Some(DataCons::Variant(v)) => {
                v.fields.iter().filter_map(|f| f.r#type.clone()).collect()
            }
            _ => Vec::new(),
        };
        for t in types {
            if let Ok(lf) = gen.types.resolve(&key.0, &t) {
                collect_cons(&lf, &mut |k| {
                    if seen.insert(k.clone()) {
                        queue.push(k);
                    }
                });
            }
        }
    }
    // the types templates, choices and interfaces of the main package are written with
    {
        let package = gen.types.package(&main)?;
        let mut extra: Vec<lf_archive::proto::daml_lf_2::Type> = Vec::new();
        for m in &package.modules {
            for t in &m.templates {
                for c in &t.choices {
                    extra.extend(c.arg_binder.as_ref().and_then(|b| b.r#type.clone()));
                    extra.extend(c.ret_type.clone());
                }
                extra.extend(t.key.as_ref().and_then(|k| k.r#type.clone()));
            }
            for i in &m.interfaces {
                extra.extend(i.view.clone());
                for c in &i.choices {
                    extra.extend(c.arg_binder.as_ref().and_then(|b| b.r#type.clone()));
                    extra.extend(c.ret_type.clone());
                }
            }
        }
        for t in extra {
            if let Ok(lf) = gen.types.resolve(&main, &t) {
                collect_cons(&lf, &mut |k| {
                    if seen.insert(k.clone()) {
                        queue.push(k);
                    }
                });
            }
        }
        // and what those reach in turn
        while let Some(key) = queue.pop() {
            let Ok(def) = gen.data(&key) else { continue };
            let types: Vec<_> = match def.data_cons.as_ref() {
                Some(DataCons::Record(r)) => {
                    r.fields.iter().filter_map(|f| f.r#type.clone()).collect()
                }
                Some(DataCons::Variant(v)) => {
                    v.fields.iter().filter_map(|f| f.r#type.clone()).collect()
                }
                _ => Vec::new(),
            };
            for t in types {
                if let Ok(lf) = gen.types.resolve(&key.0, &t) {
                    collect_cons(&lf, &mut |k| {
                        if seen.insert(k.clone()) {
                            queue.push(k);
                        }
                    });
                }
            }
        }
    }
    gen.wanted = seen;

    // the supported ones get a place and a name, unique in their module
    let mut skipped = Vec::new();
    let mut taken: BTreeMap<Vec<String>, BTreeSet<String>> = BTreeMap::new();
    let wanted: Vec<DataKey> = gen.wanted.iter().cloned().collect();
    for key in &wanted {
        let is_interface = matches!(
            gen.data(key).ok().and_then(|d| d.data_cons.as_ref()),
            Some(DataCons::Interface(_))
        );
        if is_interface {
            continue;
        }
        if let Some(reason) = gen.type_problem(key, &mut Vec::new()) {
            if key.0 == main {
                skipped.push(Skipped {
                    module: key.1.clone(),
                    name: key.2.clone(),
                    reason,
                });
            }
            continue;
        }
        let path = gen.package_path(&key.0, &key.1);
        let used = taken.entry(path.clone()).or_default();
        let mut name = type_name(&key.2);
        while used.contains(&name) {
            name.push('_');
        }
        used.insert(name.clone());
        gen.placed.insert(key.clone(), Placed { path, name });
    }

    // emit
    let mut modules: BTreeMap<Vec<String>, String> = BTreeMap::new();
    let mut items = Vec::new();
    let keys: Vec<DataKey> = gen.placed.keys().cloned().collect();
    for key in &keys {
        let placed = gen.placed[key].clone();
        let code = gen.emit_data(key, &placed)?;
        modules
            .entry(placed.path.clone())
            .or_default()
            .push_str(&code);
        if key.0 == main && !key.2.contains('.') {
            items.push(format!("{}:{}", key.1, key.2));
        }
    }
    // templates, choices, interfaces of the main package
    let package = gen.types.package(&main)?;
    for m in &package.modules {
        let module = dotted(package, m.name_interned_dname)?;
        let path = gen.package_path(&main, &module);
        for t in &m.templates {
            let name = dotted(package, t.tycon_interned_dname)?;
            let key = (main.clone(), module.clone(), name.clone());
            let Some(placed) = gen.placed.get(&key).cloned() else {
                continue; // its payload type was skipped, and said so
            };
            let mut code = String::new();
            let key_type = match t.key.as_ref().and_then(|k| k.r#type.as_ref()) {
                Some(kt) => {
                    let lf = gen.types.resolve(&main, kt)?;
                    gen.rust_type(&lf, &path, None, &[])
                }
                None => "()".into(),
            };
            let runtime = |n: &str| relative(&path, &["runtime".to_string()], n);
            code.push_str(&format!(
                "impl {} for {} {{\n    const PACKAGE_ID: &'static str = \"{main}\";\n    const MODULE: &'static str = \"{module}\";\n    const ENTITY: &'static str = \"{name}\";\n    type Key = {key_type};\n}}\n",
                runtime("Template"),
                placed.name
            ));
            for c in &t.choices {
                code.push_str(&gen.emit_choice(
                    &main,
                    &path,
                    &placed.name,
                    c,
                    package,
                    &mut skipped,
                    &module,
                    &name,
                )?);
            }
            modules.entry(path.clone()).or_default().push_str(&code);
            items.push(format!("{module}:{name}"));
        }
        for i in &m.interfaces {
            let name = dotted(package, i.tycon_interned_dname)?;
            let mut used = taken.entry(path.clone()).or_default().clone();
            let mut rust = type_name(&name);
            while used.contains(&rust) {
                rust.push('_');
            }
            used.insert(rust.clone());
            taken.insert(path.clone(), used);
            let view = match i.view.as_ref() {
                Some(v) => {
                    let lf = gen.types.resolve(&main, v)?;
                    if let Some(reason) = gen.problem(&lf, 0, &mut Vec::new()) {
                        skipped.push(Skipped {
                            module: module.clone(),
                            name: name.clone(),
                            reason: format!("its view: {reason}"),
                        });
                        continue;
                    }
                    gen.rust_type(&lf, &path, None, &[])
                }
                None => "()".into(),
            };
            let runtime = |n: &str| relative(&path, &["runtime".to_string()], n);
            let mut code = format!(
                "/// The interface `{module}:{name}`.\n#[derive(Clone, Copy, Debug)]\npub struct {rust};\nimpl {} for {rust} {{\n    const PACKAGE_ID: &'static str = \"{main}\";\n    const MODULE: &'static str = \"{module}\";\n    const ENTITY: &'static str = \"{name}\";\n    type View = {view};\n}}\n",
                runtime("Interface")
            );
            for c in &i.choices {
                code.push_str(&gen.emit_choice(
                    &main,
                    &path,
                    &rust,
                    c,
                    package,
                    &mut skipped,
                    &module,
                    &name,
                )?);
            }
            modules.entry(path.clone()).or_default().push_str(&code);
            items.push(format!("{module}:{name}"));
        }
    }

    let mut code = String::from(
        "// Generated by canton-rs (lf-eval codegen) from the main package; do not edit.\n// Include it in a module marked `#[allow(dead_code, clippy::all)]`; it needs `serde` (with `derive`).\n\n",
    );
    code.push_str(RUNTIME);
    code.push_str(&render_tree(&modules, &[]));
    skipped.sort_by(|a, b| (&a.module, &a.name).cmp(&(&b.module, &b.name)));
    items.sort();
    items.dedup();
    Ok(Generated {
        code,
        items,
        skipped,
    })
}

fn collect_cons(ty: &LfType, found: &mut impl FnMut(DataKey)) {
    match ty {
        LfType::List(t) | LfType::Optional(t) | LfType::TextMap(t) => collect_cons(t, found),
        LfType::GenMap(k, v) => {
            collect_cons(k, found);
            collect_cons(v, found);
        }
        LfType::Con {
            package_id,
            module,
            name,
            args,
        } => {
            found((package_id.clone(), module.clone(), name.clone()));
            for a in args {
                collect_cons(a, found);
            }
        }
        _ => {}
    }
}

/// The module tree as source: a `pub mod` per path part, the items inside.
fn render_tree(modules: &BTreeMap<Vec<String>, String>, prefix: &[String]) -> String {
    let mut out = String::new();
    if let Some(body) = modules.get(prefix) {
        out.push_str(body);
    }
    let mut children: BTreeSet<&String> = BTreeSet::new();
    for path in modules.keys() {
        if path.len() > prefix.len() && path[..prefix.len()] == *prefix {
            children.insert(&path[prefix.len()]);
        }
    }
    for child in children {
        let mut next = prefix.to_vec();
        next.push(child.clone());
        out.push_str(&format!(
            "pub mod {} {{\n#[allow(unused_imports, reason = \"generated module preamble\")]\nuse serde::{{Deserialize, Serialize}};\n",
            ident_module(child)
        ));
        out.push_str(&render_tree(modules, &next));
        out.push_str("}\n");
    }
    out
}

fn ident_module(part: &str) -> String {
    part.to_string()
}

impl Gen<'_> {
    fn emit_data(&self, key: &DataKey, placed: &Placed) -> Result<String, String> {
        let def = self.data(key)?;
        let package = self.types.package(&key.0)?;
        let params: Vec<String> = def
            .params
            .iter()
            .map(|p| string(package, p.var_interned_str))
            .collect::<Result<_, _>>()?;
        let generics = if params.is_empty() {
            String::new()
        } else {
            format!(
                "<{}>",
                params
                    .iter()
                    .map(|p| p.to_uppercase())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let at = &placed.path;
        let doc = format!("/// The Daml type `{}:{}`.\n", key.1, key.2);
        let derive = "#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]\n";
        let owner = Some(key);
        Ok(
            match def
                .data_cons
                .as_ref()
                .ok_or("a data type without content")?
            {
                DataCons::Record(r) => {
                    let mut used = BTreeSet::new();
                    let mut fields = String::new();
                    for f in &r.fields {
                        let label = string(package, f.field_interned_str)?;
                        let ty = self
                            .types
                            .resolve(&key.0, f.r#type.as_ref().ok_or("a field without a type")?)?;
                        let rust_ty = self.field_type(&ty, at, owner, &params);
                        let (name, wire) = field_ident(&label, &mut used);
                        let default = if matches!(ty, LfType::Optional(_)) {
                            ", default"
                        } else {
                            ""
                        };
                        fields.push_str(&format!("    #[serde(rename = \"{wire}\"{default})]\n    pub {name}: {rust_ty},\n"));
                    }
                    format!("{doc}{derive}#[serde(deny_unknown_fields)]\npub struct {}{generics} {{\n{fields}}}\n", placed.name)
                }
                DataCons::Variant(v) => {
                    let mut variants = String::new();
                    let mut used = BTreeSet::new();
                    for f in &v.fields {
                        let label = string(package, f.field_interned_str)?;
                        let ty = self.types.resolve(
                            &key.0,
                            f.r#type.as_ref().ok_or("a constructor without a type")?,
                        )?;
                        let rust_ty = self.field_type(&ty, at, owner, &params);
                        let mut name = label.clone();
                        while used.contains(&name) {
                            name.push('_');
                        }
                        used.insert(name.clone());
                        variants.push_str(&format!(
                            "    #[serde(rename = \"{label}\")]\n    {}({rust_ty}),\n",
                            ident_variant(&name)
                        ));
                    }
                    format!(
                    "{doc}{derive}#[serde(tag = \"tag\", content = \"value\")]\npub enum {}{generics} {{\n{variants}}}\n",
                    placed.name
                )
                }
                DataCons::Enum(e) => {
                    let mut variants = String::new();
                    for i in &e.constructors_interned_str {
                        let label = string(package, *i)?;
                        variants.push_str(&format!(
                            "    #[serde(rename = \"{label}\")]\n    {},\n",
                            ident_variant(&label)
                        ));
                    }
                    format!("{doc}{derive}pub enum {} {{\n{variants}}}\n", placed.name)
                }
                DataCons::Interface(_) => String::new(),
            },
        )
    }

    /// The Rust type of a field.
    fn field_type(
        &self,
        ty: &LfType,
        at: &[String],
        owner: Option<&DataKey>,
        params: &[String],
    ) -> String {
        self.rust_type(ty, at, owner, params)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    fn emit_choice(
        &self,
        main: &str,
        path: &[String],
        owner_rust: &str,
        choice: &lf_archive::proto::daml_lf_2::TemplateChoice,
        package: &lf_archive::proto::daml_lf_2::Package,
        skipped: &mut Vec<Skipped>,
        module: &str,
        owner_daml: &str,
    ) -> Result<String, String> {
        let name = string(package, choice.name_interned_str)?;
        let arg = choice
            .arg_binder
            .as_ref()
            .and_then(|b| b.r#type.as_ref())
            .ok_or("a choice without an argument type")?;
        let ret = choice
            .ret_type
            .as_ref()
            .ok_or("a choice without a result type")?;
        let arg_lf = self.types.resolve(main, arg)?;
        let ret_lf = self.types.resolve(main, ret)?;
        let mut guard = self.clone_for_problem();
        if let Some(reason) = guard
            .problem(&arg_lf, 0, &mut Vec::new())
            .or_else(|| guard.problem(&ret_lf, 0, &mut Vec::new()))
        {
            skipped.push(Skipped {
                module: module.to_string(),
                name: format!("{owner_daml}.{name}"),
                reason: format!("choice: {reason}"),
            });
            return Ok(String::new());
        }
        let arg_ty = self.rust_type(&arg_lf, path, None, &[]);
        let ret_ty = self.rust_type(&ret_lf, path, None, &[]);
        let runtime = relative(path, &["runtime".to_string()], "Choice");
        Ok(format!(
            "impl {runtime}<{owner_rust}> for {arg_ty} {{\n    const NAME: &'static str = \"{name}\";\n    const CONSUMING: bool = {};\n    type Result = {ret_ty};\n}}\n",
            choice.consuming
        ))
    }

    fn clone_for_problem(&self) -> Gen<'_> {
        Gen {
            types: Types::new(self.world),
            world: self.world,
            main: self.main.clone(),
            placed: BTreeMap::new(),
            unsupported: self.unsupported.clone(),
            wanted: BTreeSet::new(),
        }
    }
}

fn ident_variant(name: &str) -> String {
    ident(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_never_keywords() {
        assert_eq!(ident("fn"), "r#fn");
        assert_eq!(ident("match"), "r#match");
        assert_eq!(ident("self"), "self_");
        assert_eq!(ident("Self"), "Self_");
        assert_eq!(ident("amount"), "amount");
        assert_eq!(snake("fooBar"), "foo_bar");
        assert_eq!(snake("HTTPServer"), "http_server");
        assert_eq!(snake("_1"), "_1");
        assert_eq!(module_part("Types"), "types");
        assert_eq!(module_part("Type"), "type_");
    }

    #[test]
    fn paths_are_relative_to_the_module_they_are_written_in() {
        let a = vec!["types".to_string()];
        let b = vec!["other".to_string()];
        assert_eq!(relative(&a, &a, "X"), "X");
        assert_eq!(relative(&a, &b, "X"), "super::other::X");
        assert_eq!(relative(&[], &b, "X"), "other::X");
    }
}
