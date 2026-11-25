//! Daml-LF JSON values read against the types of a loaded package (G8): what a Ledger API or a Splice scan answers as JSON
//! (`create_arguments`, `choice_argument`, `exercise_result`) becomes the evaluator's [`Value`], directed by the template's, the
//! choice's or the field's type as the DAR declares it.
//!
//! [CANTON-NOTE: SEMANTICS] The Daml-LF JSON encoding: a record is an object by field name (an absent `Optional` field is `None`), a
//! variant `{"tag": .., "value": ..}`, an enum its constructor's name, a list an array, a `TextMap` an object, a `GenMap` an array of
//! pairs, `Int64` and `Numeric` strings (a number is accepted), a timestamp an RFC 3339 string in UTC, a date `YYYY-MM-DD`, unit `{}`.
//! `Optional`: `null` is `None` and the value itself is `Some`, except for an optional **of an optional**, where `Some x` is `[x]` and
//! `Some None` is `[]`. A numeric may be written as Java writes a `BigDecimal` (`0E-10`), which the official Scala apps do.
//!
//! [CANTON-NOTE: LIMITATION] Type synonyms and types of higher kind are not read (a serializable type has neither).
use lf_archive::proto::daml_lf_2::{
    def_data_type::DataCons, r#type::Sum as TypeSum, BuiltinType, DefDataType, Package, Type,
};
use lf_archive::{resolve_interned_dotted_name, resolve_interned_string};
use serde_json::Value as Json;

use crate::{CtorRank, Value, World};

mod json_encode;
mod text;
mod wire;

pub use text::{
    date_days, format_date, format_numeric, format_timestamp, format_timestamp_micros,
    format_timestamp_trimmed, numeric, timestamp_micros,
};
pub use wire::{wire_field, wire_tag, wire_varint};

use text::substitute;
use wire::sorted_map;

/// A serializable type with every reference resolved.
#[derive(Clone, Debug, PartialEq)]
pub enum LfType {
    Unit,
    Bool,
    Int64,
    Text,
    Party,
    Timestamp,
    Date,
    ContractId,
    /// The scale, when the type says it.
    Numeric(Option<u8>),
    List(Box<LfType>),
    Optional(Box<LfType>),
    TextMap(Box<LfType>),
    GenMap(Box<LfType>, Box<LfType>),
    /// A record, variant or enum declared in `module` of `package_id`.
    Con {
        package_id: String,
        module: String,
        name: String,
        args: Vec<LfType>,
    },
    Var(String),
    Nat(i64),
    /// A builtin still waiting for arguments (inside a curried application).
    Partial(i32, Vec<LfType>),
    Unsupported(String),
}

type Res<T> = Result<T, String>;

pub(crate) fn dotted(package: &Package, index: i32) -> Res<String> {
    resolve_interned_dotted_name(package, index, "a name").map_err(|e| e.to_string())
}

pub(crate) fn string(package: &Package, index: i32) -> Res<String> {
    resolve_interned_string(package, index, "a name").map_err(|e| e.to_string())
}

fn builtin(code: i32, args: Vec<LfType>) -> LfType {
    use BuiltinType as B;
    let one = |args: &[LfType]| Box::new(args[0].clone());
    match (BuiltinType::try_from(code).ok(), args.len()) {
        (Some(B::Unit), 0) => LfType::Unit,
        (Some(B::Bool), 0) => LfType::Bool,
        (Some(B::Int64), 0) => LfType::Int64,
        (Some(B::Text), 0) => LfType::Text,
        (Some(B::Party), 0) => LfType::Party,
        (Some(B::Timestamp), 0) => LfType::Timestamp,
        (Some(B::Date), 0) => LfType::Date,
        (Some(B::ContractId), 1) => LfType::ContractId,
        (Some(B::Numeric), 1) => LfType::Numeric(match &args[0] {
            LfType::Nat(n) => u8::try_from(*n).ok(),
            _ => None,
        }),
        (Some(B::List), 1) => LfType::List(one(&args)),
        (Some(B::Optional), 1) => LfType::Optional(one(&args)),
        (Some(B::Textmap), 1) => LfType::TextMap(one(&args)),
        (Some(B::Genmap), 2) => LfType::GenMap(one(&args), Box::new(args[1].clone())),
        (Some(B::ContractId | B::Numeric | B::List | B::Optional | B::Textmap), 0)
        | (Some(B::Genmap), 0 | 1) => LfType::Partial(code, args),
        (other, n) => LfType::Unsupported(format!("builtin {other:?} with {n} arguments")),
    }
}

/// `Module.Name:Type.Name` -> (`Module.Name`, `Type.Name`).
fn split(template_id: &str) -> Res<(&str, &str)> {
    template_id
        .split_once(':')
        .ok_or_else(|| format!("not Module:Name: {template_id}"))
}

/// The types of a choice: its argument, its result, and whether it consumes the contract.
#[derive(Clone, Debug)]
pub struct ChoiceTypes {
    pub argument: LfType,
    pub result: LfType,
    pub consuming: bool,
}

/// The types of the packages of a [`World`].
pub struct Types<'w> {
    world: &'w World,
    /// `encode` writes numerics the way the Daml JSON API codec does (`0.0`, `16.67`) instead of Java's `BigDecimal.toString` (`0E-10`).
    api_numerics: std::cell::Cell<bool>,
    /// `encode` writes an `Int64` as a JSON number (the Daml Script runner's `--output-file`) instead of a string (the JSON API).
    int64_numbers: std::cell::Cell<bool>,
    /// `encode` writes a numeric as the Ledger API does: plain decimal text at the type's scale (`100.0000000000`, `0.0000000000`).
    ledger_numerics: std::cell::Cell<bool>,
    /// `encode` omits record fields whose value is `Value::Optional(None)` (JSON Ledger API v2 `createArgument`/`viewValue` behavior).
    omit_none_fields: std::cell::Cell<bool>,
    /// `encode` drops only trailing `Value::Optional(None)` fields in records, keeping non-trailing `None` fields as JSON `null` (`Canton 3.7.2` `JsonCodec.removeTrailingNonesInRecords = true`).
    remove_trailing_nones: std::cell::Cell<bool>,
}

impl<'w> Types<'w> {
    pub fn new(world: &'w World) -> Self {
        Self {
            world,
            api_numerics: std::cell::Cell::new(false),
            int64_numbers: std::cell::Cell::new(false),
            ledger_numerics: std::cell::Cell::new(false),
            omit_none_fields: std::cell::Cell::new(false),
            remove_trailing_nones: std::cell::Cell::new(false),
        }
    }

    /// The declared type of the top-level value `module:name` of `package_id`.
    pub fn value_type(&self, package_id: &str, module: &str, name: &str) -> Res<LfType> {
        let package = self.package(package_id)?;
        for m in &package.modules {
            if dotted(package, m.name_interned_dname)? != module {
                continue;
            }
            for v in &m.values {
                let Some(named) = &v.name_with_type else {
                    continue;
                };
                if dotted(package, named.name_interned_dname)? == name {
                    let ty = named.r#type.as_ref().ok_or("a value without a type")?;
                    return self.resolve(package_id, ty);
                }
            }
        }
        Err(format!("no value {module}:{name} in {package_id}"))
    }

    /// Writes the value a `Script a` ends with as `daml script --output-file` writes it: the Daml-LF JSON encoding of `a`
    /// (`ApiCodecCompressed`) with an `Int64` as a JSON number (measured: `pureScript` prints `42`, `keys` `{"_1":6,...}`) and a `Time` as
    /// RFC 3339 in UTC (`"1970-01-01T00:00:00Z"`), `script_type` being the script's declared type `Script a`.
    pub fn encode_script_result(&self, script_type: &LfType, value: &Value) -> Res<Json> {
        let result = match script_type {
            LfType::Con { name, args, .. } if name == "Script" && args.len() == 1 => &args[0],
            other => return Err(format!("a script's type is `Script a`, not {other:?}")),
        };
        self.int64_numbers.set(true);
        let out = self.encode(result, value);
        self.int64_numbers.set(false);
        out
    }

    /// Like `encode`, as the scan app prints the payload of a **contract** (`ApiCodecCompressed`): a numeric without its trailing zeros
    /// (`0.0`, `16.67`, `400000.0`). The update history writes the same values as `0E-10`, `16.6700000000`-style Java text (S-SPL-006).
    pub fn encode_contract(&self, ty: &LfType, value: &Value) -> Res<Json> {
        self.api_numerics.set(true);
        let out = self.encode(ty, value);
        self.api_numerics.set(false);
        out
    }

    /// Like `encode`, as a participant's Ledger API JSON writes a contract argument: a numeric as plain decimal text at its scale
    /// (`100.0000000000`; the scan's history writes the Java text `0E-10` and its contract view trims the zeros).
    ///
    /// [CANTON-NOTE: SEMANTICS] Matches Canton 3.7.2 `SchemaProcessorsImpl.scala:251` (`removeTrailingNonesInRecords = true`) and
    /// `JsonCodec.scala:66-68` (`values.toSeq.reverse.dropWhile((_, v) => v.isNull).reverse`): drops only trailing
    /// `Optional(None)` fields while keeping non-trailing `Optional(None)` fields as `null`.
    pub fn encode_ledger_api(&self, ty: &LfType, value: &Value) -> Res<Json> {
        let prev_num = self.ledger_numerics.replace(true);
        let prev_trail = self.remove_trailing_nones.replace(true);
        let out = self.encode(ty, value);
        self.remove_trailing_nones.set(prev_trail);
        self.ledger_numerics.set(prev_num);
        out
    }

    /// Like [`Self::encode_ledger_api`], omitting record fields whose value is `None` (`Optional(None)`).
    pub fn encode_ledger_api_omitting_nulls(&self, ty: &LfType, value: &Value) -> Res<Json> {
        let prev_num = self.ledger_numerics.replace(true);
        let prev_omit = self.omit_none_fields.replace(true);
        let out = self.encode(ty, value);
        self.omit_none_fields.set(prev_omit);
        self.ledger_numerics.set(prev_num);
        out
    }

    pub(crate) fn package(&self, package_id: &str) -> Res<&'w Package> {
        self.world
            .packages
            .get(package_id)
            .ok_or_else(|| format!("package {package_id} is not loaded"))
    }

    /// The name the package declares for itself (its metadata), which a ledger event's `package_name` states.
    pub fn package_name(&self, package_id: &str) -> Res<String> {
        let package = self.package(package_id)?;
        lf_archive::resolve_metadata(package)
            .map_err(|e| e.to_string())?
            .0
            .ok_or_else(|| format!("package {package_id} declares no name"))
    }

    /// The name and the version the package declares for itself (its metadata); `None` for a package without them.
    pub fn package_name_and_version(&self, package_id: &str) -> Option<(String, String)> {
        let package = self.package(package_id).ok()?;
        let (name, version) = lf_archive::resolve_metadata(package).ok()?;
        Some((name?, version.unwrap_or_default()))
    }

    /// Whether the package is one the world holds.
    pub fn knows_package(&self, package_id: &str) -> bool {
        self.world.packages.contains_key(package_id)
    }

    pub(crate) fn resolve(&self, package_id: &str, ty: &Type) -> Res<LfType> {
        let package = self.package(package_id)?;
        Ok(match ty.sum.as_ref().ok_or("a type without content")? {
            TypeSum::InternedType(i) => {
                let inner = usize::try_from(*i)
                    .ok()
                    .and_then(|i| package.interned_types.get(i))
                    .ok_or("an interned type outside the table")?;
                self.resolve(package_id, inner)?
            }
            TypeSum::Builtin(b) => builtin(
                b.builtin,
                b.args
                    .iter()
                    .map(|a| self.resolve(package_id, a))
                    .collect::<Res<_>>()?,
            ),
            TypeSum::Con(c) => {
                let tycon = c.tycon.as_ref().ok_or("a constructor without a name")?;
                let module = tycon
                    .module
                    .as_ref()
                    .ok_or("a constructor without a module")?;
                LfType::Con {
                    package_id: crate::package_of_reference_in(
                        package,
                        package_id,
                        module.package_id.as_ref(),
                        "a type constructor",
                    )
                    .map_err(|e| e.to_string())?,
                    module: dotted(package, module.module_name_interned_dname)?,
                    name: dotted(package, tycon.name_interned_dname)?,
                    args: c
                        .args
                        .iter()
                        .map(|a| self.resolve(package_id, a))
                        .collect::<Res<_>>()?,
                }
            }
            TypeSum::Var(v) if v.args.is_empty() => {
                LfType::Var(string(package, v.var_interned_str)?)
            }
            TypeSum::Nat(n) => LfType::Nat(*n),
            TypeSum::Tapp(app) => {
                let head = self.resolve(
                    package_id,
                    app.lhs
                        .as_deref()
                        .ok_or("an application without a function")?,
                )?;
                let arg = self.resolve(
                    package_id,
                    app.rhs
                        .as_deref()
                        .ok_or("an application without an argument")?,
                )?;
                match head {
                    LfType::Con {
                        package_id,
                        module,
                        name,
                        mut args,
                    } => {
                        args.push(arg);
                        LfType::Con {
                            package_id,
                            module,
                            name,
                            args,
                        }
                    }
                    LfType::Partial(code, mut args) => {
                        args.push(arg);
                        builtin(code, args)
                    }
                    other => LfType::Unsupported(format!("an application of {other:?}")),
                }
            }
            other => LfType::Unsupported(format!("{other:?}").chars().take(40).collect()),
        })
    }

    pub(crate) fn data(
        &self,
        package_id: &str,
        module: &str,
        name: &str,
    ) -> Res<(&'w Package, &'w DefDataType)> {
        let package = self.package(package_id)?;
        for m in &package.modules {
            if dotted(package, m.name_interned_dname)? != module {
                continue;
            }
            for d in &m.data_types {
                if dotted(package, d.name_interned_dname)? == name {
                    return Ok((package, d));
                }
            }
        }
        Err(format!("no data type {module}:{name} in {package_id}"))
    }

    /// The type of the payload of the template `Module:Entity` of `package_id`.
    pub fn template(&self, package_id: &str, template_id: &str) -> Res<LfType> {
        let (module, name) = split(template_id)?;
        self.data(package_id, module, name)?;
        Ok(LfType::Con {
            package_id: package_id.to_string(),
            module: module.to_string(),
            name: name.to_string(),
            args: Vec::new(),
        })
    }

    /// The fields of a record type, in declaration order, with the type arguments substituted (`Err` for a variant, an enum or an
    /// interface). Used by the participant to write a template argument in the forms the protocol hashes and serializes.
    /// The constructors of a variant type in declaration order (the rank of a constructor is its index), each with its type, type arguments
    /// substituted; or, for an enum type, the constructors with a unit type.
    pub fn constructors(&self, ty: &LfType) -> Res<Vec<(String, LfType)>> {
        let LfType::Con {
            package_id,
            module,
            name,
            args,
        } = ty
        else {
            return Err(format!("{ty:?} is not a variant or enum type"));
        };
        let (package, def) = self.data(package_id, module, name)?;
        let params: Vec<String> = def
            .params
            .iter()
            .map(|p| string(package, p.var_interned_str))
            .collect::<Res<_>>()?;
        match def.data_cons.as_ref() {
            Some(DataCons::Variant(variant)) => variant
                .fields
                .iter()
                .map(|f| {
                    let label = string(package, f.field_interned_str)?;
                    let t = self.resolve(
                        package_id,
                        f.r#type.as_ref().ok_or("a field without a type")?,
                    )?;
                    Ok((label, substitute(&t, &params, args)))
                })
                .collect(),
            Some(DataCons::Enum(e)) => e
                .constructors_interned_str
                .iter()
                .map(|i| Ok((string(package, *i)?, LfType::Unit)))
                .collect(),
            _ => Err(format!("{module}:{name} is not a variant or an enum")),
        }
    }

    pub fn record_fields(&self, ty: &LfType) -> Res<Vec<(String, LfType)>> {
        let LfType::Con {
            package_id,
            module,
            name,
            args,
        } = ty
        else {
            return Err(format!("{ty:?} is not a record type"));
        };
        let (package, def) = self.data(package_id, module, name)?;
        let params: Vec<String> = def
            .params
            .iter()
            .map(|p| string(package, p.var_interned_str))
            .collect::<Res<_>>()?;
        if params.len() != args.len() {
            return Err(format!(
                "{module}:{name} takes {} type arguments",
                params.len()
            ));
        }
        let Some(DataCons::Record(record)) = def.data_cons.as_ref() else {
            return Err(format!("{module}:{name} is not a record"));
        };
        record
            .fields
            .iter()
            .map(|f| {
                let label = string(package, f.field_interned_str)?;
                let t = self.resolve(
                    package_id,
                    f.r#type.as_ref().ok_or("a field without a type")?,
                )?;
                Ok((label, substitute(&t, &params, args)))
            })
            .collect()
    }

    /// The types of `choice` of the template `Module:Entity` of `package_id`.
    /// The types of choice `choice` of the interface `interface_id` (`Module:Name`) defined in `package_id`.
    pub fn interface_choice(
        &self,
        package_id: &str,
        interface_id: &str,
        choice: &str,
    ) -> Res<ChoiceTypes> {
        let (module, name) = split(interface_id)?;
        let package = self.package(package_id)?;
        for m in &package.modules {
            if dotted(package, m.name_interned_dname)? != module {
                continue;
            }
            for i in &m.interfaces {
                if dotted(package, i.tycon_interned_dname)? != name {
                    continue;
                }
                for c in &i.choices {
                    if string(package, c.name_interned_str)? != choice {
                        continue;
                    }
                    let argument = c
                        .arg_binder
                        .as_ref()
                        .and_then(|b| b.r#type.as_ref())
                        .ok_or("a choice without an argument type")?;
                    let result = c
                        .ret_type
                        .as_ref()
                        .ok_or("a choice without a result type")?;
                    return Ok(ChoiceTypes {
                        argument: self.resolve(package_id, argument)?,
                        result: self.resolve(package_id, result)?,
                        consuming: c.consuming,
                    });
                }
            }
        }
        Err(format!(
            "no choice {choice} of the interface {interface_id} in {package_id}"
        ))
    }

    /// The view type of the interface `interface_id` (`Module:Name`) defined in `package_id`.
    pub fn interface_view_type(&self, package_id: &str, interface_id: &str) -> Res<LfType> {
        let (module, name) = split(interface_id)?;
        let package = self.package(package_id)?;
        for m in &package.modules {
            if dotted(package, m.name_interned_dname)? != module {
                continue;
            }
            for i in &m.interfaces {
                if dotted(package, i.tycon_interned_dname)? != name {
                    continue;
                }
                let view_ty = i.view.as_ref().ok_or("an interface without a view type")?;
                return self.resolve(package_id, view_ty);
            }
        }
        Err(format!("no interface {interface_id} in {package_id}"))
    }

    /// Resolves the contract key type of `template_id` in `package_id`, if the template declares one.
    pub fn template_key_type(&self, package_id: &str, template_id: &str) -> Res<Option<LfType>> {
        let (module, name) = split(template_id)?;
        let package = self.package(package_id)?;
        for m in &package.modules {
            if dotted(package, m.name_interned_dname)? != module {
                continue;
            }
            for t in &m.templates {
                if dotted(package, t.tycon_interned_dname)? != name {
                    continue;
                }
                return t
                    .key
                    .as_ref()
                    .and_then(|k| k.r#type.as_ref())
                    .map(|kt| self.resolve(package_id, kt))
                    .transpose();
            }
        }
        Err(format!("template {template_id} is not in {package_id}"))
    }

    pub fn choice(&self, package_id: &str, template_id: &str, choice: &str) -> Res<ChoiceTypes> {
        let (module, name) = split(template_id)?;
        let package = self.package(package_id)?;
        for m in &package.modules {
            if dotted(package, m.name_interned_dname)? != module {
                continue;
            }
            for t in &m.templates {
                if dotted(package, t.tycon_interned_dname)? != name {
                    continue;
                }
                for c in &t.choices {
                    if string(package, c.name_interned_str)? != choice {
                        continue;
                    }
                    let argument = c
                        .arg_binder
                        .as_ref()
                        .and_then(|b| b.r#type.as_ref())
                        .ok_or("a choice without an argument type")?;
                    let result = c
                        .ret_type
                        .as_ref()
                        .ok_or("a choice without a result type")?;
                    return Ok(ChoiceTypes {
                        argument: self.resolve(package_id, argument)?,
                        result: self.resolve(package_id, result)?,
                        consuming: c.consuming,
                    });
                }
            }
        }
        Err(format!(
            "no choice {choice} of {template_id} in {package_id}"
        ))
    }

    /// Reads `json` as a value of type `ty`.
    pub fn decode(&self, ty: &LfType, json: &Json) -> Res<Value> {
        self.decode_at(ty, json, "$")
    }

    fn decode_at(&self, ty: &LfType, json: &Json, path: &str) -> Res<Value> {
        let bad = || {
            format!("{path}: {json} is no {ty:?}")
                .chars()
                .take(300)
                .collect::<String>()
        };
        Ok(match ty {
            LfType::Unit => Value::Unit,
            LfType::Bool => Value::Bool(json.as_bool().ok_or_else(bad)?),
            LfType::Int64 => Value::Int64(match json {
                Json::String(s) => s.parse().map_err(|_| bad())?,
                Json::Number(n) => n.as_i64().ok_or_else(bad)?,
                _ => return Err(bad()),
            }),
            LfType::Text => Value::Text(json.as_str().ok_or_else(bad)?.to_string()),
            LfType::Party => Value::Party(json.as_str().ok_or_else(bad)?.to_string()),
            LfType::ContractId => Value::ContractId(json.as_str().ok_or_else(bad)?.to_string()),
            LfType::Timestamp => {
                Value::Int64(timestamp_micros(json.as_str().ok_or_else(bad)?).ok_or_else(bad)?)
            }
            LfType::Date => {
                Value::Int64(date_days(json.as_str().ok_or_else(bad)?).ok_or_else(bad)?)
            }
            LfType::Numeric(scale) => {
                let text = match json {
                    Json::String(s) => s.clone(),
                    Json::Number(n) => n.to_string(),
                    _ => return Err(bad()),
                };
                let (coeff, scale) = numeric(&text, scale.unwrap_or(10)).ok_or_else(bad)?;
                Value::Numeric { coeff, scale }
            }
            LfType::List(inner) => Value::List(
                json.as_array()
                    .ok_or_else(bad)?
                    .iter()
                    .enumerate()
                    .map(|(i, j)| self.decode_at(inner, j, &format!("{path}[{i}]")))
                    .collect::<Res<Vec<_>>>()?
                    .into(),
            ),
            LfType::Optional(inner) => {
                if matches!(**inner, LfType::Optional(_)) {
                    // an optional of an optional: `null`, `[]` (some none) or `[x]`
                    match json {
                        Json::Null => Value::Optional(None),
                        Json::Array(items) if items.is_empty() => {
                            Value::Optional(Some(Box::new(Value::Optional(None))))
                        }
                        Json::Array(items) if items.len() == 1 => {
                            Value::Optional(Some(Box::new(self.decode_at(inner, &items[0], path)?)))
                        }
                        _ => return Err(bad()),
                    }
                } else if json.is_null() {
                    Value::Optional(None)
                } else {
                    Value::Optional(Some(Box::new(self.decode_at(inner, json, path)?)))
                }
            }
            LfType::TextMap(inner) => {
                let entries: Vec<(Value, Value)> = json
                    .as_object()
                    .ok_or_else(bad)?
                    .iter()
                    .map(|(k, v)| {
                        Ok((
                            Value::Text(k.clone()),
                            self.decode_at(inner, v, &format!("{path}.{k}"))?,
                        ))
                    })
                    .collect::<Res<_>>()?;
                sorted_map(entries)?
            }
            LfType::GenMap(key, value) => sorted_map(
                json.as_array()
                    .ok_or_else(bad)?
                    .iter()
                    .map(|pair| {
                        let pair = pair.as_array().filter(|p| p.len() == 2).ok_or_else(bad)?;
                        Ok((
                            self.decode_at(key, &pair[0], path)?,
                            self.decode_at(value, &pair[1], path)?,
                        ))
                    })
                    .collect::<Res<_>>()?,
            )?,
            LfType::Con {
                package_id,
                module,
                name,
                args,
            } => {
                let (package, def) = self.data(package_id, module, name)?;
                let params: Vec<String> = def
                    .params
                    .iter()
                    .map(|p| string(package, p.var_interned_str))
                    .collect::<Res<_>>()?;
                if params.len() != args.len() {
                    return Err(format!(
                        "{path}: {module}:{name} takes {} type arguments, not {}",
                        params.len(),
                        args.len()
                    ));
                }
                let field_type = |t: Option<&Type>| -> Res<LfType> {
                    let resolved = self.resolve(package_id, t.ok_or("a field without a type")?)?;
                    Ok(substitute(&resolved, &params, args))
                };
                let tycon = Some(format!("{module}:{name}"));
                match def
                    .data_cons
                    .as_ref()
                    .ok_or("a data type without content")?
                {
                    DataCons::Record(record) => {
                        let object = json.as_object().ok_or_else(bad)?;
                        let mut fields = Vec::with_capacity(record.fields.len());
                        for f in &record.fields {
                            let label = string(package, f.field_interned_str)?;
                            let ty = field_type(f.r#type.as_ref())?;
                            let value = match (object.get(&label), &ty) {
                                (Some(j), _) => {
                                    self.decode_at(&ty, j, &format!("{path}.{label}"))?
                                }
                                (None, LfType::Optional(_)) => Value::Optional(None),
                                (None, _) => {
                                    return Err(format!(
                                        "{path}: the field {label} of {module}:{name} is missing"
                                    ))
                                }
                            };
                            fields.push((label, value));
                        }
                        if let Some(unknown) =
                            object.keys().find(|k| !fields.iter().any(|(l, _)| l == *k))
                        {
                            return Err(format!("{path}: {module}:{name} has no field {unknown}"));
                        }
                        Value::Record { tycon, fields }
                    }
                    DataCons::Variant(variant) => {
                        let tag = json.get("tag").and_then(Json::as_str).ok_or_else(bad)?;
                        let mut found = None;
                        for (rank, f) in (0u32..).zip(&variant.fields) {
                            if string(package, f.field_interned_str)? == tag {
                                found = Some((rank, field_type(f.r#type.as_ref())?));
                            }
                        }
                        let (rank, ty) = found.ok_or_else(|| {
                            format!("{path}: {module}:{name} has no constructor {tag}")
                        })?;
                        let inner = json.get("value").unwrap_or(&Json::Null);
                        Value::Variant {
                            tycon,
                            constructor: tag.to_string(),
                            rank: CtorRank::known(rank),
                            value: Box::new(self.decode_at(
                                &ty,
                                inner,
                                &format!("{path}.{tag}"),
                            )?),
                        }
                    }
                    DataCons::Enum(e) => {
                        let tag = json.as_str().ok_or_else(bad)?;
                        let known = e
                            .constructors_interned_str
                            .iter()
                            .map(|i| string(package, *i))
                            .collect::<Res<Vec<_>>>()?;
                        let rank = (0u32..)
                            .zip(&known)
                            .find_map(|(rank, k)| (k == tag).then_some(rank))
                            .ok_or_else(|| {
                                format!("{path}: {module}:{name} has no constructor {tag}")
                            })?;
                        Value::Enum {
                            tycon,
                            constructor: tag.to_string(),
                            rank: CtorRank::known(rank),
                        }
                    }
                    DataCons::Interface(_) => {
                        return Err(format!("{path}: {module}:{name} is an interface"))
                    }
                }
            }
            LfType::Var(_) | LfType::Nat(_) | LfType::Partial(..) | LfType::Unsupported(_) => {
                return Err(format!("{path}: a value of {ty:?} cannot be read"))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numerics_are_read_as_java_writes_them() {
        assert_eq!(
            numeric("4000.8000000000", 10),
            Some((40_008_000_000_000, 10))
        );
        assert_eq!(numeric("0E-10", 10), Some((0, 10)));
        assert_eq!(numeric("1.000E-7", 10), Some((1000, 10)));
        assert_eq!(numeric("-0.0000190259", 10), Some((-190_259, 10)));
        assert_eq!(numeric("1E+3", 10), Some((10_000_000_000_000, 10)));
        assert_eq!(numeric("5", 0), Some((5, 0)));
        // more decimal places than the scale holds
        assert_eq!(numeric("0.00000000001", 10), None);
        assert_eq!(numeric("x", 10), None);
    }

    #[test]
    fn times_and_dates_are_micros_and_days() {
        assert_eq!(timestamp_micros("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            timestamp_micros("1970-01-02T00:00:01.5Z"),
            Some(86_401_500_000)
        );
        assert_eq!(
            timestamp_micros("2026-11-14T01:35:00.465024Z"),
            Some(1_794_620_100_465_024)
        );
        assert_eq!(date_days("1970-01-01"), Some(0));
        assert_eq!(date_days("2000-03-01"), Some(11_017));
        assert_eq!(timestamp_micros("2026-11-14 01:35:00Z"), None);
    }

    fn text(s: &str) -> Value {
        Value::Text(s.to_string())
    }

    /// Commands sort map entries by key and keep the last of equal keys (Speedy `SMap.apply`, `entries.to(TreeMap)`);
    /// a contract argument's `GenMap` must already be strictly ordered (`SMap.fromStrictlyOrderedEntries`).
    #[test]
    fn map_inputs_are_ordered_as_speedy_imports_them() {
        let world = World {
            main_package_id: String::new(),
            packages: std::collections::HashMap::new(),
            val_cache: crate::world::ValCache::default(),
            ctor_cache: crate::world::CtorCache::default(),
        };
        let types = Types::new(&world);
        let gen = LfType::GenMap(Box::new(LfType::Text), Box::new(LfType::Int64));
        let json: Json = serde_json::from_str(r#"[["b","2"],["a","1"],["a","3"]]"#).unwrap();
        assert_eq!(
            types.decode(&gen, &json).unwrap(),
            Value::Map(vec![
                (text("a"), Value::Int64(3)),
                (text("b"), Value::Int64(2))
            ])
        );

        let unordered = Value::Map(vec![
            (text("b"), Value::Int64(2)),
            (text("a"), Value::Int64(1)),
        ]);
        let wire = types.to_wire(&gen, &unordered).unwrap();
        let err = types.from_wire(&gen, &wire).unwrap_err();
        assert!(err.contains("non-strictly ordered GenMap"), "{err}");
        let duplicate = Value::Map(vec![
            (text("a"), Value::Int64(2)),
            (text("a"), Value::Int64(1)),
        ]);
        let wire = types.to_wire(&gen, &duplicate).unwrap();
        assert!(types.from_wire(&gen, &wire).is_err());

        let text_map = LfType::TextMap(Box::new(LfType::Int64));
        let wire = types.to_wire(&text_map, &unordered).unwrap();
        assert_eq!(
            types.from_wire(&text_map, &wire).unwrap(),
            Value::Map(vec![
                (text("a"), Value::Int64(1)),
                (text("b"), Value::Int64(2))
            ])
        );
    }

    #[test]
    fn encode_ledger_api_omits_only_trailing_optional_nones() {
        use lf_archive::proto::daml_lf_2::{
            def_data_type, r#type, BuiltinType, DefDataType, FieldWithType, InternedDottedName,
            Module, Package, Type as ProtoType,
        };

        let req_text_ty = ProtoType {
            sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                builtin: BuiltinType::Text as i32,
                args: Vec::new(),
            })),
        };
        let opt_text_ty = ProtoType {
            sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                builtin: BuiltinType::Optional as i32,
                args: vec![req_text_ty.clone()],
            })),
        };
        // Record { a: Optional Text, b: Text, c: Optional Text }
        let dt = DefDataType {
            name_interned_dname: 1,
            data_cons: Some(def_data_type::DataCons::Record(def_data_type::Fields {
                fields: vec![
                    FieldWithType {
                        field_interned_str: 2,
                        r#type: Some(opt_text_ty.clone()),
                    },
                    FieldWithType {
                        field_interned_str: 3,
                        r#type: Some(req_text_ty),
                    },
                    FieldWithType {
                        field_interned_str: 4,
                        r#type: Some(opt_text_ty),
                    },
                ],
            })),
            serializable: true,
            ..Default::default()
        };
        let pkg = Package {
            modules: vec![Module {
                name_interned_dname: 0,
                data_types: vec![dt],
                ..Default::default()
            }],
            interned_strings: vec!["M".into(), "Rec".into(), "a".into(), "b".into(), "c".into()],
            interned_dotted_names: vec![
                InternedDottedName {
                    segments_interned_str: vec![0],
                },
                InternedDottedName {
                    segments_interned_str: vec![1],
                },
            ],
            ..Default::default()
        };
        let mut packages = std::collections::HashMap::new();
        packages.insert("pkg1".to_string(), pkg);
        let world = World {
            main_package_id: "pkg1".to_string(),
            packages,
            val_cache: crate::world::ValCache::default(),
            ctor_cache: crate::world::CtorCache::default(),
        };
        let types = Types::new(&world);
        let ty = LfType::Con {
            package_id: "pkg1".to_string(),
            module: "M".to_string(),
            name: "Rec".to_string(),
            args: Vec::new(),
        };
        let val = Value::Record {
            tycon: None,
            fields: vec![
                ("a".to_string(), Value::Optional(None)),
                ("b".to_string(), text("ok")),
                ("c".to_string(), Value::Optional(None)),
            ],
        };
        assert_eq!(
            types.encode_ledger_api(&ty, &val).unwrap(),
            serde_json::json!({ "a": null, "b": "ok" })
        );
        let with_tail = Value::Record {
            tycon: None,
            fields: vec![
                ("a".to_string(), Value::Optional(None)),
                ("b".to_string(), text("ok")),
                ("c".to_string(), Value::Optional(Some(Box::new(text("x"))))),
            ],
        };
        assert_eq!(
            types.encode_ledger_api(&ty, &with_tail).unwrap(),
            serde_json::json!({ "a": null, "b": "ok", "c": "x" })
        );
    }
}
