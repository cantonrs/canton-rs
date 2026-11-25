//! Canonical types (`CanonType`): the type keys of templates, interfaces and contract keys.

use lf_archive::proto::daml_lf_2;
use lf_archive::proto::daml_lf_2::{Package, Type};
use lf_archive::resolve_interned_string;

use crate::env::TypeEnv;
use crate::eval_error::EvalError;
use crate::machine_resolve::resolve_con_in;
use crate::{Machine, UNRESOLVED_TYPE};

impl<'a> Machine<'a> {
    /// Daml-LF 2.3 packages store many sub-expressions once in `Package.interned_exprs` and refer to them by
    /// index (`Expr.interned_expr`, field 44). Follow such references (in the current package) until a real
    /// expression is reached; a chain longer than the table or an index out of range is an error.
    /// The canonical key of a type in the current context (`CanonType::to_key`). Forms that need
    /// a definition to compare (`forall`, type synonyms) are an `Unsupported` error rather than a guess.
    pub(super) fn type_key(&self, ty: &Type) -> Result<String, EvalError> {
        Ok(self.canon_type(ty)?.to_key())
    }

    pub(super) fn canon_type(&self, ty: &Type) -> Result<CanonType, EvalError> {
        self.canon_type_in(self.package()?, &self.package_id, &self.type_env, ty, 0)
    }

    fn canon_type_in(
        &self,
        package: &Package,
        package_id: &str,
        type_env: &TypeEnv,
        ty: &Type,
        depth: usize,
    ) -> Result<CanonType, EvalError> {
        use daml_lf_2::r#type::Sum;
        if depth > 128 {
            return Err(EvalError::unsupported());
        }
        let fold_args = |mut base: CanonType, list: &[Type]| -> Result<CanonType, EvalError> {
            // [CANTON-NOTE: SEMANTICS] DecodeV2 turns LF 2.1 `.args` and LF 2.3 `TApp` into the same left-curried `Ast.TApp`.
            for arg in list {
                let rhs = self.canon_type_in(package, package_id, type_env, arg, depth + 1)?;
                base = CanonType::App(Box::new(base), Box::new(rhs));
            }
            Ok(base)
        };
        match ty.sum.as_ref().ok_or(EvalError::unsupported())? {
            Sum::Var(var) => {
                let name = resolve_interned_string(package, var.var_interned_str, "Type.var")
                    .map_err(|err| EvalError::Archive(err.to_string()))?;
                let bound = type_env
                    .iter()
                    .rev()
                    .find(|(n, _)| *n == name)
                    .map(|(_, key)| key.as_str())
                    .ok_or(EvalError::unsupported())?;
                fold_args(CanonType::parse(bound)?, &var.args)
            }
            Sum::Con(con) => {
                let id = con.tycon.as_ref().ok_or(EvalError::unsupported())?;
                let (pkg, qual) = resolve_con_in(package, package_id, id)?;
                let (module, name) = qual.split_once(':').ok_or(EvalError::unsupported())?;
                let base = CanonType::TyCon {
                    package_id: pkg,
                    module: module.to_string(),
                    name: name.to_string(),
                };
                fold_args(base, &con.args)
            }
            Sum::Builtin(b) => fold_args(CanonType::Builtin(b.builtin), &b.args),
            Sum::Nat(n) => Ok(CanonType::Nat(*n)),
            Sum::InternedType(index) => {
                let inner = usize::try_from(*index)
                    .ok()
                    .and_then(|i| package.interned_types.get(i))
                    .ok_or(EvalError::unsupported())?;
                self.canon_type_in(package, package_id, type_env, inner, depth + 1)
            }
            Sum::Tapp(app) => {
                let lhs = app.lhs.as_deref().ok_or(EvalError::unsupported())?;
                let rhs = app.rhs.as_deref().ok_or(EvalError::unsupported())?;
                let lhs_c = self.canon_type_in(package, package_id, type_env, lhs, depth + 1)?;
                let rhs_c = self.canon_type_in(package, package_id, type_env, rhs, depth + 1)?;
                Ok(CanonType::App(Box::new(lhs_c), Box::new(rhs_c)))
            }
            Sum::Struct(st) => {
                let mut fields = Vec::with_capacity(st.fields.len());
                for field in &st.fields {
                    let name = resolve_interned_string(
                        package,
                        field.field_interned_str,
                        "Type.struct.field",
                    )
                    .map_err(|err| EvalError::Archive(err.to_string()))?;
                    let fty = field.r#type.as_ref().ok_or(EvalError::unsupported())?;
                    fields.push((
                        name,
                        self.canon_type_in(package, package_id, type_env, fty, depth + 1)?,
                    ));
                }
                // [CANTON-NOTE: SEMANTICS] Struct.scala sorts TStruct fields alphabetically by field name.
                fields.sort_by(|a, b| a.0.cmp(&b.0));
                Ok(CanonType::Struct(fields))
            }
            Sum::Forall(_) | Sum::Syn(_) => Err(EvalError::unsupported()),
        }
    }

    /// `type_key`, or the marker `<unresolved>` (never equal to a real key, and refused by `FromAny`) for the forms
    /// it cannot name, so that merely applying such a type never fails an evaluation that did not need the key.
    pub(super) fn type_key_or_unresolved(&self, ty: &Type) -> String {
        self.type_key(ty)
            .unwrap_or_else(|_| UNRESOLVED_TYPE.to_string())
    }
}

/// Canonical Daml-LF type key matching `DecodeV2` currying, `TStruct` field sorting, and
/// `TypeOrdering` (`TypeOrdering.scala`, `Ref.scala`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CanonType {
    Builtin(i32),
    TyCon {
        package_id: String,
        module: String,
        name: String,
    },
    Nat(i64),
    Struct(Vec<(String, CanonType)>),
    App(Box<CanonType>, Box<CanonType>),
}

impl CanonType {
    fn rank(&self) -> u8 {
        match self {
            CanonType::Builtin(_) => 0,
            CanonType::TyCon { .. } => 1,
            CanonType::Nat(_) => 2,
            CanonType::Struct(_) => 3,
            CanonType::App(_, _) => 4,
        }
    }

    fn cmp_dotted(a: &str, b: &str) -> std::cmp::Ordering {
        a.split('.').cmp(b.split('.'))
    }

    pub(super) fn unapplied_tycon(&self) -> Option<String> {
        match self {
            CanonType::TyCon {
                package_id,
                module,
                name,
            } => Some(format!("{package_id}:{module}:{name}")),
            _ => None,
        }
    }

    pub(super) fn to_key(&self) -> String {
        match self {
            CanonType::Builtin(b) => b.to_string(),
            CanonType::TyCon {
                package_id,
                module,
                name,
            } => format!("{package_id}:{module}:{name}"),
            CanonType::Nat(n) => format!("nat{n}"),
            CanonType::Struct(fields) => {
                let parts: Vec<String> = fields
                    .iter()
                    .map(|(name, ty)| format!("{name}:{}", ty.to_key()))
                    .collect();
                format!("struct{{{}}}", parts.join(","))
            }
            CanonType::App(lhs, rhs) => format!("({} {})", lhs.to_key(), rhs.to_key()),
        }
    }

    pub(crate) fn parse(key: &str) -> Result<Self, EvalError> {
        if key.is_empty() || key == UNRESOLVED_TYPE {
            return Err(EvalError::unsupported());
        }
        if let Some(inner) = key.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
            let mut paren: i32 = 0;
            let mut brace: i32 = 0;
            for (idx, ch) in inner.char_indices() {
                match ch {
                    '(' => paren += 1,
                    ')' => {
                        paren -= 1;
                        if paren < 0 {
                            return Err(EvalError::unsupported());
                        }
                    }
                    '{' => brace += 1,
                    '}' => {
                        brace -= 1;
                        if brace < 0 {
                            return Err(EvalError::unsupported());
                        }
                    }
                    ' ' if paren == 0 && brace == 0 => {
                        let lhs = Self::parse(&inner[..idx])?;
                        let rhs = Self::parse(&inner[idx + 1..])?;
                        return Ok(CanonType::App(Box::new(lhs), Box::new(rhs)));
                    }
                    _ => {}
                }
            }
            return Err(EvalError::unsupported());
        }
        if let Some(body) = key
            .strip_prefix("struct{")
            .and_then(|s| s.strip_suffix('}'))
        {
            if body.is_empty() {
                return Ok(CanonType::Struct(Vec::new()));
            }
            let mut fields = Vec::new();
            let mut start = 0usize;
            let mut paren: i32 = 0;
            let mut brace: i32 = 0;
            for (idx, ch) in body.char_indices() {
                match ch {
                    '(' => paren += 1,
                    ')' => paren -= 1,
                    '{' => brace += 1,
                    '}' => brace -= 1,
                    ',' if paren == 0 && brace == 0 => {
                        fields.push(Self::parse_struct_field(&body[start..idx])?);
                        start = idx + 1;
                    }
                    _ => {}
                }
            }
            fields.push(Self::parse_struct_field(&body[start..])?);
            fields.sort_by(|a, b| a.0.cmp(&b.0));
            return Ok(CanonType::Struct(fields));
        }
        if !key.contains(':') {
            if let Some(rest) = key.strip_prefix("nat") {
                let n = rest.parse::<i64>().map_err(|_| EvalError::unsupported())?;
                return Ok(CanonType::Nat(n));
            }
            let b = key.parse::<i32>().map_err(|_| EvalError::unsupported())?;
            return Ok(CanonType::Builtin(b));
        }
        let mut parts = key.splitn(3, ':');
        let (Some(package_id), Some(module), Some(name)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(EvalError::unsupported());
        };
        Ok(CanonType::TyCon {
            package_id: package_id.to_string(),
            module: module.to_string(),
            name: name.to_string(),
        })
    }

    fn parse_struct_field(part: &str) -> Result<(String, CanonType), EvalError> {
        let (name, ty_str) = part.split_once(':').ok_or(EvalError::unsupported())?;
        Ok((name.to_string(), Self::parse(ty_str)?))
    }
}

impl Ord for CanonType {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match (self, other) {
            (CanonType::Builtin(a), CanonType::Builtin(b)) => a.cmp(b),
            (
                CanonType::TyCon {
                    package_id: p1,
                    module: m1,
                    name: n1,
                },
                CanonType::TyCon {
                    package_id: p2,
                    module: m2,
                    name: n2,
                },
            ) => p1
                .cmp(p2)
                .then_with(|| Self::cmp_dotted(m1, m2))
                .then_with(|| Self::cmp_dotted(n1, n2)),
            (CanonType::Nat(a), CanonType::Nat(b)) => a.cmp(b),
            // [CANTON-NOTE: SEMANTICS] TypeOrdering compares all TStruct field names before comparing field types.
            (CanonType::Struct(xs), CanonType::Struct(ys)) => {
                for ((nx, _), (ny, _)) in xs.iter().zip(ys) {
                    let ord = nx.cmp(ny);
                    if ord != Ordering::Equal {
                        return ord;
                    }
                }
                let len_ord = xs.len().cmp(&ys.len());
                if len_ord != Ordering::Equal {
                    return len_ord;
                }
                for ((_, tx), (_, ty)) in xs.iter().zip(ys) {
                    let ord = tx.cmp(ty);
                    if ord != Ordering::Equal {
                        return ord;
                    }
                }
                Ordering::Equal
            }
            (CanonType::App(l1, r1), CanonType::App(l2, r2)) => l1.cmp(l2).then_with(|| r1.cmp(r2)),
            (a, b) => a.rank().cmp(&b.rank()),
        }
    }
}

impl PartialOrd for CanonType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
