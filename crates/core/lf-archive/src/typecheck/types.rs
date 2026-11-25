//! The checker's kinds and types (`LKind`, `LType`), substitution and alpha-equivalence.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::proto::daml_lf_2::BuiltinType;

use super::STABLE_TUPLE2_PKG;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Ident {
    pub(crate) pkg: String,
    pub(crate) module: String,
    pub(crate) name: String,
}

impl Ident {
    pub(super) fn pretty(&self) -> String {
        format!("{}:{}:{}", self.pkg, self.module, self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LKind {
    Star,
    Nat,
    Arrow(Box<LKind>, Box<LKind>),
}

impl LKind {
    pub(super) fn pretty(&self) -> String {
        match self {
            LKind::Star => "*".to_string(),
            LKind::Nat => "Nat".to_string(),
            LKind::Arrow(a, b) => match **a {
                LKind::Arrow(_, _) => format!("({}) -> {}", a.pretty(), b.pretty()),
                _ => format!("{} -> {}", a.pretty(), b.pretty()),
            },
        }
    }

    pub(super) fn k_arrow(param: LKind, result: LKind) -> LKind {
        LKind::Arrow(Box::new(param), Box::new(result))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LType {
    Var(String),
    Nat(i64),
    Con(Ident),
    Builtin(BuiltinType),
    App(Box<LType>, Box<LType>),
    Forall {
        param: String,
        kind: LKind,
        body: Box<LType>,
    },
    Struct(BTreeMap<String, LType>),
    SynApp {
        syn: Ident,
        args: Vec<LType>,
    },
}

impl LType {
    pub(super) fn app(f: LType, a: LType) -> LType {
        LType::App(Box::new(f), Box::new(a))
    }

    fn builtin(b: BuiltinType) -> LType {
        LType::Builtin(b)
    }

    pub(super) fn arrow(from: LType, to: LType) -> LType {
        LType::app(LType::app(LType::builtin(BuiltinType::Arrow), from), to)
    }

    pub(super) fn t_unit() -> LType {
        LType::builtin(BuiltinType::Unit)
    }
    pub(super) fn t_bool() -> LType {
        LType::builtin(BuiltinType::Bool)
    }
    pub(super) fn t_int64() -> LType {
        LType::builtin(BuiltinType::Int64)
    }
    pub(super) fn t_text() -> LType {
        LType::builtin(BuiltinType::Text)
    }
    pub(super) fn t_timestamp() -> LType {
        LType::builtin(BuiltinType::Timestamp)
    }
    pub(super) fn t_date() -> LType {
        LType::builtin(BuiltinType::Date)
    }
    pub(super) fn t_party() -> LType {
        LType::builtin(BuiltinType::Party)
    }
    pub(super) fn t_any() -> LType {
        LType::builtin(BuiltinType::Any)
    }
    pub(super) fn t_typerep() -> LType {
        LType::builtin(BuiltinType::TypeRep)
    }
    pub(super) fn t_any_exception() -> LType {
        LType::builtin(BuiltinType::AnyException)
    }
    pub(super) fn t_rounding_mode() -> LType {
        LType::builtin(BuiltinType::RoundingMode)
    }
    pub(super) fn t_bignumeric() -> LType {
        LType::builtin(BuiltinType::Bignumeric)
    }
    pub(super) fn t_failure_category() -> LType {
        LType::builtin(BuiltinType::FailureCategory)
    }
    pub(super) fn t_numeric(scale: LType) -> LType {
        LType::app(LType::builtin(BuiltinType::Numeric), scale)
    }
    pub(super) fn t_list(elem: LType) -> LType {
        LType::app(LType::builtin(BuiltinType::List), elem)
    }
    pub(super) fn t_optional(elem: LType) -> LType {
        LType::app(LType::builtin(BuiltinType::Optional), elem)
    }
    pub(super) fn t_textmap(val: LType) -> LType {
        LType::app(LType::builtin(BuiltinType::Textmap), val)
    }
    pub(super) fn t_genmap(k: LType, v: LType) -> LType {
        LType::app(LType::app(LType::builtin(BuiltinType::Genmap), k), v)
    }
    pub(super) fn t_update(res: LType) -> LType {
        LType::app(LType::builtin(BuiltinType::Update), res)
    }
    pub(super) fn t_contract_id(t: LType) -> LType {
        LType::app(LType::builtin(BuiltinType::ContractId), t)
    }
    pub(super) fn t_parties() -> LType {
        LType::t_list(LType::t_party())
    }
    pub(super) fn t_tuple2(t1: LType, t2: LType) -> LType {
        let id = Ident {
            pkg: STABLE_TUPLE2_PKG.to_string(),
            module: "DA.Types".to_string(),
            name: "Tuple2".to_string(),
        };
        LType::app(LType::app(LType::Con(id), t1), t2)
    }

    pub(super) fn contains_syn_app(&self) -> bool {
        match self {
            LType::SynApp { .. } => true,
            LType::App(f, a) => f.contains_syn_app() || a.contains_syn_app(),
            LType::Forall { body, .. } => body.contains_syn_app(),
            LType::Struct(fields) => fields.values().any(LType::contains_syn_app),
            LType::Var(_) | LType::Nat(_) | LType::Con(_) | LType::Builtin(_) => false,
        }
    }

    /// Collect free type variables in `self`.
    fn free_vars(&self, out: &mut HashSet<String>) {
        match self {
            LType::Var(v) => {
                out.insert(v.clone());
            }
            LType::Nat(_) | LType::Con(_) | LType::Builtin(_) => {}
            LType::App(f, a) => {
                f.free_vars(out);
                a.free_vars(out);
            }
            LType::Forall { param, body, .. } => {
                let mut inner = HashSet::new();
                body.free_vars(&mut inner);
                inner.remove(param);
                out.extend(inner);
            }
            LType::Struct(fields) => {
                for t in fields.values() {
                    t.free_vars(out);
                }
            }
            LType::SynApp { args, .. } => {
                for a in args {
                    a.free_vars(out);
                }
            }
        }
    }

    pub(super) fn pretty(&self) -> String {
        match self {
            LType::Var(v) => v.clone(),
            LType::Nat(n) => n.to_string(),
            LType::Con(id) => format!("{}:{}", id.module, id.name),
            LType::Builtin(b) => format!("{b:?}"),
            LType::App(f, a) => {
                if let LType::App(ff, arg) = &**f {
                    if matches!(**ff, LType::Builtin(BuiltinType::Arrow)) {
                        return format!("({} -> {})", arg.pretty(), a.pretty());
                    }
                }
                format!("({} {})", f.pretty(), a.pretty())
            }
            LType::Forall { param, kind, body } => {
                format!("(forall ({param} : {}). {})", kind.pretty(), body.pretty())
            }
            LType::Struct(fields) => {
                let inner: Vec<String> = fields
                    .iter()
                    .map(|(k, v)| format!("{k}: {}", v.pretty()))
                    .collect();
                format!("<{}>", inner.join(", "))
            }
            LType::SynApp { syn, args } => {
                let args_s: Vec<String> = args.iter().map(LType::pretty).collect();
                format!("||{}||({})", syn.pretty(), args_s.join(", "))
            }
        }
    }
}

/// Capture-avoiding substitution `TypeSubst.substitute` from Canton `TypeSubst.scala`.
pub(super) fn subst_type(subst: &HashMap<String, LType>, ty: &LType) -> LType {
    if subst.is_empty() {
        return ty.clone();
    }
    let mut fv = HashSet::new();
    for v in subst.values() {
        v.free_vars(&mut fv);
    }
    subst_go(&fv, subst, ty)
}

fn fresh_type_var(fv: &HashSet<String>) -> String {
    for i in 0usize.. {
        let candidate = format!("$freshVar{i}");
        if !fv.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!()
}

fn subst_go(fv: &HashSet<String>, subst: &HashMap<String, LType>, ty: &LType) -> LType {
    match ty {
        LType::Var(name) => subst.get(name).cloned().unwrap_or_else(|| ty.clone()),
        LType::Con(_) | LType::Builtin(_) | LType::Nat(_) => ty.clone(),
        LType::App(f, a) => LType::app(subst_go(fv, subst, f), subst_go(fv, subst, a)),
        LType::SynApp { syn, args } => LType::SynApp {
            syn: syn.clone(),
            args: args.iter().map(|a| subst_go(fv, subst, a)).collect(),
        },
        LType::Struct(fields) => LType::Struct(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), subst_go(fv, subst, v)))
                .collect(),
        ),
        LType::Forall { param, kind, body } => {
            if fv.contains(param) {
                let v1 = fresh_type_var(fv);
                let mut fv1 = fv.clone();
                fv1.insert(v1.clone());
                let mut subst1 = subst.clone();
                subst1.insert(param.clone(), LType::Var(v1.clone()));
                LType::Forall {
                    param: v1,
                    kind: kind.clone(),
                    body: Box::new(subst_go(&fv1, &subst1, body)),
                }
            } else {
                let mut fv1 = fv.clone();
                fv1.insert(param.clone());
                let mut subst1 = subst.clone();
                subst1.remove(param);
                LType::Forall {
                    param: param.clone(),
                    kind: kind.clone(),
                    body: Box::new(subst_go(&fv1, &subst1, body)),
                }
            }
        }
    }
}

pub(super) fn subst_one(var: &str, replacement: &LType, ty: &LType) -> LType {
    let mut map = HashMap::with_capacity(1);
    map.insert(var.to_string(), replacement.clone());
    subst_type(&map, ty)
}

/// De-Bruijn alpha equivalence matching `AlphaEquiv.scala` (with nominal `SynApp` first).
pub(super) fn alpha_equiv_nominal(t1: &LType, t2: &LType) -> bool {
    struct Env {
        depth: usize,
        lhs: HashMap<String, usize>,
        rhs: HashMap<String, usize>,
    }
    impl Env {
        fn extend(&self, v1: &str, v2: &str) -> Self {
            let mut lhs = self.lhs.clone();
            let mut rhs = self.rhs.clone();
            lhs.insert(v1.to_string(), self.depth);
            rhs.insert(v2.to_string(), self.depth);
            Self {
                depth: self.depth + 1,
                lhs,
                rhs,
            }
        }
    }
    fn go(env: &Env, a: &LType, b: &LType) -> bool {
        match (a, b) {
            (LType::Var(x1), LType::Var(x2)) => match (env.lhs.get(x1), env.rhs.get(x2)) {
                (Some(d1), Some(d2)) => d1 == d2,
                (None, None) => x1 == x2,
                _ => false,
            },
            (LType::Nat(n1), LType::Nat(n2)) => n1 == n2,
            (LType::Con(c1), LType::Con(c2)) => c1 == c2,
            (LType::Builtin(b1), LType::Builtin(b2)) => b1 == b2,
            (LType::App(f1, a1), LType::App(f2, a2)) => go(env, f1, f2) && go(env, a1, a2),
            (
                LType::Forall {
                    param: p1,
                    kind: k1,
                    body: b1,
                },
                LType::Forall {
                    param: p2,
                    kind: k2,
                    body: b2,
                },
            ) => k1 == k2 && go(&env.extend(p1, p2), b1, b2),
            (LType::Struct(fs1), LType::Struct(fs2)) => {
                fs1.len() == fs2.len()
                    && fs1
                        .iter()
                        .zip(fs2.iter())
                        .all(|((n1, t1), (n2, t2))| n1 == n2 && go(env, t1, t2))
            }
            (LType::SynApp { syn: s1, args: xs1 }, LType::SynApp { syn: s2, args: xs2 }) => {
                s1 == s2
                    && xs1.len() == xs2.len()
                    && xs1.iter().zip(xs2.iter()).all(|(x, y)| go(env, x, y))
            }
            _ => false,
        }
    }
    go(
        &Env {
            depth: 0,
            lhs: HashMap::new(),
            rhs: HashMap::new(),
        },
        t1,
        t2,
    )
}
