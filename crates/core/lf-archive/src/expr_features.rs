//! Expression- and type-level Daml-LF feature gates: the checks Canton 3.7.2 `DecodeV2` makes while it decodes each
//! type and expression of a package (`assertSince` on version-ranged builtins, `assertVersionSupports` on gated
//! expression and update cases).

use crate::error::DecodeError;
use crate::features::{
    Feature, BIG_NUMERIC, CHOICE_FUNCS, CONTRACT_KEYS, DEV, EXTENDED_CRYPTO, EXTENDED_INTERFACES,
    EXTERNAL_CALL, FLAT_ARCHIVE, UNPACK, UNSAFE_FROM_INTERFACE, UNSTABLE,
};
use crate::proto::daml_lf_2::{
    builtin_lit, def_data_type::DataCons, expr::Sum as E, r#type::Sum as T, update::Sum as U,
    BuiltinFunction, BuiltinType, Expr, Package, TemplateChoice, Type, Update,
};

enum Node<'a> {
    Expr(&'a Expr),
    Type(&'a Type),
    Update(&'a Update),
}

struct Walk<'a> {
    package: &'a Package,
    rank: u32,
    minor: &'a str,
    stack: Vec<Node<'a>>,
    /// Interned expressions already walked: each table entry is checked once however often it is referenced.
    seen_exprs: Vec<bool>,
}

/// Refuses a package one of whose types or expressions uses a feature its LF version does not have.
///
/// [CANTON-NOTE: SEMANTICS] `decodeTypesTable` decodes the whole interned type table, so every entry is checked;
/// interned expressions are decoded where they are referenced, so only referenced entries are. The walk keeps an
/// explicit stack: a chain of interned expressions may be as long as the table.
pub(crate) fn check_expr_features(
    package: &Package,
    minor: &str,
    rank: u32,
) -> Result<(), DecodeError> {
    let mut walk = Walk {
        package,
        rank,
        minor,
        stack: Vec::new(),
        seen_exprs: vec![false; package.interned_exprs.len()],
    };
    for ty in &package.interned_types {
        walk.stack.push(Node::Type(ty));
    }
    walk.drain()?;
    for module in &package.modules {
        for def in &module.data_types {
            if let Some(DataCons::Record(fields) | DataCons::Variant(fields)) = &def.data_cons {
                walk.types(fields.fields.iter().filter_map(|f| f.r#type.as_ref()));
            }
        }
        for syn in &module.synonyms {
            walk.ty(syn.r#type.as_ref());
        }
        for value in &module.values {
            walk.ty(value
                .name_with_type
                .as_ref()
                .and_then(|n| n.r#type.as_ref()));
            walk.expr(value.expr.as_ref());
        }
        for template in &module.templates {
            walk.expr(template.precond.as_ref());
            walk.expr(template.signatories.as_ref());
            walk.expr(template.observers.as_ref());
            for choice in &template.choices {
                walk.choice(choice);
            }
            if let Some(key) = &template.key {
                walk.ty(key.r#type.as_ref());
                walk.expr(key.key_expr.as_ref());
                walk.expr(key.maintainers.as_ref());
            }
            for implements in &template.implements {
                if let Some(body) = &implements.body {
                    walk.exprs(body.methods.iter().filter_map(|m| m.value.as_ref()));
                    walk.expr(body.view.as_ref());
                }
            }
        }
        for exception in &module.exceptions {
            walk.expr(exception.message.as_ref());
        }
        for interface in &module.interfaces {
            walk.types(interface.methods.iter().filter_map(|m| m.r#type.as_ref()));
            walk.ty(interface.view.as_ref());
            for choice in &interface.choices {
                walk.choice(choice);
            }
        }
        walk.drain()?;
    }
    Ok(())
}

impl<'a> Walk<'a> {
    fn refuse(&self, description: &str) -> DecodeError {
        DecodeError::UnsupportedFeature(format!(
            "{description} is not supported by Daml-LF 2.{}",
            self.minor
        ))
    }

    /// `assertVersionSupports(feature, case)`.
    fn supports(&self, feature: Feature, case: Option<&str>) -> Result<(), DecodeError> {
        if feature.enabled_in(self.rank) {
            return Ok(());
        }
        Err(match case {
            Some(case) => self.refuse(&format!("{} (case {case})", feature.name)),
            None => self.refuse(feature.name),
        })
    }

    /// `assertSince(minVersion, description)`.
    fn since(&self, min: u32, description: impl FnOnce() -> String) -> Result<(), DecodeError> {
        if self.rank < min {
            return Err(self.refuse(&description()));
        }
        Ok(())
    }

    fn expr(&mut self, e: Option<&'a Expr>) {
        if let Some(e) = e {
            self.stack.push(Node::Expr(e));
        }
    }

    fn exprs(&mut self, es: impl Iterator<Item = &'a Expr>) {
        for e in es {
            self.stack.push(Node::Expr(e));
        }
    }

    fn ty(&mut self, t: Option<&'a Type>) {
        if let Some(t) = t {
            self.stack.push(Node::Type(t));
        }
    }

    fn types(&mut self, ts: impl Iterator<Item = &'a Type>) {
        for t in ts {
            self.stack.push(Node::Type(t));
        }
    }

    fn choice(&mut self, choice: &'a TemplateChoice) {
        self.expr(choice.controllers.as_ref());
        self.expr(choice.observers.as_ref());
        self.expr(choice.authorizers.as_ref());
        self.ty(choice.arg_binder.as_ref().and_then(|b| b.r#type.as_ref()));
        self.ty(choice.ret_type.as_ref());
        self.expr(choice.update.as_ref());
    }

    fn drain(&mut self) -> Result<(), DecodeError> {
        while let Some(node) = self.stack.pop() {
            match node {
                Node::Type(t) => self.visit_type(t)?,
                Node::Expr(e) => self.visit_expr(e)?,
                Node::Update(u) => self.visit_update(u)?,
            }
        }
        Ok(())
    }

    fn visit_type(&mut self, t: &'a Type) -> Result<(), DecodeError> {
        match &t.sum {
            Some(T::Builtin(b)) => {
                if let Ok(bt @ (BuiltinType::Bignumeric | BuiltinType::RoundingMode)) =
                    BuiltinType::try_from(b.builtin)
                {
                    self.since(BIG_NUMERIC.min, || {
                        format!("daml_lf_2.BuiltinType.{}", bt.as_str_name())
                    })?;
                }
                self.types(b.args.iter());
            }
            Some(T::Var(v)) => self.types(v.args.iter()),
            Some(T::Con(c)) => self.types(c.args.iter()),
            Some(T::Syn(s)) => self.types(s.args.iter()),
            Some(T::Forall(f)) => self.ty(f.body.as_deref()),
            Some(T::Struct(s)) => self.types(s.fields.iter().filter_map(|f| f.r#type.as_ref())),
            Some(T::Tapp(a)) => {
                self.ty(a.lhs.as_deref());
                self.ty(a.rhs.as_deref());
            }
            // the interned type table is walked as a whole
            Some(T::InternedType(_) | T::Nat(_)) | None => {}
        }
        Ok(())
    }

    fn builtin_min_version(bf: BuiltinFunction) -> Option<u32> {
        use BuiltinFunction as B;
        match bf {
            B::Secp256k1ValidateKey => Some(EXTENDED_CRYPTO.min),
            B::ScaleBignumeric
            | B::PrecisionBignumeric
            | B::AddBignumeric
            | B::SubBignumeric
            | B::MulBignumeric
            | B::DivBignumeric
            | B::ShiftRightBignumeric
            | B::BignumericToNumeric
            | B::NumericToBignumeric
            | B::BignumericToText => Some(BIG_NUMERIC.min),
            B::TypeRepTyconName => Some(UNSTABLE.min),
            B::ExternalCall => Some(EXTERNAL_CALL.min),
            B::ExternalCallLegacyDev => Some(DEV),
            _ => None,
        }
    }

    fn visit_expr(&mut self, e: &'a Expr) -> Result<(), DecodeError> {
        let Some(sum) = &e.sum else { return Ok(()) };
        match sum {
            E::Builtin(tag) => {
                if let Ok(bf) = BuiltinFunction::try_from(*tag) {
                    if let Some(min) = Self::builtin_min_version(bf) {
                        self.since(min, || {
                            format!("daml_lf_2.BuiltinFunction.{}", bf.as_str_name())
                        })?;
                    }
                }
            }
            E::BuiltinLit(lit) => {
                if let Some(builtin_lit::Sum::RoundingMode(_)) = lit.sum {
                    self.supports(BIG_NUMERIC, Some("Expr.rounding_mode"))?;
                }
            }
            E::InternedExpr(idx) => {
                self.supports(FLAT_ARCHIVE, Some("INTERNED_EXPR"))?;
                // an index out of range is the interning check's to report
                if let Some(i) = usize::try_from(*idx)
                    .ok()
                    .filter(|i| *i < self.seen_exprs.len())
                {
                    if !self.seen_exprs[i] {
                        self.seen_exprs[i] = true;
                        self.expr(self.package.interned_exprs.get(i));
                    }
                }
            }
            E::UnsafeFromInterface(x) => {
                self.supports(UNSAFE_FROM_INTERFACE, Some("Expr.unsafe_from_interface"))?;
                self.expr(x.contract_id_expr.as_deref());
                self.expr(x.interface_expr.as_deref());
            }
            E::ChoiceController(x) => {
                self.supports(CHOICE_FUNCS, Some("Expr.choice_controller"))?;
                self.expr(x.contract_expr.as_deref());
                self.expr(x.choice_arg_expr.as_deref());
            }
            E::ChoiceObserver(x) => {
                self.supports(CHOICE_FUNCS, Some("Expr.choice_observer"))?;
                self.expr(x.contract_expr.as_deref());
                self.expr(x.choice_arg_expr.as_deref());
            }
            E::Experimental(x) => {
                self.supports(UNSTABLE, None)?;
                self.ty(x.r#type.as_ref());
            }
            E::VarInternedStr(_) | E::Val(_) | E::BuiltinCon(_) | E::EnumCon(_) => {}
            E::RecCon(x) => {
                self.ty_con(x.tycon.as_ref());
                self.exprs(x.fields.iter().filter_map(|f| f.expr.as_ref()));
            }
            E::RecProj(x) => {
                self.ty_con(x.tycon.as_ref());
                self.expr(x.record.as_deref());
            }
            E::RecUpd(x) => {
                self.ty_con(x.tycon.as_ref());
                self.expr(x.record.as_deref());
                self.expr(x.update.as_deref());
            }
            E::VariantCon(x) => {
                self.ty_con(x.tycon.as_ref());
                self.expr(x.variant_arg.as_deref());
            }
            E::StructCon(x) => self.exprs(x.fields.iter().filter_map(|f| f.expr.as_ref())),
            E::StructProj(x) => self.expr(x.r#struct.as_deref()),
            E::StructUpd(x) => {
                self.expr(x.r#struct.as_deref());
                self.expr(x.update.as_deref());
            }
            E::App(x) => {
                self.expr(x.fun.as_deref());
                self.exprs(x.args.iter());
            }
            E::TyApp(x) => {
                self.expr(x.expr.as_deref());
                self.types(x.types.iter());
            }
            E::Abs(x) => {
                self.types(x.param.iter().filter_map(|p| p.r#type.as_ref()));
                self.expr(x.body.as_deref());
            }
            E::TyAbs(x) => self.expr(x.body.as_deref()),
            E::Case(x) => {
                self.expr(x.scrut.as_deref());
                self.exprs(x.alts.iter().filter_map(|a| a.body.as_ref()));
            }
            E::Let(x) => self.block(x),
            E::Nil(x) => self.ty(x.r#type.as_ref()),
            E::Cons(x) => {
                self.ty(x.r#type.as_ref());
                self.exprs(x.front.iter());
                self.expr(x.tail.as_deref());
            }
            E::Update(u) => self.stack.push(Node::Update(u)),
            E::OptionalNone(x) => self.ty(x.r#type.as_ref()),
            E::OptionalSome(x) => {
                self.ty(x.r#type.as_ref());
                self.expr(x.value.as_deref());
            }
            E::ToAny(x) => {
                self.ty(x.r#type.as_ref());
                self.expr(x.expr.as_deref());
            }
            E::FromAny(x) => {
                self.ty(x.r#type.as_ref());
                self.expr(x.expr.as_deref());
            }
            E::TypeRep(t) => self.ty(Some(t)),
            E::ToAnyException(x) => {
                self.ty(x.r#type.as_ref());
                self.expr(x.expr.as_deref());
            }
            E::FromAnyException(x) => {
                self.ty(x.r#type.as_ref());
                self.expr(x.expr.as_deref());
            }
            E::Throw(x) => {
                self.ty(x.return_type.as_ref());
                self.ty(x.exception_type.as_ref());
                self.expr(x.exception_expr.as_deref());
            }
            E::ToInterface(x) => self.expr(x.template_expr.as_deref()),
            E::FromInterface(x) => self.expr(x.interface_expr.as_deref()),
            E::CallInterface(x) => self.expr(x.interface_expr.as_deref()),
            E::SignatoryInterface(x) => self.expr(x.expr.as_deref()),
            E::ObserverInterface(x) => self.expr(x.expr.as_deref()),
            E::ViewInterface(x) => self.expr(x.expr.as_deref()),
            E::InterfaceTemplateTypeRep(x) => self.expr(x.expr.as_deref()),
            E::ToRequiredInterface(x) => self.expr(x.expr.as_deref()),
            E::FromRequiredInterface(x) => self.expr(x.expr.as_deref()),
            E::UnsafeFromRequiredInterface(x) => {
                self.expr(x.contract_id_expr.as_deref());
                self.expr(x.interface_expr.as_deref());
            }
        }
        Ok(())
    }

    fn ty_con(&mut self, con: Option<&'a crate::proto::daml_lf_2::r#type::Con>) {
        if let Some(con) = con {
            self.types(con.args.iter());
        }
    }

    fn block(&mut self, block: &'a crate::proto::daml_lf_2::Block) {
        for binding in &block.bindings {
            self.ty(binding.binder.as_ref().and_then(|b| b.r#type.as_ref()));
            self.expr(binding.bound.as_ref());
        }
        self.expr(block.body.as_deref());
    }

    fn visit_update(&mut self, u: &'a Update) -> Result<(), DecodeError> {
        let Some(sum) = &u.sum else { return Ok(()) };
        match sum {
            U::ExerciseByKey(x) => {
                self.supports(CONTRACT_KEYS, None)?;
                self.expr(x.key.as_deref());
                self.expr(x.arg.as_deref());
            }
            U::FetchByKey(_) | U::QueryNByKey(_) => self.supports(CONTRACT_KEYS, None)?,
            U::UnpackTemplate(x) => {
                self.supports(UNPACK, None)?;
                self.expr(x.cid.as_deref());
            }
            U::UnpackInterface(x) => {
                self.supports(UNPACK, None)?;
                self.expr(x.cid.as_deref());
            }
            U::ExerciseInterface(x) => {
                if x.guard.is_some() {
                    self.supports(EXTENDED_INTERFACES, Some("exerciseInterface.guard"))?;
                }
                self.expr(x.cid.as_deref());
                self.expr(x.arg.as_deref());
                self.expr(x.guard.as_deref());
            }
            U::Pure(x) => {
                self.ty(x.r#type.as_ref());
                self.expr(x.expr.as_deref());
            }
            U::Block(x) => self.block(x),
            U::Create(x) => self.expr(x.expr.as_deref()),
            U::CreateInterface(x) => self.expr(x.expr.as_deref()),
            U::Exercise(x) => {
                self.expr(x.cid.as_deref());
                self.expr(x.arg.as_deref());
            }
            U::Fetch(x) => self.expr(x.cid.as_deref()),
            U::FetchInterface(x) => self.expr(x.cid.as_deref()),
            U::GetTime(_) => {}
            U::EmbedExpr(x) => {
                self.ty(x.r#type.as_ref());
                self.expr(x.body.as_deref());
            }
            U::TryCatch(x) => {
                self.ty(x.return_type.as_ref());
                self.expr(x.try_expr.as_deref());
                self.expr(x.catch_expr.as_deref());
            }
            U::LedgerTimeLt(e) => self.expr(Some(e)),
        }
        Ok(())
    }
}
