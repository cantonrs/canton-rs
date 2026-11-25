//! Package and module checks of the validator: definition lookups, module typing, templates, interfaces, exceptions and serializability.

use std::collections::{HashMap, HashSet};

use crate::proto::daml_lf_2;
use crate::proto::daml_lf_2::{BuiltinType, Package};

use super::decode::{
    dotted_string, err, DecodedDataCons, DecodedDataType, DecodedException, DecodedInterface,
    DecodedTemplate, DecodedTypeSyn, DecodedValue,
};
use super::types::{Ident, LKind, LType};
use super::typing_env::TypingEnv;
use super::{check_kind, TypeError, Validator};

impl<'a> Validator<'a> {
    pub(super) fn lookup_data_type(
        &self,
        ctx_pkg: &str,
        id: &Ident,
    ) -> Result<Option<&DecodedDataType>, TypeError> {
        if let Some(d) = self.data_types.get(id) {
            return Ok(Some(d));
        }
        if !self.packages.contains_key(&id.pkg) {
            // Package outside the validated set (provided via participant `known`).
            return Ok(None);
        }
        Err(err(
            ctx_pkg,
            "EUnknownDefinition",
            format!("unknown data type {}", id.pretty()),
        ))
    }

    pub(super) fn lookup_type_syn(
        &self,
        ctx_pkg: &str,
        id: &Ident,
    ) -> Result<Option<&DecodedTypeSyn>, TypeError> {
        if let Some(s) = self.type_syns.get(id) {
            return Ok(Some(s));
        }
        if !self.packages.contains_key(&id.pkg) {
            return Ok(None);
        }
        Err(err(
            ctx_pkg,
            "EUnknownDefinition",
            format!("unknown type synonym {}", id.pretty()),
        ))
    }

    pub(super) fn lookup_value(
        &self,
        ctx_pkg: &str,
        id: &Ident,
    ) -> Result<Option<&DecodedValue>, TypeError> {
        if let Some(v) = self.values.get(id) {
            return Ok(Some(v));
        }
        if !self.packages.contains_key(&id.pkg) {
            return Ok(None);
        }
        Err(err(
            ctx_pkg,
            "EUnknownDefinition",
            format!("unknown value {}", id.pretty()),
        ))
    }

    pub(super) fn lookup_template(
        &self,
        ctx_pkg: &str,
        id: &Ident,
    ) -> Result<Option<&DecodedTemplate<'a>>, TypeError> {
        if let Some(t) = self.templates.get(id) {
            return Ok(Some(t));
        }
        if !self.packages.contains_key(&id.pkg) {
            return Ok(None);
        }
        Err(err(
            ctx_pkg,
            "EUnknownDefinition",
            format!("unknown template {}", id.pretty()),
        ))
    }

    pub(super) fn lookup_interface(
        &self,
        ctx_pkg: &str,
        id: &Ident,
    ) -> Result<Option<&DecodedInterface<'a>>, TypeError> {
        if let Some(i) = self.interfaces.get(id) {
            return Ok(Some(i));
        }
        if !self.packages.contains_key(&id.pkg) {
            return Ok(None);
        }
        Err(err(
            ctx_pkg,
            "EUnknownDefinition",
            format!("unknown interface {}", id.pretty()),
        ))
    }

    pub(super) fn lookup_exception(
        &self,
        ctx_pkg: &str,
        id: &Ident,
    ) -> Result<Option<&DecodedException<'a>>, TypeError> {
        if let Some(e) = self.exceptions.get(id) {
            return Ok(Some(e));
        }
        if !self.packages.contains_key(&id.pkg) {
            return Ok(None);
        }
        Err(err(
            ctx_pkg,
            "EUnknownDefinition",
            format!("unknown exception {}", id.pretty()),
        ))
    }

    pub(super) fn check_package(&self, pkg_id: &str, pkg: &Package) -> Result<(), TypeError> {
        self.check_dependencies_and_recursion(pkg_id, pkg)?;
        self.check_collisions(pkg_id, pkg)?;
        for module in &pkg.modules {
            self.check_module_typing(pkg_id, pkg, module)?;
            self.check_module_serializability(pkg_id, pkg, module)?;
        }
        Ok(())
    }

    fn check_module_typing(
        &self,
        pkg_id: &str,
        pkg: &Package,
        module: &daml_lf_2::Module,
    ) -> Result<(), TypeError> {
        let mod_name = dotted_string(pkg_id, pkg, module.name_interned_dname, "Module.name")?;

        for syn in &module.synonyms {
            let name = dotted_string(pkg_id, pkg, syn.name_interned_dname, "DefTypeSyn.name")?;
            let id = Ident {
                pkg: pkg_id.to_string(),
                module: mod_name.clone(),
                name,
            };
            if let Some(s) = self.type_syns.get(&id) {
                let mut env = TypingEnv::new(self, pkg_id, pkg, &mod_name);
                let mut seen = HashSet::new();
                for (p, k) in &s.params {
                    if !seen.insert(p.as_str()) {
                        return Err(err(
                            pkg_id,
                            "EDuplicateTypeParam",
                            format!("duplicate type parameter {p}"),
                        ));
                    }
                    check_kind(pkg_id, k)?;
                    env.t_vars.insert(p.clone(), k.clone());
                }
                env.check_type(&s.replacement, &LKind::Star)?;
            }
        }

        for def in &module.data_types {
            let name = dotted_string(pkg_id, pkg, def.name_interned_dname, "DefDataType.name")?;
            let id = Ident {
                pkg: pkg_id.to_string(),
                module: mod_name.clone(),
                name,
            };
            if let Some(d) = self.data_types.get(&id) {
                let mut env = TypingEnv::new(self, pkg_id, pkg, &mod_name);
                let mut seen = HashSet::new();
                for (p, k) in &d.params {
                    if !seen.insert(p.as_str()) {
                        return Err(err(
                            pkg_id,
                            "EDuplicateTypeParam",
                            format!("duplicate type parameter {p}"),
                        ));
                    }
                    check_kind(pkg_id, k)?;
                    env.t_vars.insert(p.clone(), k.clone());
                }
                match &d.cons {
                    DecodedDataCons::Record(fields) => {
                        let mut fnames = HashSet::new();
                        for (fn_s, ft) in fields {
                            if !fnames.insert(fn_s.as_str()) {
                                return Err(err(
                                    pkg_id,
                                    "EDuplicateField",
                                    format!("duplicate field {fn_s}"),
                                ));
                            }
                            env.check_type(ft, &LKind::Star)?;
                        }
                    }
                    DecodedDataCons::Variant(variants) => {
                        let mut vnames = HashSet::new();
                        for (vn, vt) in variants {
                            if !vnames.insert(vn.as_str()) {
                                return Err(err(
                                    pkg_id,
                                    "EDuplicateVariantCon",
                                    format!("duplicate variant constructor {vn}"),
                                ));
                            }
                            env.check_type(vt, &LKind::Star)?;
                        }
                    }
                    DecodedDataCons::Enum(cons) => {
                        if !d.params.is_empty() {
                            return Err(err(
                                pkg_id,
                                "EIllegalHigherEnumType",
                                format!("illegal higher order enum type {}", id.pretty()),
                            ));
                        }
                        let mut enames = HashSet::new();
                        for c in cons {
                            if !enames.insert(c.as_str()) {
                                return Err(err(
                                    pkg_id,
                                    "EDuplicateEnumCon",
                                    format!("duplicate enum constructor {c}"),
                                ));
                            }
                        }
                    }
                    DecodedDataCons::Interface => {
                        if !d.params.is_empty() {
                            return Err(err(
                                pkg_id,
                                "EIllegalHigherInterfaceType",
                                format!("illegal higher interface type {}", id.pretty()),
                            ));
                        }
                    }
                }
            }
        }

        for val in &module.values {
            let Some(nwt) = &val.name_with_type else {
                continue;
            };
            let vname = dotted_string(pkg_id, pkg, nwt.name_interned_dname, "DefValue.name")?;
            let id = Ident {
                pkg: pkg_id.to_string(),
                module: mod_name.clone(),
                name: vname,
            };
            if let Some(dv) = self.values.get(&id) {
                let env = TypingEnv::new(self, pkg_id, pkg, &mod_name);
                env.check_type(&dv.typ, &LKind::Star)?;
                if let Some(expr) = &val.expr {
                    env.check_top_expr(expr, &dv.typ)?;
                }
            }
        }

        for tmpl in &module.templates {
            let tname = dotted_string(pkg_id, pkg, tmpl.tycon_interned_dname, "DefTemplate")?;
            let id = Ident {
                pkg: pkg_id.to_string(),
                module: mod_name.clone(),
                name: tname,
            };
            if let Some(t) = self.templates.get(&id) {
                self.check_template_typing(pkg_id, pkg, &mod_name, &id, t)?;
            }
        }

        for exc in &module.exceptions {
            let ename = dotted_string(pkg_id, pkg, exc.name_interned_dname, "DefException")?;
            let id = Ident {
                pkg: pkg_id.to_string(),
                module: mod_name.clone(),
                name: ename,
            };
            if let Some(e) = self.exceptions.get(&id) {
                self.check_exception_typing(pkg_id, pkg, &mod_name, &id, e)?;
            }
        }

        for iface in &module.interfaces {
            let iname = dotted_string(pkg_id, pkg, iface.tycon_interned_dname, "DefInterface")?;
            let id = Ident {
                pkg: pkg_id.to_string(),
                module: mod_name.clone(),
                name: iname,
            };
            if let Some(i) = self.interfaces.get(&id) {
                self.check_interface_typing(pkg_id, pkg, &mod_name, &id, i)?;
            }
        }

        Ok(())
    }

    fn check_template_typing(
        &self,
        pkg_id: &str,
        pkg: &Package,
        mod_name: &str,
        tpl_id: &Ident,
        t: &DecodedTemplate<'a>,
    ) -> Result<(), TypeError> {
        let Some(d) = self.lookup_data_type(pkg_id, tpl_id)? else {
            return Ok(());
        };
        if !d.params.is_empty() || !matches!(d.cons, DecodedDataCons::Record(_)) {
            return Err(err(
                pkg_id,
                "EExpectedTemplatableType",
                format!(
                    "expected monomorphic record type in template definition, found {}",
                    tpl_id.pretty()
                ),
            ));
        }

        let tpl_ty = LType::Con(tpl_id.clone());
        let mut env = TypingEnv::new(self, pkg_id, pkg, mod_name);
        env.e_vars.insert(t.param.clone(), tpl_ty.clone());

        if let Some(precond) = t.precond {
            env.check_top_expr(precond, &LType::t_bool())?;
        }
        if let Some(signatories) = t.signatories {
            env.check_top_expr(signatories, &LType::t_parties())?;
        }
        if let Some(observers) = t.observers {
            env.check_top_expr(observers, &LType::t_parties())?;
        }

        for ch in &t.choices {
            env.check_choice_typing(tpl_id, &tpl_ty, ch)?;
        }

        let impl_set: HashSet<&Ident> = t.implements.iter().map(|i| &i.iface).collect();
        for imp in &t.implements {
            let Some(iface) = self.lookup_interface(pkg_id, &imp.iface)? else {
                continue;
            };
            for req in &iface.requires {
                if !impl_set.contains(req) {
                    return Err(err(
                        pkg_id,
                        "EMissingRequiredInterfaceInstance",
                        format!(
                            "template {} implements {} without required interface {}",
                            tpl_id.pretty(),
                            imp.iface.pretty(),
                            req.pretty()
                        ),
                    ));
                }
            }
            let iface_methods: HashMap<&str, &LType> =
                iface.methods.iter().map(|(n, t)| (n.as_str(), t)).collect();
            let mut impl_methods: HashMap<&str, Option<&daml_lf_2::Expr>> = HashMap::new();
            for (mname, mexpr) in &imp.methods {
                if !iface_methods.contains_key(mname.as_str()) {
                    return Err(err(
                        pkg_id,
                        "EUnknownMethodInInterfaceInstance",
                        format!(
                            "template {} implements unknown method {} of interface {}",
                            tpl_id.pretty(),
                            mname,
                            imp.iface.pretty()
                        ),
                    ));
                }
                impl_methods.insert(mname.as_str(), *mexpr);
            }
            for (mname, expected_ty) in &iface.methods {
                let Some(mexpr_opt) = impl_methods.get(mname.as_str()) else {
                    return Err(err(
                        pkg_id,
                        "EMissingMethodInInterfaceInstance",
                        format!(
                            "template {} missing method {} of interface {}",
                            tpl_id.pretty(),
                            mname,
                            imp.iface.pretty()
                        ),
                    ));
                };
                if let Some(mexpr) = mexpr_opt {
                    env.check_top_expr_with_kind(mexpr, expected_ty, "EMethodTypeMismatch")?;
                }
            }
            if let Some(view_expr) = imp.view {
                env.check_top_expr_with_kind(view_expr, &iface.view, "EViewTypeMismatch")?;
            }
        }

        if let Some(key) = &t.key {
            let key_env = TypingEnv::new(self, pkg_id, pkg, mod_name);
            key_env.check_type(&key.typ, &LKind::Star)?;
            if let Some(body) = key.body {
                env.check_top_expr(body, &key.typ)?;
            }
            if let Some(maintainers) = key.maintainers {
                // `this` is NOT in scope for key.maintainers.
                key_env.check_top_expr(
                    maintainers,
                    &LType::arrow(key.typ.clone(), LType::t_parties()),
                )?;
            }
        }

        Ok(())
    }

    fn check_exception_typing(
        &self,
        pkg_id: &str,
        pkg: &Package,
        mod_name: &str,
        exc_id: &Ident,
        e: &DecodedException<'a>,
    ) -> Result<(), TypeError> {
        let Some(d) = self.lookup_data_type(pkg_id, exc_id)? else {
            return Ok(());
        };
        if !d.params.is_empty() || !matches!(d.cons, DecodedDataCons::Record(_)) {
            return Err(err(
                pkg_id,
                "EExpectedExceptionableType",
                format!(
                    "expected monomorphic record type in exception definition, found {}",
                    exc_id.pretty()
                ),
            ));
        }
        if let Some(msg) = e.message {
            let env = TypingEnv::new(self, pkg_id, pkg, mod_name);
            env.check_top_expr(
                msg,
                &LType::arrow(LType::Con(exc_id.clone()), LType::t_text()),
            )?;
        }
        Ok(())
    }

    fn check_interface_typing(
        &self,
        pkg_id: &str,
        pkg: &Package,
        mod_name: &str,
        iface_id: &Ident,
        iface: &DecodedInterface<'a>,
    ) -> Result<(), TypeError> {
        let req_set: HashSet<&Ident> = iface.requires.iter().collect();
        if req_set.contains(iface_id) {
            return Err(err(
                pkg_id,
                "ECircularInterfaceRequires",
                format!("interface {} requires itself", iface_id.pretty()),
            ));
        }
        for req_id in &iface.requires {
            let Some(req_iface) = self.lookup_interface(pkg_id, req_id)? else {
                continue;
            };
            for transitive in &req_iface.requires {
                if !req_set.contains(transitive) {
                    return Err(err(
                        pkg_id,
                        "ENotClosedInterfaceRequires",
                        format!(
                            "interface {} requires {} which requires missing {}",
                            iface_id.pretty(),
                            req_id.pretty(),
                            transitive.pretty()
                        ),
                    ));
                }
            }
        }

        let mut env = TypingEnv::new(self, pkg_id, pkg, mod_name);
        for (_, mtype) in &iface.methods {
            env.check_type(mtype, &LKind::Star)?;
        }

        let iface_ty = LType::Con(iface_id.clone());
        env.e_vars.insert(iface.param.clone(), iface_ty.clone());
        for ch in &iface.choices {
            env.check_choice_typing(iface_id, &iface_ty, ch)?;
        }

        // `checkViewType` (`Typing.scala`)
        env.check_type(&iface.view, &LKind::Star)?;
        match &iface.view {
            LType::Con(con_id) => {
                if let Some(d) = self.lookup_data_type(pkg_id, con_id)? {
                    if !matches!(d.cons, DecodedDataCons::Record(_)) {
                        return Err(err(
                            pkg_id,
                            "EViewTypeConNotRecord",
                            format!("view type {} is not a record", iface.view.pretty()),
                        ));
                    }
                    if !d.params.is_empty() {
                        return Err(err(
                            pkg_id,
                            "EViewTypeHasVars",
                            format!("view type {} has type parameters", iface.view.pretty()),
                        ));
                    }
                }
            }
            LType::App(_, _) => {
                let mut cur = &iface.view;
                while let LType::App(lhs, _) = cur {
                    cur = lhs;
                }
                match cur {
                    LType::Con(_) => {
                        return Err(err(
                            pkg_id,
                            "EViewTypeHasVars",
                            format!(
                                "view type {} has applied type arguments",
                                iface.view.pretty()
                            ),
                        ));
                    }
                    _ => {
                        return Err(err(
                            pkg_id,
                            "EViewTypeHeadNotCon",
                            format!(
                                "view type {} head is not a type constructor",
                                iface.view.pretty()
                            ),
                        ));
                    }
                }
            }
            _ => {
                return Err(err(
                    pkg_id,
                    "EViewTypeHeadNotCon",
                    format!(
                        "view type {} head is not a type constructor",
                        iface.view.pretty()
                    ),
                ));
            }
        }

        Ok(())
    }

    fn check_module_serializability(
        &self,
        pkg_id: &str,
        pkg: &Package,
        module: &daml_lf_2::Module,
    ) -> Result<(), TypeError> {
        let mod_name = dotted_string(pkg_id, pkg, module.name_interned_dname, "Module.name")?;

        for def in &module.data_types {
            let name = dotted_string(pkg_id, pkg, def.name_interned_dname, "DefDataType.name")?;
            let id = Ident {
                pkg: pkg_id.to_string(),
                module: mod_name.clone(),
                name,
            };
            if let Some(d) = self.data_types.get(&id) {
                if !d.serializable {
                    continue;
                }
                let mut bound_star = HashSet::new();
                for (p, k) in &d.params {
                    if *k != LKind::Star {
                        return Err(err(
                            pkg_id,
                            "ENonSerializableType",
                            format!(
                                "serializable data type {} has higher-kinded/Nat parameter {p} : {}",
                                id.pretty(),
                                k.pretty()
                            ),
                        ));
                    }
                    bound_star.insert(p.clone());
                }
                match &d.cons {
                    DecodedDataCons::Record(fields) => {
                        for (_, ft) in fields {
                            self.check_serializable_type(pkg_id, "SRDataType", &bound_star, ft)?;
                        }
                    }
                    DecodedDataCons::Variant(variants) => {
                        if variants.is_empty() {
                            return Err(err(
                                pkg_id,
                                "ENonSerializableType",
                                format!("serializable variant {} has no constructors", id.pretty()),
                            ));
                        }
                        for (_, vt) in variants {
                            self.check_serializable_type(pkg_id, "SRDataType", &bound_star, vt)?;
                        }
                    }
                    DecodedDataCons::Enum(cons) => {
                        if cons.is_empty() {
                            return Err(err(
                                pkg_id,
                                "ENonSerializableType",
                                format!("serializable enum {} has no constructors", id.pretty()),
                            ));
                        }
                    }
                    DecodedDataCons::Interface => {
                        return Err(err(
                            pkg_id,
                            "ENonSerializableType",
                            format!("interface {} marked serializable", id.pretty()),
                        ));
                    }
                }
            }
        }

        let empty_vars = HashSet::new();
        for tmpl in &module.templates {
            let name = dotted_string(pkg_id, pkg, tmpl.tycon_interned_dname, "DefTemplate")?;
            let id = Ident {
                pkg: pkg_id.to_string(),
                module: mod_name.clone(),
                name,
            };
            if let Some(t) = self.templates.get(&id) {
                self.check_serializable_type(
                    pkg_id,
                    "SRTemplateArg",
                    &empty_vars,
                    &LType::Con(id.clone()),
                )?;
                for ch in &t.choices {
                    self.check_serializable_type(pkg_id, "SRChoiceArg", &empty_vars, &ch.arg_type)?;
                    self.check_serializable_type(pkg_id, "SRChoiceRes", &empty_vars, &ch.ret_type)?;
                }
                if let Some(k) = &t.key {
                    self.check_serializable_type(pkg_id, "SRKey", &empty_vars, &k.typ)?;
                }
            }
        }

        for exc in &module.exceptions {
            let name = dotted_string(pkg_id, pkg, exc.name_interned_dname, "DefException")?;
            let id = Ident {
                pkg: pkg_id.to_string(),
                module: mod_name.clone(),
                name,
            };
            self.check_serializable_type(pkg_id, "SRExceptionArg", &empty_vars, &LType::Con(id))?;
        }

        for iface in &module.interfaces {
            let name = dotted_string(pkg_id, pkg, iface.tycon_interned_dname, "DefInterface")?;
            let id = Ident {
                pkg: pkg_id.to_string(),
                module: mod_name.clone(),
                name,
            };
            if let Some(i) = self.interfaces.get(&id) {
                for ch in &i.choices {
                    self.check_serializable_type(pkg_id, "SRChoiceArg", &empty_vars, &ch.arg_type)?;
                    self.check_serializable_type(pkg_id, "SRChoiceRes", &empty_vars, &ch.ret_type)?;
                }
                self.check_serializable_type(pkg_id, "SRView", &empty_vars, &i.view)?;
            }
        }

        Ok(())
    }

    /// Recursive serializability check (`Serializability.scala`).
    fn check_serializable_type(
        &self,
        pkg_id: &str,
        req: &str,
        bound_star: &HashSet<String>,
        ty: &LType,
    ) -> Result<(), TypeError> {
        let mut stack = vec![ty];
        while let Some(cur) = stack.pop() {
            match cur {
                LType::Var(v) => {
                    if !bound_star.contains(v) {
                        return Err(err(
                            pkg_id,
                            "ENonSerializableType",
                            format!("{req}: free or non-* type variable {v} in {}", ty.pretty()),
                        ));
                    }
                }
                LType::Con(id) => {
                    if let Some(d) = self.lookup_data_type(pkg_id, id)? {
                        if !d.serializable {
                            return Err(err(
                                pkg_id,
                                "ENonSerializableType",
                                format!("{req}: unserializable data type {}", id.pretty()),
                            ));
                        }
                    }
                }
                LType::Builtin(b) => match b {
                    BuiltinType::Unit
                    | BuiltinType::Bool
                    | BuiltinType::Int64
                    | BuiltinType::Date
                    | BuiltinType::Timestamp
                    | BuiltinType::Party
                    | BuiltinType::Text => {}
                    BuiltinType::Arrow
                    | BuiltinType::Update
                    | BuiltinType::Any
                    | BuiltinType::TypeRep
                    | BuiltinType::AnyException
                    | BuiltinType::RoundingMode
                    | BuiltinType::Bignumeric
                    | BuiltinType::FailureCategory
                    | BuiltinType::Numeric
                    | BuiltinType::List
                    | BuiltinType::Optional
                    | BuiltinType::Textmap
                    | BuiltinType::Genmap
                    | BuiltinType::ContractId => {
                        return Err(err(
                            pkg_id,
                            "ENonSerializableType",
                            format!("{req}: unserializable or unapplied builtin {b:?}"),
                        ));
                    }
                },
                LType::App(f, a) => match (&**f, &**a) {
                    (LType::Builtin(BuiltinType::ContractId), _) => {
                        // `ContractId T` is serializable even when `T` is an interface (SerializabilitySpec).
                    }
                    (LType::Builtin(BuiltinType::Numeric), LType::Nat(_)) => {}
                    (LType::Builtin(BuiltinType::Numeric), _) => {
                        return Err(err(
                            pkg_id,
                            "ENonSerializableType",
                            format!(
                                "{req}: Numeric must be applied to a TNat literal, found {}",
                                cur.pretty()
                            ),
                        ));
                    }
                    (
                        LType::Builtin(
                            BuiltinType::List | BuiltinType::Optional | BuiltinType::Textmap,
                        ),
                        inner,
                    ) => {
                        stack.push(inner);
                    }
                    (LType::App(ff, k), v)
                        if matches!(**ff, LType::Builtin(BuiltinType::Genmap)) =>
                    {
                        stack.push(k);
                        stack.push(v);
                    }
                    (
                        LType::Builtin(
                            BuiltinType::Arrow | BuiltinType::Genmap | BuiltinType::Update,
                        ),
                        _,
                    ) => {
                        return Err(err(
                            pkg_id,
                            "ENonSerializableType",
                            format!("{req}: unserializable type {}", cur.pretty()),
                        ));
                    }
                    (lhs, rhs) => {
                        stack.push(lhs);
                        stack.push(rhs);
                    }
                },
                LType::Nat(_) | LType::Forall { .. } | LType::Struct(_) | LType::SynApp { .. } => {
                    return Err(err(
                        pkg_id,
                        "ENonSerializableType",
                        format!("{req}: unserializable type {}", cur.pretty()),
                    ));
                }
            }
        }
        Ok(())
    }
}
