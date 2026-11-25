//! Validation of every interned reference of a decoded package (AT-A08).
//!
//! [CANTON-NOTE: ORACLE] The JVM upload endpoint answers `DAR_PARSE_ERROR` for a package whose interned string,
//! dotted-name or type reference points outside its table, is negative, or (for interned types) does not point to
//! a smaller index, **even when nothing uses the broken table entry** (`a08-unused-dotted-segment-out-of-range`).
//! Resolving references lazily (what the surface decoder does) accepts packages the JVM refuses and could turn a
//! bad reference into a default value, so a DAR is checked as a whole here before it is trusted.
//!
//! [CANTON-NOTE: LIMITATION] This walks the tables and the type and name references of every module-level
//! definition (data types, synonyms, values, templates, exceptions, interfaces, module names). It does not walk
//! the bodies of expressions (update/scenario code); a broken index inside a choice body is not found here.
use crate::error::DecodeError;
use crate::proto::daml_lf_2::{
    r#type::Sum as T, self_or_imported_package_id::Sum as P, ModuleId, Package, Type,
};

struct Tables {
    strings: usize,
    dnames: usize,
    types: usize,
}

fn oob(index: i32, size: usize, context: &'static str) -> DecodeError {
    DecodeError::InternedIndexOutOfBounds {
        index,
        table_size: size,
        context,
    }
}

fn check(index: i32, size: usize, context: &'static str) -> Result<(), DecodeError> {
    if index < 0 || index as usize >= size {
        return Err(oob(index, size, context));
    }
    Ok(())
}

fn module_id(t: &Tables, m: &Option<ModuleId>) -> Result<(), DecodeError> {
    if let Some(m) = m {
        check(
            m.module_name_interned_dname,
            t.dnames,
            "ModuleId.module_name_interned_dname",
        )?;
        if let Some(p) = &m.package_id {
            if let Some(P::ImportedPackageIdInternedStr(i)) = p.sum {
                check(
                    i,
                    t.strings,
                    "SelfOrImportedPackageId.imported_package_id_interned_str",
                )?;
            }
        }
    }
    Ok(())
}

/// A type at a definition site must be a reference into the interning table (the JVM: "CON is not supported outside
/// type interning table"); the reference itself is range-checked by [`ty`].
fn site(t: &Tables, x: &Type, context: &'static str) -> Result<(), DecodeError> {
    match &x.sum {
        None | Some(T::InternedType(_)) => ty(t, x, t.types, 0),
        Some(_) => Err(DecodeError::InvalidTypeForm(context)),
    }
}

/// `limit` is how many interned types a reference may name: the table size outside the table, and the entry's own
/// index inside it (types may only refer to smaller indices).
fn ty(t: &Tables, x: &Type, limit: usize, depth: usize) -> Result<(), DecodeError> {
    if depth > 256 {
        return Err(DecodeError::RecursionLimitExceeded {
            context: "interned type validation",
        });
    }
    let args = |a: &[Type]| -> Result<(), DecodeError> {
        for y in a {
            ty(t, y, limit, depth + 1)?;
        }
        Ok(())
    };
    match &x.sum {
        None | Some(T::Nat(_)) => Ok(()),
        Some(T::InternedType(i)) => check(*i, limit, "Type.interned_type"),
        Some(T::Var(v)) => {
            check(v.var_interned_str, t.strings, "Type.Var.var_interned_str")?;
            args(&v.args)
        }
        Some(T::Con(c)) => {
            if let Some(id) = &c.tycon {
                module_id(t, &id.module)?;
                check(
                    id.name_interned_dname,
                    t.dnames,
                    "TypeConId.name_interned_dname",
                )?;
            }
            args(&c.args)
        }
        Some(T::Syn(s)) => {
            if let Some(id) = &s.tysyn {
                module_id(t, &id.module)?;
                check(
                    id.name_interned_dname,
                    t.dnames,
                    "TypeSynId.name_interned_dname",
                )?;
            }
            args(&s.args)
        }
        Some(T::Builtin(b)) => args(&b.args),
        Some(T::Forall(f)) => {
            for v in &f.vars {
                check(
                    v.var_interned_str,
                    t.strings,
                    "TypeVarWithKind.var_interned_str",
                )?;
            }
            if let Some(b) = &f.body {
                ty(t, b, limit, depth + 1)?;
            }
            Ok(())
        }
        Some(T::Struct(s)) => {
            for f in &s.fields {
                check(
                    f.field_interned_str,
                    t.strings,
                    "FieldWithType.field_interned_str",
                )?;
                if let Some(y) = &f.r#type {
                    ty(t, y, limit, depth + 1)?;
                }
            }
            Ok(())
        }
        Some(T::Tapp(a)) => {
            for side in [&a.lhs, &a.rhs].into_iter().flatten() {
                ty(t, side, limit, depth + 1)?;
            }
            Ok(())
        }
    }
}

/// Checks every interned reference of `package`; the first broken one is returned.
pub fn validate_interned_references(package: &Package) -> Result<(), DecodeError> {
    let t = Tables {
        strings: package.interned_strings.len(),
        dnames: package.interned_dotted_names.len(),
        types: package.interned_types.len(),
    };
    for d in &package.interned_dotted_names {
        for s in &d.segments_interned_str {
            check(*s, t.strings, "InternedDottedName.segments_interned_str")?;
        }
    }
    for (i, x) in package.interned_types.iter().enumerate() {
        if matches!(x.sum, Some(T::InternedType(_))) {
            return Err(DecodeError::InvalidTypeForm(
                "interned type entry that is only a reference",
            ));
        }
        ty(&t, x, i, 0)?;
    }
    let mut seen = std::collections::HashSet::new();
    for m in &package.modules {
        if !seen.insert(m.name_interned_dname) {
            return Err(DecodeError::DuplicateModule(m.name_interned_dname));
        }
    }
    if let Some(m) = &package.metadata {
        check(
            m.name_interned_str,
            t.strings,
            "PackageMetadata.name_interned_str",
        )?;
        check(
            m.version_interned_str,
            t.strings,
            "PackageMetadata.version_interned_str",
        )?;
    }
    for m in &package.modules {
        check(
            m.name_interned_dname,
            t.dnames,
            "Module.name_interned_dname",
        )?;
        for s in &m.synonyms {
            check(
                s.name_interned_dname,
                t.dnames,
                "DefTypeSyn.name_interned_dname",
            )?;
            for v in &s.params {
                check(v.var_interned_str, t.strings, "DefTypeSyn.params")?;
            }
            if let Some(y) = &s.r#type {
                site(&t, y, "DefTypeSyn.type")?;
            }
        }
        for d in &m.data_types {
            check(
                d.name_interned_dname,
                t.dnames,
                "DefDataType.name_interned_dname",
            )?;
            for v in &d.params {
                check(v.var_interned_str, t.strings, "DefDataType.params")?;
            }
            use crate::proto::daml_lf_2::def_data_type::DataCons;
            match &d.data_cons {
                Some(DataCons::Record(r)) => {
                    for f in &r.fields {
                        check(f.field_interned_str, t.strings, "DefDataType.Fields.field")?;
                        if let Some(y) = &f.r#type {
                            site(&t, y, "DefDataType field type")?;
                        }
                    }
                }
                Some(DataCons::Variant(r)) => {
                    for f in &r.fields {
                        check(f.field_interned_str, t.strings, "DefDataType.Fields.field")?;
                        if let Some(y) = &f.r#type {
                            site(&t, y, "DefDataType field type")?;
                        }
                    }
                }
                Some(DataCons::Interface(_)) => {}
                Some(DataCons::Enum(e)) => {
                    for c in &e.constructors_interned_str {
                        check(*c, t.strings, "DefDataType.EnumConstructors")?;
                    }
                }
                None => {}
            }
        }
        for v in &m.values {
            if let Some(n) = &v.name_with_type {
                check(
                    n.name_interned_dname,
                    t.dnames,
                    "DefValue.name_interned_dname",
                )?;
                if let Some(y) = &n.r#type {
                    site(&t, y, "DefValue type")?;
                }
            }
        }
        for x in &m.templates {
            check(
                x.tycon_interned_dname,
                t.dnames,
                "DefTemplate.tycon_interned_dname",
            )?;
        }
        for x in &m.exceptions {
            check(
                x.name_interned_dname,
                t.dnames,
                "DefException.name_interned_dname",
            )?;
        }
        for x in &m.interfaces {
            check(
                x.tycon_interned_dname,
                t.dnames,
                "DefInterface.tycon_interned_dname",
            )?;
        }
    }
    Ok(())
}
