//! Synthetic MODEL tests for nested Update evaluation (lazy Update, nested Exercise,
//! Fetch, GetTime) through `Machine` -> `UpdateHost`.
//!
//! TryCatch/exception tests (second half of the file) are model tests too: the expected
//! outcomes (rollback to the `try` checkpoint, only `throw`n exceptions catchable, handler
//! `None` = rethrow) come from the Daml-LF exception model as documented/remembered, NOT
//! from Speedy or `daml script`. No DAR on disk has a choice containing a `try`.
//!
//! These are NOT oracle comparisons. The packages are hand-built LF expression trees; the
//! expected values come from the Daml ledger model as understood from its documentation,
//! not from `daml script --ide-ledger` or Speedy. No DAR available on disk contains a choice
//! whose body exercises or fetches, so there is nothing real to compare against.
//! The one real-DAR check lives in `tests/engine_real_dar.rs`.

use std::cell::{Cell as CountCell, RefCell};
use std::collections::HashMap;

use lf_archive::proto::daml_lf_2::{
    self, builtin_lit, expr, BuiltinCon, Expr, InternedDottedName, Module, ModuleId, Package,
    SelfOrImportedPackageId, TypeConId, Unit, VarWithType,
};

use crate::engine::{Engine, EngineEvent, MAX_EXERCISE_DEPTH};
use crate::{EvalError, UpdateHost, Value, World};

const PKG: &str = "synthetic-package";
const ADD_INT64: i32 = 7;
const GREATER: i32 = 6;

/// Interning tables behind `RefCell` so the expression helpers can share one `&Interner`
/// and nest freely (`block(b, .., pure(var(b, ..)))`) without borrow-checker gymnastics.
#[derive(Default)]
struct Interner {
    strings: RefCell<Vec<String>>,
    dnames: RefCell<Vec<InternedDottedName>>,
}

impl Interner {
    fn s(&self, text: &str) -> i32 {
        let mut strings = self.strings.borrow_mut();
        if let Some(i) = strings.iter().position(|t| t == text) {
            return i as i32;
        }
        strings.push(text.to_string());
        (strings.len() - 1) as i32
    }

    /// Interns a dotted name; `"A.B.C"` becomes three segments (module names of the
    /// built-in exceptions are dotted, e.g. `DA.Exception.PreconditionFailed`).
    fn dn(&self, text: &str) -> i32 {
        let segs: Vec<i32> = text.split('.').map(|part| self.s(part)).collect();
        let mut dnames = self.dnames.borrow_mut();
        if let Some(i) = dnames.iter().position(|d| d.segments_interned_str == segs) {
            return i as i32;
        }
        dnames.push(InternedDottedName {
            segments_interned_str: segs,
        });
        (dnames.len() - 1) as i32
    }
}

fn e(sum: expr::Sum) -> Expr {
    Expr {
        sum: Some(sum),
        ..Default::default()
    }
}

fn var(b: &Interner, name: &str) -> Expr {
    e(expr::Sum::VarInternedStr(b.s(name)))
}

fn proj(b: &Interner, record: Expr, field: &str) -> Expr {
    e(expr::Sum::RecProj(Box::new(expr::RecProj {
        tycon: None,
        field_interned_str: b.s(field),
        record: Some(Box::new(record)),
    })))
}

fn rec(b: &Interner, fields: Vec<(&str, Expr)>) -> Expr {
    e(expr::Sum::RecCon(expr::RecCon {
        tycon: None,
        fields: fields
            .into_iter()
            .map(|(name, value)| daml_lf_2::FieldWithExpr {
                field_interned_str: b.s(name),
                expr: Some(value),
            })
            .collect(),
    }))
}

fn list(items: Vec<Expr>) -> Expr {
    e(expr::Sum::Cons(Box::new(expr::Cons {
        r#type: None,
        front: items,
        tail: Some(Box::new(e(expr::Sum::Nil(expr::Nil { r#type: None })))),
    })))
}

fn int(n: i64) -> Expr {
    e(expr::Sum::BuiltinLit(daml_lf_2::BuiltinLit {
        sum: Some(builtin_lit::Sum::Int64(n)),
    }))
}

fn unit() -> Expr {
    e(expr::Sum::BuiltinCon(BuiltinCon::ConUnit as i32))
}

fn text(b: &Interner, value: &str) -> Expr {
    e(expr::Sum::BuiltinLit(daml_lf_2::BuiltinLit {
        sum: Some(builtin_lit::Sum::TextInternedStr(b.s(value))),
    }))
}

fn tcon(b: &Interner, module: &str, name: &str) -> TypeConId {
    TypeConId {
        module: Some(ModuleId {
            package_id: Some(SelfOrImportedPackageId {
                sum: Some(daml_lf_2::self_or_imported_package_id::Sum::SelfPackageId(
                    Unit {},
                )),
            }),
            module_name_interned_dname: b.dn(module),
        }),
        name_interned_dname: b.dn(name),
    }
}

fn con_type(b: &Interner, module: &str, name: &str) -> daml_lf_2::Type {
    daml_lf_2::Type {
        sum: Some(daml_lf_2::r#type::Sum::Con(daml_lf_2::r#type::Con {
            tycon: Some(tcon(b, module, name)),
            args: Vec::new(),
        })),
    }
}

fn upd(sum: daml_lf_2::update::Sum) -> Expr {
    e(expr::Sum::Update(Box::new(daml_lf_2::Update {
        sum: Some(sum),
    })))
}

fn pure(inner: Expr) -> Expr {
    upd(daml_lf_2::update::Sum::Pure(Box::new(daml_lf_2::Pure {
        r#type: None,
        expr: Some(Box::new(inner)),
    })))
}

fn create(b: &Interner, template: &str, payload: Expr) -> Expr {
    upd(daml_lf_2::update::Sum::Create(Box::new(
        daml_lf_2::update::Create {
            template: Some(tcon(b, "M", template)),
            expr: Some(Box::new(payload)),
        },
    )))
}

fn exercise(b: &Interner, template: &str, choice: &str, cid: Expr, arg: Expr) -> Expr {
    upd(daml_lf_2::update::Sum::Exercise(Box::new(
        daml_lf_2::update::Exercise {
            template: Some(tcon(b, "M", template)),
            choice_interned_str: b.s(choice),
            cid: Some(Box::new(cid)),
            arg: Some(Box::new(arg)),
        },
    )))
}

fn fetch(b: &Interner, template: &str, cid: Expr) -> Expr {
    upd(daml_lf_2::update::Sum::Fetch(Box::new(
        daml_lf_2::update::Fetch {
            template: Some(tcon(b, "M", template)),
            cid: Some(Box::new(cid)),
        },
    )))
}

fn get_time() -> Expr {
    upd(daml_lf_2::update::Sum::GetTime(Unit {}))
}

/// `throw @_ @module:name payload`
fn throw(b: &Interner, module: &str, name: &str, payload: Expr) -> Expr {
    e(expr::Sum::Throw(Box::new(expr::Throw {
        return_type: None,
        exception_type: Some(con_type(b, module, name)),
        exception_expr: Some(Box::new(payload)),
    })))
}

fn throw_boom(b: &Interner, name: &str) -> Expr {
    throw(b, "M", name, rec(b, vec![("message", text(b, "boom"))]))
}

fn some(inner: Expr) -> Expr {
    e(expr::Sum::OptionalSome(Box::new(expr::OptionalSome {
        r#type: None,
        value: Some(Box::new(inner)),
    })))
}

fn none() -> Expr {
    e(expr::Sum::OptionalNone(expr::OptionalNone { r#type: None }))
}

fn to_any_exception(b: &Interner, module: &str, name: &str, inner: Expr) -> Expr {
    e(expr::Sum::ToAnyException(Box::new(expr::ToAnyException {
        r#type: Some(con_type(b, module, name)),
        expr: Some(Box::new(inner)),
    })))
}

fn from_any_exception(b: &Interner, module: &str, name: &str, inner: Expr) -> Expr {
    e(expr::Sum::FromAnyException(Box::new(
        expr::FromAnyException {
            r#type: Some(con_type(b, module, name)),
            expr: Some(Box::new(inner)),
        },
    )))
}

/// `case scrut of Some binder -> on_some; _ -> on_none`
fn case_some(b: &Interner, scrut: Expr, binder: &str, on_some: Expr, on_none: Expr) -> Expr {
    e(expr::Sum::Case(Box::new(daml_lf_2::Case {
        scrut: Some(Box::new(scrut)),
        alts: vec![
            daml_lf_2::CaseAlt {
                body: Some(on_some),
                sum: Some(daml_lf_2::case_alt::Sum::OptionalSome(
                    daml_lf_2::case_alt::OptionalSome {
                        var_body_interned_str: b.s(binder),
                    },
                )),
            },
            daml_lf_2::CaseAlt {
                body: Some(on_none),
                sum: Some(daml_lf_2::case_alt::Sum::Default(Unit {})),
            },
        ],
    })))
}

/// `try try_expr catch ex -> catch_expr`; `catch_expr : Optional (Update a)` as in LF.
fn try_catch(b: &Interner, try_expr: Expr, catch_expr: Expr) -> Expr {
    upd(daml_lf_2::update::Sum::TryCatch(Box::new(
        daml_lf_2::update::TryCatch {
            return_type: None,
            try_expr: Some(Box::new(try_expr)),
            var_interned_str: b.s("ex"),
            catch_expr: Some(Box::new(catch_expr)),
        },
    )))
}

/// Handler matching only exceptions of type `module:name`: what damlc generates for
/// `catch (e : T) -> action`. Any other exception type yields `None` (= rethrow). The
/// action may refer to the matched payload as `e`.
fn catch_type(b: &Interner, module: &str, name: &str, action: Expr) -> Expr {
    let ex = var(b, "ex");
    case_some(
        b,
        from_any_exception(b, module, name, ex),
        "e",
        some(action),
        none(),
    )
}

/// Handler that accepts *every* value it is offered. Used to prove that host errors never
/// reach a handler at all: if they did, this one would swallow them.
fn catch_all(action: Expr) -> Expr {
    some(action)
}

fn block(b: &Interner, bindings: Vec<(&str, Expr)>, body: Expr) -> Expr {
    upd(daml_lf_2::update::Sum::Block(Box::new(daml_lf_2::Block {
        bindings: bindings
            .into_iter()
            .map(|(name, bound)| daml_lf_2::Binding {
                binder: Some(VarWithType {
                    var_interned_str: b.s(name),
                    r#type: None,
                }),
                bound: Some(bound),
            })
            .collect(),
        body: Some(Box::new(body)),
    })))
}

fn abs(b: &Interner, params: &[&str], body: Expr) -> Expr {
    e(expr::Sum::Abs(Box::new(expr::Abs {
        param: params
            .iter()
            .map(|p| VarWithType {
                var_interned_str: b.s(p),
                r#type: None,
            })
            .collect(),
        body: Some(Box::new(body)),
    })))
}

fn app(fun: Expr, args: Vec<Expr>) -> Expr {
    e(expr::Sum::App(Box::new(expr::App {
        fun: Some(Box::new(fun)),
        args,
    })))
}

/// `case scrut of True -> on_true; _ -> on_false`
fn if_then_else(scrut: Expr, on_true: Expr, on_false: Expr) -> Expr {
    e(expr::Sum::Case(Box::new(daml_lf_2::Case {
        scrut: Some(Box::new(scrut)),
        alts: vec![
            daml_lf_2::CaseAlt {
                body: Some(on_true),
                sum: Some(daml_lf_2::case_alt::Sum::BuiltinCon(
                    BuiltinCon::ConTrue as i32,
                )),
            },
            daml_lf_2::CaseAlt {
                body: Some(on_false),
                sum: Some(daml_lf_2::case_alt::Sum::Default(Unit {})),
            },
        ],
    })))
}

fn bool_con(value: bool) -> Expr {
    e(expr::Sum::BuiltinCon(if value {
        BuiltinCon::ConTrue as i32
    } else {
        BuiltinCon::ConFalse as i32
    }))
}

/// Every synthetic choice is controlled by `this.owner`; authorization variety comes from
/// the templates' signatories/observers instead.
fn choice(b: &Interner, name: &str, consuming: bool, update: Expr) -> daml_lf_2::TemplateChoice {
    daml_lf_2::TemplateChoice {
        name_interned_str: b.s(name),
        consuming,
        controllers: Some(owner_list(b)),
        observers: None,
        arg_binder: Some(VarWithType {
            var_interned_str: b.s("arg"),
            r#type: None,
        }),
        ret_type: None,
        update: Some(update),
        self_binder_interned_str: b.s("self"),
        ..Default::default()
    }
}

fn template(
    b: &Interner,
    name: &str,
    signatories: Expr,
    observers: Option<Expr>,
    choices: Vec<daml_lf_2::TemplateChoice>,
) -> daml_lf_2::DefTemplate {
    daml_lf_2::DefTemplate {
        tycon_interned_dname: b.dn(name),
        param_interned_str: b.s("this"),
        precond: None,
        signatories: Some(signatories),
        choices,
        observers,
        ..Default::default()
    }
}

fn owner_list(b: &Interner) -> Expr {
    let this = var(b, "this");
    list(vec![proj(b, this, "owner")])
}

fn cell_payload(owner: &str, n: i64) -> Value {
    Value::Record {
        tycon: None,
        fields: vec![
            ("owner".into(), Value::Party(owner.into())),
            ("n".into(), Value::Int64(n)),
        ],
    }
}

/// The synthetic package:
/// * `Cell {owner, n}` (signatory owner) with choices Bump (consuming), Peek,
///   FetchSelf, BumpThenFetch (consuming), OuterBump, Twice, Spawn, Clock, Attempt and the
///   laziness probes LazyArg / LazyCase / EagerCase.
/// * `Watch {owner, watcher, victim}`: watcher is an *observer* only.
/// * `Delegate {owner, partner, victim}`: partner is a *signatory*.
fn build_world() -> World {
    let b = &Interner::default();

    let mut cell_choices = Vec::new();

    // Bump (consuming): create Cell{owner, n + 1}, return the new id.
    let this = var(b, "this");
    let owner = proj(b, this, "owner");
    let this = var(b, "this");
    let n = proj(b, this, "n");
    let plus_one = app(e(expr::Sum::Builtin(ADD_INT64)), vec![n, int(1)]);
    let payload = rec(b, vec![("owner", owner), ("n", plus_one)]);
    let created = create(b, "Cell", payload);
    let body = block(b, vec![("c", created)], {
        let c = var(b, "c");
        pure(c)
    });
    cell_choices.push(choice(b, "Bump", true, body));

    // Peek (non-consuming): return n.
    let this = var(b, "this");
    let n = proj(b, this, "n");
    cell_choices.push(choice(b, "Peek", false, pure(n)));

    // LoudObservers (non-consuming): its choice observers throw.
    let mut loud = choice(b, "LoudObservers", false, pure(unit()));
    loud.observers = Some(throw_boom(b, "MyErr"));
    cell_choices.push(loud);

    // FetchSelf (non-consuming): fetch own id, return its n.
    let fetched = {
        let me = var(b, "self");
        fetch(b, "Cell", me)
    };
    let body = block(b, vec![("c", fetched)], {
        let c = var(b, "c");
        let n = proj(b, c, "n");
        pure(n)
    });
    cell_choices.push(choice(b, "FetchSelf", false, body));

    // BumpThenFetch (consuming): fetches self AFTER it was archived by the exercise itself.
    let fetched = {
        let me = var(b, "self");
        fetch(b, "Cell", me)
    };
    let body = block(b, vec![("c", fetched)], {
        let c = var(b, "c");
        pure(c)
    });
    cell_choices.push(choice(b, "BumpThenFetch", true, body));

    // OuterBump (non-consuming): nested consuming exercise of Bump on self; returns result.
    let nested = {
        let me = var(b, "self");
        exercise(b, "Cell", "Bump", me, unit())
    };
    let body = block(b, vec![("r", nested)], {
        let r = var(b, "r");
        pure(r)
    });
    cell_choices.push(choice(b, "OuterBump", false, body));

    // Twice (non-consuming): Bump self, then Bump self again -> second must find it inactive.
    let first = {
        let me = var(b, "self");
        exercise(b, "Cell", "Bump", me, unit())
    };
    let second = {
        let me = var(b, "self");
        exercise(b, "Cell", "Bump", me, unit())
    };
    let body = block(b, vec![("a", first), ("b", second)], {
        let r = var(b, "b");
        pure(r)
    });
    cell_choices.push(choice(b, "Twice", false, body));

    // Spawn (non-consuming): create Cell{owner, 100}, then exercise Peek on the new id.
    let this = var(b, "this");
    let owner = proj(b, this, "owner");
    let payload = rec(b, vec![("owner", owner), ("n", int(100))]);
    let created = create(b, "Cell", payload);
    let peeked = {
        let a = var(b, "a");
        exercise(b, "Cell", "Peek", a, unit())
    };
    let body = block(b, vec![("a", created), ("p", peeked)], {
        let p = var(b, "p");
        pure(p)
    });
    cell_choices.push(choice(b, "Spawn", false, body));

    // Clock (non-consuming): return ledger time.
    let body = block(b, vec![("t", get_time())], {
        let t = var(b, "t");
        pure(t)
    });
    cell_choices.push(choice(b, "Clock", false, body));

    // Recurse (non-consuming): exercises itself forever; only the host's depth guard stops it.
    let again = {
        let me = var(b, "self");
        exercise(b, "Cell", "Recurse", me, unit())
    };
    cell_choices.push(choice(b, "Recurse", false, again));

    // Attempt (non-consuming): a TryCatch node, used against hosts that cannot roll back.
    let attempt = try_catch(b, pure(unit()), catch_all(pure(unit())));
    cell_choices.push(choice(b, "Attempt", false, attempt));

    // ---- TryCatch / exception probes (all non-consuming, controlled by owner) ----
    // `MyErr`/`OtherErr` are user exception types (`M:MyErr` etc.); payload `{message}`.
    let create_cell = |b: &Interner, n: i64| {
        let this = var(b, "this");
        let owner = proj(b, this, "owner");
        create(b, "Cell", rec(b, vec![("owner", owner), ("n", int(n))]))
    };
    let exercise_self = |b: &Interner, name: &str| {
        let me = var(b, "self");
        exercise(b, "Cell", name, me, unit())
    };

    // TryRollbackCreate: create inside `try`, then throw. The handler returns 7; the
    // created Cell must be gone afterwards.
    let body = try_catch(
        b,
        block(b, vec![("c", create_cell(b, 100))], throw_boom(b, "MyErr")),
        catch_type(b, "M", "MyErr", pure(int(7))),
    );
    cell_choices.push(choice(b, "TryRollbackCreate", false, body));

    // TryRollbackArchive: a consuming nested Bump (archives self, creates a new Cell),
    // then throw. After the rollback `self` must be active again and the new Cell gone.
    let body = try_catch(
        b,
        block(
            b,
            vec![("r", exercise_self(b, "Bump"))],
            throw_boom(b, "MyErr"),
        ),
        catch_type(b, "M", "MyErr", pure(int(1))),
    );
    cell_choices.push(choice(b, "TryRollbackArchive", false, body));

    // TryOk: no exception; the effects of the try body must survive (commit path).
    let body = try_catch(
        b,
        create_cell(b, 5),
        catch_type(b, "M", "MyErr", pure(unit())),
    );
    cell_choices.push(choice(b, "TryOk", false, body));

    // ThrowPlain: create then throw with no `try` anywhere: uncaught.
    let body = block(b, vec![("c", create_cell(b, 6))], throw_boom(b, "MyErr"));
    cell_choices.push(choice(b, "ThrowPlain", false, body));

    // NestedInnerCatches: the inner try catches, so only ITS create (300) is undone; the
    // outer body continues and keeps its own create (200).
    let inner = try_catch(
        b,
        block(b, vec![("b", create_cell(b, 300))], throw_boom(b, "MyErr")),
        catch_type(b, "M", "MyErr", pure(unit())),
    );
    let body = try_catch(
        b,
        block(
            b,
            vec![("a", create_cell(b, 200)), ("i", inner)],
            pure(int(2)),
        ),
        catch_type(b, "M", "MyErr", pure(int(-2))),
    );
    cell_choices.push(choice(b, "NestedInnerCatches", false, body));

    // NestedOuterCatches: the inner handler only accepts OtherErr, so MyErr is declined
    // (`None` = rethrow) and the OUTER handler catches it and returns the exception's
    // message. Both creates (200 and 300) must be gone.
    let inner = try_catch(
        b,
        block(b, vec![("b", create_cell(b, 300))], throw_boom(b, "MyErr")),
        catch_type(b, "M", "OtherErr", pure(unit())),
    );
    let message = {
        let ex = var(b, "e");
        proj(b, ex, "message")
    };
    let body = try_catch(
        b,
        block(
            b,
            vec![("a", create_cell(b, 200)), ("i", inner)],
            pure(int(2)),
        ),
        catch_type(b, "M", "MyErr", pure(message)),
    );
    cell_choices.push(choice(b, "NestedOuterCatches", false, body));

    // Boom: creates a Cell, then throws. Used as a *nested* exercise (CatchBoom).
    let body = block(b, vec![("c", create_cell(b, 500))], throw_boom(b, "MyErr"));
    cell_choices.push(choice(b, "Boom", false, body));

    // CatchBoom: the exception is thrown inside a nested exercise (another machine) and
    // must reach this body's try; the nested create (500) is rolled back with it.
    let body = try_catch(
        b,
        exercise_self(b, "Boom"),
        catch_type(b, "M", "MyErr", pure(int(3))),
    );
    cell_choices.push(choice(b, "CatchBoom", false, body));

    // Host errors inside `try` with a catch-everything handler: none may be caught.
    let arg_cid = var(b, "arg");
    let body = try_catch(b, fetch(b, "Cell", arg_cid), catch_all(pure(int(1))));
    cell_choices.push(choice(b, "TryBadFetch", false, body));

    let this = var(b, "this");
    let owner = proj(b, this, "owner");
    let partner = var(b, "arg");
    let me = var(b, "self");
    let body = try_catch(
        b,
        create(
            b,
            "Delegate",
            rec(
                b,
                vec![("owner", owner), ("partner", partner), ("victim", me)],
            ),
        ),
        catch_all(pure(int(1))),
    );
    cell_choices.push(choice(b, "TryUnauthorized", false, body));

    let body = try_catch(b, exercise_self(b, "Recurse"), catch_all(pure(int(1))));
    cell_choices.push(choice(b, "TryRecurse", false, body));

    // Precondition failure (`ensure`) is the built-in PreconditionFailed Daml exception.
    let guarded = |b: &Interner, n: Expr| {
        let this = var(b, "this");
        let owner = proj(b, this, "owner");
        create(b, "Guarded", rec(b, vec![("owner", owner), ("n", n)]))
    };
    let message = {
        let ex = var(b, "e");
        proj(b, ex, "message")
    };
    let body = try_catch(
        b,
        guarded(b, int(-1)),
        catch_type(
            b,
            "DA.Exception.PreconditionFailed",
            "PreconditionFailed",
            pure(message),
        ),
    );
    cell_choices.push(choice(b, "TryEnsure", false, body));
    let arg_n = var(b, "arg");
    cell_choices.push(choice(b, "MakeGuarded", false, guarded(b, arg_n)));

    // ThrowInHandler: the handler's own action throws OtherErr. The try frame is already
    // gone then, so only the OUTER try (which accepts OtherErr) may catch it.
    let inner = try_catch(
        b,
        throw_boom(b, "MyErr"),
        catch_all(block(b, Vec::new(), throw_boom(b, "OtherErr"))),
    );
    let body = try_catch(b, inner, catch_type(b, "M", "OtherErr", pure(int(11))));
    cell_choices.push(choice(b, "ThrowInHandler", false, body));

    // RoundTrip*: FromAnyException (ToAnyException e) matches only the same static type.
    for (name, ty) in [
        ("RoundTripMatch", "MyErr"),
        ("RoundTripMismatch", "OtherErr"),
    ] {
        let wrapped = to_any_exception(b, "M", "MyErr", rec(b, vec![("message", text(b, "rt"))]));
        let msg = {
            let e1 = var(b, "e");
            proj(b, e1, "message")
        };
        let probe = case_some(
            b,
            from_any_exception(b, "M", ty, wrapped),
            "e",
            msg,
            text(b, "none"),
        );
        cell_choices.push(choice(b, name, false, pure(probe)));
    }

    // Cell helper payload used by the laziness probes: a create expression we must NOT run.
    let probe_create = |b: &Interner| {
        let this = var(b, "this");
        let owner = proj(b, this, "owner");
        let payload = rec(b, vec![("owner", owner), ("n", int(-1))]);
        create(b, "Cell", payload)
    };

    // LazyArg: the create is passed as an UNUSED argument of a function. Strict argument
    // evaluation used to execute it (Update was an identity monad); it must stay inert.
    let arg_create = probe_create(b);
    let ignore = {
        let body = pure(int(7));
        abs(b, &["u"], body)
    };
    let body = block(b, vec![("x", app(ignore, vec![arg_create]))], {
        let x = var(b, "x");
        pure(x)
    });
    cell_choices.push(choice(b, "LazyArg", false, body));

    // LazyCase / EagerCase: `when cond (create ..)`, selected branch only may run.
    for (name, cond) in [("LazyCase", false), ("EagerCase", true)] {
        let created = probe_create(b);
        let then_branch = block(b, vec![("c", created)], pure(unit()));
        let when = if_then_else(bool_con(cond), then_branch, pure(unit()));
        let body = block(b, vec![("w", when)], pure(int(1)));
        cell_choices.push(choice(b, name, false, body));
    }

    let cell_sigs = owner_list(b);
    let cell = template(b, "Cell", cell_sigs, None, cell_choices);

    // Watch: signatory owner, OBSERVER watcher. `Go` exercises Cell.Bump on `victim`.
    let go_body = |b: &Interner| {
        let this = var(b, "this");
        let victim = proj(b, this, "victim");
        let nested = exercise(b, "Cell", "Bump", victim, unit());
        block(b, vec![("r", nested)], {
            let r = var(b, "r");
            pure(r)
        })
    };
    let watch_sigs = owner_list(b);
    let watch_obs = {
        let this = var(b, "this");
        list(vec![proj(b, this, "watcher")])
    };
    let watch_go = go_body(b);
    let watch_choice = choice(b, "Go", false, watch_go);
    let watch = template(b, "Watch", watch_sigs, Some(watch_obs), vec![watch_choice]);

    // Delegate: signatories owner AND partner, so partner's authority flows to children.
    let delegate_sigs = {
        let this = var(b, "this");
        let owner = proj(b, this, "owner");
        let this = var(b, "this");
        let partner = proj(b, this, "partner");
        list(vec![owner, partner])
    };
    let delegate_go = go_body(b);
    let delegate_choice = choice(b, "Go", false, delegate_go);
    let delegate = template(b, "Delegate", delegate_sigs, None, vec![delegate_choice]);

    // Guarded: `ensure n > 0` (GREATER on Int64), to produce a real PreconditionFailed.
    let mut guarded = template(b, "Guarded", owner_list(b), None, Vec::new());
    let guard_n = {
        let this = var(b, "this");
        proj(b, this, "n")
    };
    guarded.precond = Some(app(e(expr::Sum::Builtin(GREATER)), vec![guard_n, int(0)]));

    let module = Module {
        name_interned_dname: b.dn("M"),
        data_types: Vec::new(),
        values: Vec::new(),
        templates: vec![cell, watch, delegate, guarded],
        ..Default::default()
    };
    let package = Package {
        modules: vec![module],
        interned_strings: b.strings.take(),
        interned_dotted_names: b.dnames.take(),
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };
    World {
        main_package_id: PKG.to_string(),
        packages: HashMap::from([(PKG.to_string(), package)]),
        val_cache: crate::ValCache::default(),
        ctor_cache: crate::world::CtorCache::default(),
    }
}

fn cid(text: &str) -> Value {
    Value::ContractId(text.to_string())
}

fn cell_n(engine: &Engine<'_>, contract_id: &str) -> i64 {
    let contract = engine.contract(contract_id).expect("contract exists");
    match &contract.payload {
        Value::Record { fields, .. } => fields
            .iter()
            .find_map(|(k, v)| match (k.as_str(), v) {
                ("n", Value::Int64(n)) => Some(*n),
                _ => None,
            })
            .expect("n field"),
        other => panic!("unexpected payload {other:?}"),
    }
}

fn active_ids(engine: &Engine<'_>) -> Vec<String> {
    engine
        .active_contracts()
        .map(|c| c.contract_id.clone())
        .collect()
}

#[test]
fn nested_consuming_exercise_creates_and_archives_through_the_machine() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = engine
        .create_as(&["alice"], PKG, "M:Cell", &cell_payload("alice", 1))
        .unwrap();

    // OuterBump is non-consuming; its body exercises the consuming Bump on the same id.
    let result = engine
        .exercise_as(&["alice"], &root, "OuterBump", &Value::Unit)
        .unwrap();

    // The nested exercise's result value flows back as the value of the `r <- exercise`.
    let Value::ContractId(new_id) = result else {
        panic!("expected a contract id, got {result:?}");
    };
    assert_ne!(new_id, root);
    assert_eq!(cell_n(&engine, &new_id), 2);
    // The nested Bump was consuming: the original is archived, only the new cell is active.
    assert!(!engine.contract(&root).unwrap().active);
    assert_eq!(active_ids(&engine), vec![new_id.clone()]);

    // Event order and nesting depth, model-level expectations.
    let events: Vec<_> = engine.events().to_vec();
    assert_eq!(
        events,
        vec![
            EngineEvent::Create {
                contract_id: root.clone(),
                template_id: "M:Cell".into(),
                depth: 0
            },
            EngineEvent::Exercise {
                contract_id: root.clone(),
                choice: "OuterBump".into(),
                consuming: false,
                actors: vec!["alice".into()],
                depth: 0,
                argument: Value::Unit,
                result: Some(Value::ContractId(new_id.clone())),
                interface_id: None,
                observers: Vec::new(),
            },
            EngineEvent::Exercise {
                contract_id: root.clone(),
                choice: "Bump".into(),
                consuming: true,
                actors: vec!["alice".into()],
                depth: 1,
                argument: Value::Unit,
                result: Some(Value::ContractId(new_id.clone())),
                interface_id: None,
                observers: Vec::new(),
            },
            EngineEvent::Create {
                contract_id: new_id,
                template_id: "M:Cell".into(),
                depth: 2
            },
        ]
    );
}

#[test]
fn exercise_on_contract_created_earlier_in_same_choice_body() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = engine
        .create_as(&["alice"], PKG, "M:Cell", &cell_payload("alice", 1))
        .unwrap();
    let result = engine
        .exercise_as(&["alice"], &root, "Spawn", &Value::Unit)
        .unwrap();
    // Spawn creates Cell{n=100} then exercises Peek on it: the value is 100.
    assert_eq!(result, Value::Int64(100));
    // Peek is non-consuming, so both cells remain active.
    assert_eq!(active_ids(&engine).len(), 2);
}

#[test]
fn nested_fetch_returns_the_contract_payload() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = engine
        .create_as(&["alice"], PKG, "M:Cell", &cell_payload("alice", 41))
        .unwrap();
    let result = engine
        .exercise_as(&["alice"], &root, "FetchSelf", &Value::Unit)
        .unwrap();
    assert_eq!(result, Value::Int64(41));
    assert!(engine.events().contains(&EngineEvent::Fetch {
        contract_id: root,
        depth: 1,
        authorizers: vec!["alice".into()],
        interface_id: None,
    }));
}

#[test]
fn consuming_choice_archives_before_its_body_so_fetching_self_fails() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = engine
        .create_as(&["alice"], PKG, "M:Cell", &cell_payload("alice", 1))
        .unwrap();
    let err = engine
        .exercise_as(&["alice"], &root, "BumpThenFetch", &Value::Unit)
        .unwrap_err();
    assert!(
        matches!(&err, EvalError::ContractNotActive { contract_id } if *contract_id == root),
        "{err:?}"
    );
    // A failed command leaves the ledger as it was: the archive is rolled back with it.
    assert!(engine.contract(&root).unwrap().active);
}

#[test]
fn second_nested_exercise_of_a_consumed_contract_aborts_the_whole_command() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = engine
        .create_as(&["alice"], PKG, "M:Cell", &cell_payload("alice", 1))
        .unwrap();
    let err = engine
        .exercise_as(&["alice"], &root, "Twice", &Value::Unit)
        .unwrap_err();
    assert!(
        matches!(err, EvalError::ContractNotActive { .. }),
        "{err:?}"
    );
    // The first Bump's create must not leak out of the aborted command.
    assert_eq!(active_ids(&engine), vec![root]);
    assert_eq!(engine.events().len(), 1, "only the original create remains");
}

#[test]
fn fetch_of_unknown_contract_is_contract_not_found() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = engine
        .create_as(&["alice"], PKG, "M:Cell", &cell_payload("alice", 1))
        .unwrap();
    // Watch.Go exercises `victim`; point it at an id the engine never issued.
    let watch = Value::Record {
        tycon: None,
        fields: vec![
            ("owner".into(), Value::Party("alice".into())),
            ("watcher".into(), Value::Party("bob".into())),
            ("victim".into(), cid("#999")),
        ],
    };
    let watch_id = engine
        .create_as(&["alice"], PKG, "M:Watch", &watch)
        .unwrap();
    let err = engine
        .exercise_as(&["alice"], &watch_id, "Go", &Value::Unit)
        .unwrap_err();
    assert!(
        matches!(&err, EvalError::ContractNotFound { contract_id } if contract_id == "#999"),
        "{err:?}"
    );
    assert!(engine.contract(&root).unwrap().active);
}

/// Speedy evaluates the choice observers before the exercise begins (`computeChoiceObservers`); an error there
/// fails the exercise like any other.
#[test]
fn an_error_in_the_choice_observers_fails_the_exercise() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = engine
        .create_as(&["alice"], PKG, "M:Cell", &cell_payload("alice", 1))
        .unwrap();
    let err = engine
        .exercise_as(&["alice"], &root, "LoudObservers", &Value::Unit)
        .unwrap_err();
    assert!(err.to_string().contains("MyErr"), "{err:?}");
}

#[test]
fn observer_confers_no_authority_on_nested_exercise() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    // The victim Cell is owned (and signed) by bob; bob is only an OBSERVER of the Watch.
    let victim = engine
        .create_as(&["bob"], PKG, "M:Cell", &cell_payload("bob", 1))
        .unwrap();
    let watch = Value::Record {
        tycon: None,
        fields: vec![
            ("owner".into(), Value::Party("alice".into())),
            ("watcher".into(), Value::Party("bob".into())),
            ("victim".into(), cid(&victim)),
        ],
    };
    let watch_id = engine
        .create_as(&["alice"], PKG, "M:Watch", &watch)
        .unwrap();
    // Without visibility (disclosure or readAs), alice cannot even see bob's Cell.
    let invis_err = engine
        .exercise_as(&["alice"], &watch_id, "Go", &Value::Unit)
        .unwrap_err();
    assert!(
        matches!(&invis_err, EvalError::ContractNotFound { contract_id } if contract_id == &victim),
        "expected ContractNotFound before disclosure, got {invis_err:?}"
    );
    // Explicit disclosure grants visibility (not authority), exposing the missing controller check.
    engine.disclose(&victim);
    let err = engine
        .exercise_as(&["alice"], &watch_id, "Go", &Value::Unit)
        .unwrap_err();
    // Bump's controller is bob, but the Go body only runs with {alice} (signatory+actor).
    // tx_model.rs would have let this through by treating all stakeholders as authorizers.
    let EvalError::Unauthorized {
        kind,
        what,
        missing,
        ..
    } = &err
    else {
        panic!("expected an authorization failure, got {err:?}");
    };
    assert_eq!(*kind, crate::AuthKind::Controllers);
    assert!(what.contains("exercise of M:Cell:Bump"), "{what}");
    assert_eq!(missing, &["bob".to_string()]);
    assert!(engine.contract(&victim).unwrap().active);
}

#[test]
fn signatory_authority_flows_to_nested_exercise() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let victim = engine
        .create_as(&["bob"], PKG, "M:Cell", &cell_payload("bob", 1))
        .unwrap();
    let delegate = Value::Record {
        tycon: None,
        fields: vec![
            ("owner".into(), Value::Party("alice".into())),
            ("partner".into(), Value::Party("bob".into())),
            ("victim".into(), cid(&victim)),
        ],
    };
    // Both alice and bob sign the Delegate, so bob's authority is available inside Go.
    let delegate_id = engine
        .create_as(&["alice", "bob"], PKG, "M:Delegate", &delegate)
        .unwrap();
    // Disclosure makes bob's pre-existing Cell visible to alice's submission without granting authority;
    // bob's authority still comes solely from being a signatory of Delegate.
    engine.disclose(&victim);
    let result = engine
        .exercise_as(&["alice"], &delegate_id, "Go", &Value::Unit)
        .unwrap();
    let Value::ContractId(new_id) = result else {
        panic!("expected contract id");
    };
    assert_eq!(cell_n(&engine, &new_id), 2);
    assert!(!engine.contract(&victim).unwrap().active);
}

#[test]
fn top_level_actor_must_cover_choice_controllers() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = engine
        .create_as(&["alice"], PKG, "M:Cell", &cell_payload("alice", 1))
        .unwrap();
    let invis_err = engine
        .exercise_as(&["mallory"], &root, "Peek", &Value::Unit)
        .unwrap_err();
    assert!(
        matches!(&invis_err, EvalError::ContractNotFound { contract_id } if contract_id == &root),
        "expected ContractNotFound when undisclosed, got {invis_err:?}"
    );
    engine.disclose(&root);
    let err = engine
        .exercise_as(&["mallory"], &root, "Peek", &Value::Unit)
        .unwrap_err();
    assert!(
        matches!(err, EvalError::Unauthorized { ref missing, .. } if missing == &["alice".to_string()]),
        "{err:?}"
    );
}

#[test]
fn create_requires_every_signatory_to_authorize() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let delegate = Value::Record {
        tycon: None,
        fields: vec![
            ("owner".into(), Value::Party("alice".into())),
            ("partner".into(), Value::Party("bob".into())),
            ("victim".into(), cid("#1")),
        ],
    };
    let err = engine
        .create_as(&["alice"], PKG, "M:Delegate", &delegate)
        .unwrap_err();
    assert!(
        matches!(
            err,
            EvalError::Unauthorized { kind: crate::AuthKind::Signatories, ref missing, .. }
                if missing == &["bob".to_string()]
        ),
        "{err:?}"
    );
    assert_eq!(active_ids(&engine).len(), 0);
}

#[test]
fn get_time_returns_the_host_clock() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    engine.set_time_micros(1_700_000_000_000_000);
    let root = engine
        .create_as(&["alice"], PKG, "M:Cell", &cell_payload("alice", 1))
        .unwrap();
    let result = engine
        .exercise_as(&["alice"], &root, "Clock", &Value::Unit)
        .unwrap();
    assert_eq!(result, Value::Int64(1_700_000_000_000_000));
}

/// Counts every host call so the laziness tests can assert on *absence* of effects.
#[derive(Default)]
struct CountingHost {
    creates: CountCell<u32>,
}

impl UpdateHost for CountingHost {
    fn create_contract(
        &mut self,
        _template_id: &str,
        _payload: &Value,
    ) -> Result<String, EvalError> {
        self.creates.set(self.creates.get() + 1);
        Ok(format!("#{}", self.creates.get()))
    }
}

fn run_choice_with_counting_host(choice: &str) -> (Result<Value, EvalError>, u32) {
    let world = build_world();
    let mut host = CountingHost::default();
    let result = world.eval_choice_update_in(
        PKG,
        "M",
        "Cell",
        choice,
        "#0",
        &cell_payload("alice", 1),
        &Value::Unit,
        &mut host,
    );
    (result, host.creates.get())
}

#[test]
fn update_passed_as_unused_argument_is_not_executed() {
    // Fails on the pre-suspension evaluator: the strictly evaluated `create` argument ran.
    let (result, creates) = run_choice_with_counting_host("LazyArg");
    assert_eq!(result.unwrap(), Value::Int64(7));
    assert_eq!(
        creates, 0,
        "an Update that is never run must have no effect"
    );
}

#[test]
fn when_false_create_does_not_create_but_when_true_does() {
    let (result, creates) = run_choice_with_counting_host("LazyCase");
    assert_eq!(result.unwrap(), Value::Int64(1));
    assert_eq!(creates, 0);

    // Positive control: the same shape with the condition flipped must create exactly once,
    // otherwise the zero above could be an evaluator that never creates at all.
    let (result, creates) = run_choice_with_counting_host("EagerCase");
    assert_eq!(result.unwrap(), Value::Int64(1));
    assert_eq!(creates, 1);
}

#[test]
fn hosts_that_only_implement_create_reject_exercise_fetch_and_time_with_a_typed_error() {
    let world = build_world();
    let mut host = CountingHost::default();
    let run = |choice: &str, host: &mut CountingHost| {
        world.eval_choice_update_in(
            PKG,
            "M",
            "Cell",
            choice,
            "#0",
            &cell_payload("alice", 1),
            &Value::Unit,
            host,
        )
    };
    assert!(matches!(
        run("OuterBump", &mut host),
        Err(EvalError::HostUnsupported("exercise"))
    ));
    assert!(matches!(
        run("FetchSelf", &mut host),
        Err(EvalError::HostUnsupported("fetch"))
    ));
    assert!(matches!(
        run("Clock", &mut host),
        Err(EvalError::HostUnsupported("get_time"))
    ));
}

#[test]
fn try_on_a_host_without_rollback_support_is_refused_not_run_unprotected() {
    // The default `begin_try` must fail: running the body with no checkpoint would let a
    // caught exception leave the ledger half-modified.
    let (result, creates) = run_choice_with_counting_host("Attempt");
    assert!(
        matches!(result, Err(EvalError::HostUnsupported("begin_try"))),
        "{result:?}"
    );
    assert_eq!(creates, 0);
}

#[test]
fn unbounded_nested_exercise_stops_at_the_depth_limit() {
    // Without the guard this would recurse on the native stack (each nested exercise
    // re-enters the evaluator), long before any per-body step limit triggers.
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = engine
        .create_as(&["alice"], PKG, "M:Cell", &cell_payload("alice", 1))
        .unwrap();
    let err = engine
        .exercise_as(&["alice"], &root, "Recurse", &Value::Unit)
        .unwrap_err();
    assert!(
        matches!(&err, EvalError::Host(m) if m.contains(&format!("exceeds {MAX_EXERCISE_DEPTH}"))),
        "{err:?}"
    );
    // The aborted command leaves nothing behind.
    assert_eq!(engine.events().len(), 1);
}

// ---------------------------------------------------------------------------------------
// TryCatch / exceptions / rollback (synthetic model tests, see the file header).
// ---------------------------------------------------------------------------------------

fn new_cell(engine: &mut Engine<'_>) -> String {
    engine
        .create_as(&["alice"], PKG, "M:Cell", &cell_payload("alice", 1))
        .unwrap()
}

fn run_choice(engine: &mut Engine<'_>, root: &str, choice: &str) -> Result<Value, EvalError> {
    engine.exercise_as(&["alice"], root, choice, &Value::Unit)
}

fn event_choices(engine: &Engine<'_>) -> Vec<String> {
    engine
        .events()
        .iter()
        .filter_map(|event| match event {
            EngineEvent::Exercise { choice, .. } => Some(choice.clone()),
            _ => None,
        })
        .collect()
}

// [CANTON-NOTE: SEMANTICS] JVM 3.7.2 refuses to roll back a `try` body that created or consumed a contract
// (`EffectfulRollbackError`, measured: tests/oracle/key-diff `rb*` scenarios). These synthetic tests used to assert that
// such a rollback silently undoes the body; that was an unverified assumption and is now the opposite. Rollbacks of
// bodies without effects are covered against the JVM by `key_diff`.
#[test]
fn a_try_that_created_a_contract_cannot_be_rolled_back() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = new_cell(&mut engine);
    let err = run_choice(&mut engine, &root, "TryRollbackCreate").unwrap_err();
    assert!(
        matches!(err, EvalError::EffectfulRollback { .. }),
        "{err:?}"
    );
    // The whole command is undone: only the original create is left.
    assert_eq!(active_ids(&engine), vec![root.clone()]);
    assert_eq!(engine.events().len(), 1, "{:?}", engine.events());
    assert_eq!(engine.open_checkpoints(), 0);
}

#[test]
fn a_try_that_archived_a_contract_cannot_be_rolled_back() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = new_cell(&mut engine);
    let err = run_choice(&mut engine, &root, "TryRollbackArchive").unwrap_err();
    assert!(
        matches!(err, EvalError::EffectfulRollback { .. }),
        "{err:?}"
    );
    // The refused command leaves the original contract active and nothing else.
    assert!(engine.contract(&root).unwrap().active);
    assert_eq!(active_ids(&engine), vec![root.clone()]);
    assert_eq!(engine.events().len(), 1);
}

#[test]
fn try_without_exception_keeps_the_body_effects() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = new_cell(&mut engine);
    let result = run_choice(&mut engine, &root, "TryOk").unwrap();
    let Value::ContractId(created) = result else {
        panic!("expected the created id, got {result:?}");
    };
    assert_eq!(cell_n(&engine, &created), 5);
    assert!(engine.contract(&created).unwrap().active);
    assert_eq!(
        engine.open_checkpoints(),
        0,
        "end_try must release the checkpoint"
    );
}

#[test]
fn uncaught_exception_aborts_the_command_and_reports_the_flat_error() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = new_cell(&mut engine);
    let err = run_choice(&mut engine, &root, "ThrowPlain").unwrap_err();
    // Same error_id/message shape the pre-TryCatch evaluator produced.
    let EvalError::UnhandledException { error_id, message } = &err else {
        panic!("expected UnhandledException, got {err:?}");
    };
    assert_eq!(error_id, "UNHANDLED_EXCEPTION/M:MyErr");
    assert_eq!(message, "boom");
    // Whole command undone: no Cell{n=6}, only the original create is journaled.
    assert_eq!(active_ids(&engine), vec![root]);
    assert_eq!(engine.events().len(), 1);
}

#[test]
fn nested_try_whose_inner_body_created_a_contract_is_refused() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = new_cell(&mut engine);
    let err = run_choice(&mut engine, &root, "NestedInnerCatches").unwrap_err();
    assert!(
        matches!(err, EvalError::EffectfulRollback { .. }),
        "{err:?}"
    );
    assert_eq!(active_ids(&engine), vec![root]);
}

#[test]
fn a_declining_handler_still_triggers_the_effectful_rollback_check() {
    // Speedy rolls back before it looks at the handler, so even a handler that would decline the exception turns an
    // effectful body into an `EffectfulRollbackError` (measured: `rbUncaught`).
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = new_cell(&mut engine);
    let err = run_choice(&mut engine, &root, "NestedOuterCatches").unwrap_err();
    assert!(
        matches!(err, EvalError::EffectfulRollback { .. }),
        "{err:?}"
    );
    assert_eq!(active_ids(&engine), vec![root]);
    assert_eq!(engine.open_checkpoints(), 0);
}

#[test]
fn effects_of_a_nested_exercise_that_threw_make_the_parents_rollback_illegal() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = new_cell(&mut engine);
    // Boom creates n=500 in a child machine and throws; the parent's try would have to roll that create back.
    let err = run_choice(&mut engine, &root, "CatchBoom").unwrap_err();
    assert!(
        matches!(err, EvalError::EffectfulRollback { .. }),
        "{err:?}"
    );
    assert_eq!(active_ids(&engine), vec![root]);
    // The refused command is journaled nowhere.
    assert!(event_choices(&engine).is_empty());
}

#[test]
fn exception_thrown_by_the_handlers_own_action_goes_to_the_enclosing_try() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = new_cell(&mut engine);
    // Inner handler (catch-all) throws OtherErr; only the outer try accepts OtherErr.
    let result = run_choice(&mut engine, &root, "ThrowInHandler").unwrap();
    assert_eq!(result, Value::Int64(11));
    assert_eq!(engine.open_checkpoints(), 0);
}

#[test]
fn host_errors_are_not_catchable_even_by_a_catch_everything_handler() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = new_cell(&mut engine);

    // Unknown contract id.
    let err = engine
        .exercise_as(&["alice"], &root, "TryBadFetch", &cid("#999"))
        .unwrap_err();
    assert!(
        matches!(&err, EvalError::ContractNotFound { contract_id } if contract_id == "#999"),
        "{err:?}"
    );

    // Archived contract: a consuming Bump leaves the old id inactive.
    let bumped = engine
        .exercise_as(&["alice"], &root, "Bump", &Value::Unit)
        .unwrap();
    assert!(matches!(bumped, Value::ContractId(_)));
    let live = new_cell(&mut engine);
    let err = engine
        .exercise_as(&["alice"], &live, "TryBadFetch", &cid(&root))
        .unwrap_err();
    assert!(
        matches!(&err, EvalError::ContractNotActive { contract_id } if *contract_id == root),
        "{err:?}"
    );

    // Authorization failure (partner bob never authorized the Delegate create).
    let err = engine
        .exercise_as(
            &["alice"],
            &live,
            "TryUnauthorized",
            &Value::Party("bob".into()),
        )
        .unwrap_err();
    assert!(
        matches!(&err, EvalError::Unauthorized { missing, .. } if missing == &["bob".to_string()]),
        "{err:?}"
    );

    // Engine limit (exercise depth).
    let err = run_choice(&mut engine, &live, "TryRecurse").unwrap_err();
    assert!(
        matches!(&err, EvalError::Host(m) if m.contains(&format!("exceeds {MAX_EXERCISE_DEPTH}"))),
        "{err:?}"
    );

    // Abandoned try frames must not leave checkpoints behind for the next command.
    assert_eq!(engine.open_checkpoints(), 0);
    assert!(engine.contract(&live).unwrap().active);
}

#[test]
fn failed_ensure_is_a_catchable_precondition_failed_exception() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = new_cell(&mut engine);
    let result = run_choice(&mut engine, &root, "TryEnsure").unwrap();
    assert_eq!(
        result,
        Value::Text("Template precondition violated: M:Guarded".into())
    );
    assert_eq!(active_ids(&engine), vec![root.clone()]);

    // Without a try it still surfaces with the exact error_id the ledger always used.
    let err = engine
        .exercise_as(&["alice"], &root, "MakeGuarded", &Value::Int64(-1))
        .unwrap_err();
    assert!(
        matches!(&err, EvalError::UnhandledException { error_id, .. }
            if error_id == "UNHANDLED_EXCEPTION/DA.Exception.PreconditionFailed:PreconditionFailed"),
        "{err:?}"
    );
    // A passing `ensure` creates normally.
    engine
        .exercise_as(&["alice"], &root, "MakeGuarded", &Value::Int64(3))
        .unwrap();
    assert_eq!(active_ids(&engine).len(), 2);
}

#[test]
fn from_any_exception_matches_only_the_same_static_exception_type() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = new_cell(&mut engine);
    let hit = run_choice(&mut engine, &root, "RoundTripMatch").unwrap();
    assert_eq!(hit, Value::Text("rt".into()));
    let miss = run_choice(&mut engine, &root, "RoundTripMismatch").unwrap();
    assert_eq!(miss, Value::Text("none".into()));
}

#[test]
fn stale_or_unknown_checkpoint_is_a_host_error() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let err = engine.abort_try(crate::TryCheckpoint(0)).unwrap_err();
    assert!(
        matches!(err, EvalError::Host(ref m) if m.contains("stale")),
        "{err:?}"
    );
    let err = engine.end_try(crate::TryCheckpoint(3)).unwrap_err();
    assert!(matches!(err, EvalError::Host(_)), "{err:?}");
}

// ---------------------------------------------------------------------------------------
// Generic command API (`execute_create` / `execute_exercise`). Synthetic model tests on the
// hand-built world above, NOT oracle comparisons; the real-DAR end-to-end checks are in
// `tests/generic_exec_real_dar.rs`.
// ---------------------------------------------------------------------------------------

use crate::engine::{ExecError, NewContract};
use crate::AuthKind;

fn guarded_payload(owner: &str, n: i64) -> Value {
    Value::Record {
        tycon: None,
        fields: vec![
            ("owner".into(), Value::Party(owner.into())),
            ("n".into(), Value::Int64(n)),
        ],
    }
}

#[test]
fn execute_exercise_reports_created_and_archived_across_nested_exercises() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = engine
        .execute_create(&["alice"], "M:Cell", &cell_payload("alice", 1))
        .unwrap()
        .contract_id;

    // OuterBump (non-consuming) exercises the consuming Bump on the same contract.
    let outcome = engine
        .execute_exercise(&["alice"], &root, "OuterBump", &Value::Unit)
        .unwrap();
    assert!(!outcome.consuming, "the root choice is non-consuming");
    // The archive comes from the *nested* exercise, not from the root choice.
    assert_eq!(outcome.archived, vec![root.clone()]);
    assert_eq!(outcome.created.len(), 1);
    assert!(outcome.created[0].active);
    assert_eq!(
        outcome.result,
        Value::ContractId(outcome.created[0].contract_id.clone())
    );
    assert_eq!(cell_n(&engine, &outcome.created[0].contract_id), 2);
}

#[test]
fn failed_execute_exercise_leaves_the_engine_untouched_and_is_typed() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let root = engine
        .execute_create(&["alice"], "M:Cell", &cell_payload("alice", 1))
        .unwrap()
        .contract_id;
    let events_before = engine.events().len();

    // Visibility: mallory is neither signatory nor observer of the cell, so it cannot see it (S-TX-001: the JVM
    // answers ContractNotFound for such a submitter). The controller rule is covered with stakeholders elsewhere.
    let err = engine
        .execute_exercise(&["mallory"], &root, "Bump", &Value::Unit)
        .unwrap_err();
    assert!(
        matches!(&err, ExecError::ContractNotFound(id) if id == &root),
        "{err:?}"
    );
    assert_eq!(active_ids(&engine), vec![root.clone()]);
    assert_eq!(engine.events().len(), events_before);

    assert!(matches!(
        engine.execute_exercise(&["alice"], "#nope", "Bump", &Value::Unit),
        Err(ExecError::ContractNotFound(id)) if id == "#nope"
    ));
    assert!(matches!(
        engine.execute_exercise(&["alice"], &root, "NoSuchChoice", &Value::Unit),
        Err(ExecError::UnknownChoice { choice, .. }) if choice == "NoSuchChoice"
    ));
    // After a successful consuming exercise the contract is no longer active.
    engine
        .execute_exercise(&["alice"], &root, "Bump", &Value::Unit)
        .unwrap();
    assert!(matches!(
        engine.execute_exercise(&["alice"], &root, "Bump", &Value::Unit),
        Err(ExecError::ContractNotActive(id)) if id == root
    ));
}

#[test]
fn execute_create_enforces_signatories_ensure_and_template_existence() {
    let world = build_world();
    let mut engine = Engine::new(&world);

    let delegate = Value::Record {
        tycon: None,
        fields: vec![
            ("owner".into(), Value::Party("alice".into())),
            ("partner".into(), Value::Party("bob".into())),
            ("victim".into(), cid("#1")),
        ],
    };
    let err = engine
        .execute_create(&["alice"], "M:Delegate", &delegate)
        .unwrap_err();
    assert!(
        matches!(&err, ExecError::Unauthorized { kind: AuthKind::Signatories, missing, .. }
            if missing == &["bob".to_string()]),
        "{err:?}"
    );

    let err = engine
        .execute_create(&["alice"], "M:Guarded", &guarded_payload("alice", 0))
        .unwrap_err();
    assert!(
        matches!(&err, ExecError::PreconditionFailed { message } if message.contains("M:Guarded")),
        "{err:?}"
    );

    assert!(matches!(
        engine.execute_create(&["alice"], "M:Nope", &Value::Unit),
        Err(ExecError::UnknownTemplate { .. })
    ));
    assert!(matches!(
        engine.execute_create(&["alice"], "not-a-template-id", &Value::Unit),
        Err(ExecError::UnknownTemplate { .. })
    ));
    assert!(
        active_ids(&engine).is_empty(),
        "no failed command may leave a contract"
    );

    let ok = engine
        .execute_create(&["alice"], "M:Guarded", &guarded_payload("alice", 1))
        .unwrap();
    assert!(ok.active);
    assert_eq!(ok.signatories, vec!["alice".to_string()]);
}

/// [CANTON-NOTE: SEMANTICS] The path the engine hands a create counts every node among the siblings, a fetch included (the official participant
/// approves that numbering, `doc/slices/S-SPL-002.md`). Here: `BumpThenFetch` is a consuming choice whose body fetches `self` (inactive, so it
/// fails) — instead the positions are checked on event lists that have the shape of `Tree.Driver.Run` (fetch, exercise with a create below,
/// create) and on a real engine run.
#[test]
fn node_paths_count_every_node_among_the_siblings() {
    let ev_create = |depth| EngineEvent::Create {
        contract_id: "c".into(),
        template_id: "M:T".into(),
        depth,
    };
    let ev_exercise = |depth| EngineEvent::Exercise {
        contract_id: "x".into(),
        choice: "C".into(),
        consuming: false,
        actors: vec![],
        depth,
        argument: Value::Unit,
        result: None,
        interface_id: None,
        observers: Vec::new(),
    };
    let ev_fetch = |depth| EngineEvent::Fetch {
        contract_id: "f".into(),
        depth,
        authorizers: vec![],
        interface_id: None,
    };
    // root exercise; fetch (0); nested exercise (1) with a create (1,0) and a fetch (1,1); create (2)
    let events = vec![
        ev_exercise(0),
        ev_fetch(1),
        ev_exercise(1),
        ev_create(2),
        ev_fetch(2),
        ev_create(1),
    ];
    let (after, paths) = crate::engine::NodePaths::of_events(&events);
    assert_eq!(
        paths,
        vec![vec![], vec![0], vec![1], vec![1, 0], vec![1, 1], vec![2]]
    );
    // the next create under the root is child 3; under the second nested exercise it would be (1, 2)
    assert_eq!(after.peek(1), vec![3]);
    assert_eq!(after.peek(2), vec![1, 2]);
    // a second nested exercise restarts the count below it, and an exercise two levels down has the path of both ancestors
    let mut more = events;
    more.extend([ev_exercise(1), ev_exercise(2), ev_create(3)]);
    let (_, paths) = crate::engine::NodePaths::of_events(&more);
    assert_eq!(paths[6], vec![3]);
    assert_eq!(paths[7], vec![3, 0]);
    assert_eq!(paths[8], vec![3, 0, 0]);
    // a root create is no node below anything
    assert_eq!(after.peek(0), Vec::<usize>::new());
}

#[test]
fn the_allocator_is_told_where_a_create_sits_in_the_tree() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let seen = std::rc::Rc::new(RefCell::new(Vec::<Vec<usize>>::new()));
    let log = std::rc::Rc::clone(&seen);
    let mut counter = 0;
    engine.set_contract_id_allocator(move |new: &NewContract<'_>| {
        counter += 1;
        log.borrow_mut().push(new.path.to_vec());
        format!("#local:{counter}")
    });
    let root = engine
        .execute_create(&["alice"], "M:Cell", &cell_payload("alice", 1))
        .unwrap();
    // a root create has no path
    assert_eq!(*seen.borrow(), vec![Vec::<usize>::new()]);
    // OuterBump: the nested Bump is child 0 of the root exercise, and the Cell it creates is child 0 of that
    engine
        .execute_exercise(&["alice"], &root.contract_id, "OuterBump", &Value::Unit)
        .unwrap();
    assert_eq!(seen.borrow()[1], vec![0, 0]);
    // Spawn: the create is child 0 of the root exercise (the exercise of Peek on it is child 1)
    let spawned = engine.execute_exercise(&["alice"], "#local:1", "Spawn", &Value::Unit);
    // `#local:1` was consumed by OuterBump: the command fails before it allocates anything
    assert!(spawned.is_err());
    assert_eq!(seen.borrow().len(), 2);
    let fresh = engine
        .execute_create(&["alice"], "M:Cell", &cell_payload("alice", 2))
        .unwrap();
    engine
        .execute_exercise(&["alice"], &fresh.contract_id, "Spawn", &Value::Unit)
        .unwrap();
    assert_eq!(seen.borrow()[3], vec![0]);
}

#[test]
fn injected_allocator_names_every_created_contract_including_nested_ones() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    let seen = std::rc::Rc::new(RefCell::new(Vec::<(String, usize)>::new()));
    let log = std::rc::Rc::clone(&seen);
    let mut counter = 0;
    engine.set_contract_id_allocator(move |new: &NewContract<'_>| {
        counter += 1;
        log.borrow_mut()
            .push((new.template_id.to_string(), new.creation_index));
        format!("#local:{counter}")
    });

    let root = engine
        .execute_create(&["alice"], "M:Cell", &cell_payload("alice", 1))
        .unwrap();
    assert_eq!(root.contract_id, "#local:1");
    let outcome = engine
        .execute_exercise(&["alice"], &root.contract_id, "OuterBump", &Value::Unit)
        .unwrap();
    assert_eq!(outcome.created[0].contract_id, "#local:2");
    assert_eq!(outcome.result, Value::ContractId("#local:2".into()));
    // `creation_index` restarts for every root command.
    assert_eq!(
        *seen.borrow(),
        vec![("M:Cell".to_string(), 0), ("M:Cell".to_string(), 0)]
    );
}

#[test]
fn allocator_returning_an_existing_id_is_refused_and_state_is_kept() {
    let world = build_world();
    let mut engine = Engine::new(&world);
    engine.set_contract_id_allocator(|_: &NewContract<'_>| "#same".to_string());
    engine
        .execute_create(&["alice"], "M:Cell", &cell_payload("alice", 1))
        .unwrap();
    let err = engine
        .execute_create(&["alice"], "M:Cell", &cell_payload("alice", 2))
        .unwrap_err();
    assert!(
        matches!(&err, ExecError::Eval(EvalError::Host(m)) if m.contains("allocated twice")),
        "{err:?}"
    );
    assert_eq!(
        cell_n(&engine, "#same"),
        1,
        "the first contract must not be overwritten"
    );
}

#[test]
fn imported_contracts_can_be_exercised_and_duplicates_are_refused() {
    let world = build_world();
    let mut source = Engine::new(&world);
    let created = source
        .execute_create(&["alice"], "M:Cell", &cell_payload("alice", 5))
        .unwrap();

    let mut engine = Engine::new(&world);
    engine.import_contract(created.clone()).unwrap();
    assert!(engine.import_contract(created.clone()).is_err());
    let outcome = engine
        .execute_exercise(&["alice"], &created.contract_id, "Bump", &Value::Unit)
        .unwrap();
    assert!(outcome.consuming);
    assert_eq!(outcome.archived, vec![created.contract_id.clone()]);
    // The default `#n` scheme must not collide with the imported `#1`.
    assert_ne!(outcome.created[0].contract_id, created.contract_id);
    assert_eq!(cell_n(&engine, &outcome.created[0].contract_id), 6);
}
