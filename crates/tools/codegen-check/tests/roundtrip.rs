//! G10 (AT-K05): the generated Rust types read and write the Daml-LF JSON the same way the evaluator's reader (`typed_json`, itself checked
//! against the official Splice scan data) does: what one accepts the other accepts, and what comes out equals what went in.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use codegen_check::bindings::{other, types};
use lf_eval::typed_json::{LfType, Types};
use lf_eval::World;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value as Json};
use std::path::Path;

fn world() -> World {
    World::open(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../tests/oracle/codegen/codegen-fixture.dar"),
    )
    .unwrap()
}

fn con(world: &World, module: &str, name: &str, args: Vec<LfType>) -> LfType {
    LfType::Con {
        package_id: world.main_package_id().to_string(),
        module: module.into(),
        name: name.into(),
        args,
    }
}

/// Both readers accept `sample`, and the generated type writes it back unchanged.
fn same<T: Serialize + DeserializeOwned>(world: &World, ty: &LfType, sample: Json) {
    Types::new(world)
        .decode(ty, &sample)
        .unwrap_or_else(|e| panic!("the evaluator's reader refuses {sample}: {e}"));
    let value: T = serde_json::from_value(sample.clone())
        .unwrap_or_else(|e| panic!("the generated type refuses {sample}: {e}"));
    assert_eq!(serde_json::to_value(&value).unwrap(), sample);
}

/// Both readers refuse `sample`.
fn both_refuse<T: DeserializeOwned>(world: &World, ty: &LfType, sample: Json) {
    assert!(
        Types::new(world).decode(ty, &sample).is_err(),
        "the evaluator's reader accepts {sample}"
    );
    assert!(
        serde_json::from_value::<T>(sample.clone()).is_err(),
        "the generated type accepts {sample}"
    );
}

#[test]
fn scalars_and_reserved_words() {
    let w = world();
    let plain = json!({"a":"1","b":"x","c":true,"d":"alice::1220","e":"1.5","f":"0.0000000001","g":"2026-11-14","h":"2026-11-14T01:02:03Z","i":{}});
    same::<types::Plain>(&w, &con(&w, "Types", "Plain", vec![]), plain);
    let reserved: serde_json::Map<String, Json> = [
        "type_", "class_", "fn", "match", "new", "final", "function", "default_", "import_",
        "package", "in_", "self", "where_", "async", "await", "yield", "var", "let_",
    ]
    .iter()
    .enumerate()
    .map(|(i, n)| ((*n).to_string(), json!((i as i64 + 1).to_string())))
    .collect();
    same::<types::Reserved>(
        &w,
        &con(&w, "Types", "Reserved", vec![]),
        Json::Object(reserved),
    );
}

#[test]
fn enums_variants_and_recursion() {
    let w = world();
    same::<types::Color>(&w, &con(&w, "Types", "Color", vec![]), json!("Green"));
    let shape = con(&w, "Types", "Shape", vec![]);
    for sample in [
        json!({"tag":"Circle","value":"3"}),
        json!({"tag":"Rect","value":{"w":"1","h":"2"}}),
        json!({"tag":"Empty","value":{}}),
    ] {
        same::<types::Shape>(&w, &shape, sample);
    }
    let tree = con(&w, "Types", "Tree", vec![LfType::Int64]);
    let leaf = json!({"tag":"Leaf","value":{}});
    let node =
        |l: Json, v: &str, r: Json| json!({"tag":"Node","value":{"left":l,"value":v,"right":r}});
    same::<types::Tree<codegen_check::bindings::runtime::Int64>>(
        &w,
        &tree,
        node(leaf.clone(), "5", node(leaf.clone(), "6", leaf)),
    );
    let pair = con(&w, "Types", "Pair", vec![LfType::Int64, LfType::Text]);
    same::<types::Pair<codegen_check::bindings::runtime::Int64, String>>(
        &w,
        &pair,
        json!({"first":"1","second":"t"}),
    );
}

#[test]
fn containers_and_nested_optionals() {
    let w = world();
    let ty = con(&w, "Types", "Containers", vec![]);
    for opt_opt in [json!(null), json!([]), json!(["3"])] {
        same::<types::Containers>(
            &w,
            &ty,
            json!({"opt":null,"optOpt":opt_opt,"xs":["a","b"],"tm":{"k":"1"},"gm":[["a","1"]],"nested":[[null,"bob"]],"tup":{"_1":"1","_2":"t"}}),
        );
    }
}

#[test]
fn templates_and_a_second_module_with_a_colliding_name() {
    let w = world();
    let asset = con(&w, "Types", "Asset", vec![]);
    same::<types::Asset>(
        &w,
        &asset,
        json!({"issuer":"a","owner":"b","amount":"10","note":null}),
    );
    same::<types::Asset>(
        &w,
        &asset,
        json!({"issuer":"a","owner":"b","amount":"10","note":"n"}),
    );
    // an absent optional field is `None` for both readers
    let absent = json!({"issuer":"a","owner":"b","amount":"10"});
    Types::new(&w).decode(&asset, &absent).unwrap();
    let read: types::Asset = serde_json::from_value(absent).unwrap();
    assert!(read.note.is_none());
    // `Other:Asset` is another type with the same name
    same::<other::Asset>(&w, &con(&w, "Other", "Asset", vec![]), json!({"kind":"k"}));
    same::<other::Holding>(
        &w,
        &con(&w, "Other", "Holding", vec![]),
        json!({"owner":"o","asset":{"kind":"k"}}),
    );
}

#[test]
fn what_the_evaluators_reader_refuses_the_generated_types_refuse() {
    let w = world();
    let asset = con(&w, "Types", "Asset", vec![]);
    both_refuse::<types::Asset>(&w, &asset, json!({"issuer":"a","owner":"b"}));
    both_refuse::<types::Asset>(
        &w,
        &asset,
        json!({"issuer":"a","owner":"b","amount":"10","extra":1}),
    );
    both_refuse::<types::Color>(&w, &con(&w, "Types", "Color", vec![]), json!("Purple"));
    both_refuse::<types::Shape>(
        &w,
        &con(&w, "Types", "Shape", vec![]),
        json!({"tag":"Triangle","value":{}}),
    );
}

#[test]
#[allow(
    clippy::assertions_on_constants,
    reason = "codegen test validates generated constant associated items at runtime"
)]
fn the_traits_say_where_a_template_and_its_choices_are_declared() {
    use codegen_check::bindings::runtime::{Choice, Template};
    let w = world();
    assert_eq!(<types::Asset as Template>::PACKAGE_ID, w.main_package_id());
    assert_eq!(
        (
            <types::Asset as Template>::MODULE,
            <types::Asset as Template>::ENTITY
        ),
        ("Types", "Asset")
    );
    assert_eq!(<types::Give as Choice<types::Asset>>::NAME, "Give");
    assert!(<types::Give as Choice<types::Asset>>::CONSUMING);
    assert!(!<types::Peek as Choice<types::Asset>>::CONSUMING);
}
