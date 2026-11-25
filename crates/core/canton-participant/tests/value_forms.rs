//! F1: the forms of a template argument computed from the evaluator's value and the declared type equal the ones the sample-contract tests wrote
//! by hand (`tests/sequencer_connect.rs::rust_creates_sample`), which the official mediator approved.
#![cfg(feature = "sequencer-grpc")]
use canton_participant::contract_id::HashValue;
use canton_participant::contract_wire::LfValue;
use canton_participant::value_forms::forms;
use lf_eval::typed_json::Types;
use lf_eval::{Value, World};
use std::path::Path;

fn sample(amount_unscaled: i128) -> Value {
    Value::Record {
        tycon: Some("AssetHolding:AssetHolding".into()),
        fields: vec![
            ("bank".into(), Value::Party("erin::1220".into())),
            ("owner".into(), Value::Party("erin::1220".into())),
            ("auditor".into(), Value::Party("alice::1220".into())),
            ("assetSymbol".into(), Value::Text("USD".into())),
            (
                "amount".into(),
                Value::Numeric {
                    coeff: amount_unscaled,
                    scale: 10,
                },
            ),
        ],
    }
}

#[test]
fn the_sample_template_has_the_forms_the_tests_wrote_by_hand() {
    let world = World::open(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar"),
    )
    .unwrap();
    let types = Types::new(&world);
    let ty = types
        .template(world.main_package_id(), "AssetHolding:AssetHolding")
        .unwrap();
    let (lf, hash) = forms(&types, &ty, &sample(1_005_000_000_000)).unwrap();
    // what `rust_creates_sample` writes for the amount "100.5"
    assert_eq!(
        lf,
        LfValue::Record(vec![
            LfValue::Party("erin::1220".into()),
            LfValue::Party("erin::1220".into()),
            LfValue::Party("alice::1220".into()),
            LfValue::Text("USD".into()),
            LfValue::Numeric("100.5000000000".into()),
        ])
    );
    assert_eq!(
        hash,
        HashValue::Record {
            module: vec!["AssetHolding".into()],
            name: vec!["AssetHolding".into()],
            fields: vec![
                ("bank".into(), HashValue::Party("erin::1220".into())),
                ("owner".into(), HashValue::Party("erin::1220".into())),
                ("auditor".into(), HashValue::Party("alice::1220".into())),
                ("assetSymbol".into(), HashValue::Text("USD".into())),
                ("amount".into(), HashValue::Numeric(1_005_000_000_000)),
            ],
        }
    );
}

#[test]
fn a_value_that_does_not_fit_its_type_is_refused() {
    let world = World::open(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar"),
    )
    .unwrap();
    let types = Types::new(&world);
    let ty = types
        .template(world.main_package_id(), "AssetHolding:AssetHolding")
        .unwrap();
    // a field missing
    let Value::Record { tycon, mut fields } = sample(1) else {
        unreachable!()
    };
    fields.pop();
    assert!(forms(&types, &ty, &Value::Record { tycon, fields })
        .unwrap_err()
        .contains("fields"));
    // a text where a party is declared
    let Value::Record { tycon, mut fields } = sample(1) else {
        unreachable!()
    };
    fields[0].1 = Value::Text("x".into());
    assert!(forms(&types, &ty, &Value::Record { tycon, fields }).is_err());
    // a numeric whose digits would be lost at the declared scale is not rounded
    let Value::Record { tycon, mut fields } = sample(1) else {
        unreachable!()
    };
    fields[4].1 = Value::Numeric {
        coeff: 1,
        scale: 12,
    };
    assert!(forms(&types, &ty, &Value::Record { tycon, fields }).is_err());
}
