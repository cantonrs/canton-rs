//! Labelled value codec checks.
//!
//! Real here: the template/choice labels and types come from `sample-contract.dar`'s decoded
//! surface (`AssetHolding` fields, `Transfer`/`SplitTransfer`/`Settle` params), and the
//! positional wire bytes are compared with `Value::to_lf_value`.
//!
//! NOT here: no comparison against the official JSON API or any Canton encoder; the wire
//! format is this repository's own convention (protobuf of `lf_archive::Value::Record`).
//! Types the DAR does not exercise (Date, Timestamp, List, Optional, ContractId) are covered
//! with a hand-written synthetic schema, labelled as such below.

use std::path::{Path, PathBuf};

use lf_archive::{FieldDef, SurfaceType};
use lf_eval::codec::{CodecError, RecordSchema};
use lf_eval::ledger::{Holding, AUDITOR_PARTY, BANK_PARTY, OWNER_PARTY};
use lf_eval::Value;
use serde_json::json;

const TEMPLATE: &str = "AssetHolding:AssetHolding";

fn dar_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn surfaces() -> Vec<lf_archive::ModuleSurface> {
    lf_archive::parse_dar_file(dar_path())
        .expect("sample-contract.dar")
        .module_surfaces
}

fn template_schema() -> RecordSchema {
    RecordSchema::template(&surfaces(), TEMPLATE).expect("AssetHolding surface")
}

fn holding_value(tenths: i64) -> Value {
    Holding::new(BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, "USD", tenths).to_lf_record()
}

#[test]
fn schema_labels_come_from_the_dar_surface() {
    let schema = template_schema();
    assert_eq!(schema.tycon, TEMPLATE);
    let labels: Vec<&str> = schema.fields.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        labels,
        ["bank", "owner", "auditor", "assetSymbol", "amount"]
    );
    assert_eq!(schema.fields[4].1.display_daml(), "Decimal");

    let transfer = RecordSchema::choice_arg(&surfaces(), TEMPLATE, "Transfer").unwrap();
    assert_eq!(transfer.fields.len(), 1);
    assert_eq!(transfer.fields[0].0, "newOwner");
    let split = RecordSchema::choice_arg(&surfaces(), TEMPLATE, "SplitTransfer").unwrap();
    let split_labels: Vec<&str> = split.fields.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(split_labels, ["transferAmount", "recipient"]);
    let settle = RecordSchema::choice_arg(&surfaces(), TEMPLATE, "Settle").unwrap();
    assert!(settle.fields.is_empty());
}

#[test]
fn unknown_template_or_choice_is_a_typed_error() {
    assert_eq!(
        RecordSchema::template(&surfaces(), "AssetHolding:Nope").unwrap_err(),
        CodecError::UnknownTemplate("AssetHolding:Nope".into())
    );
    assert_eq!(
        RecordSchema::template(&surfaces(), "no-colon").unwrap_err(),
        CodecError::UnknownTemplate("no-colon".into())
    );
    assert!(matches!(
        RecordSchema::choice_arg(&surfaces(), TEMPLATE, "Nope"),
        Err(CodecError::UnknownChoice { choice, .. }) if choice == "Nope"
    ));
}

#[test]
fn wire_round_trip_restores_labels_and_matches_the_positional_encoding() {
    let schema = template_schema();
    let value = holding_value(1000);
    let bytes = schema.encode(&value).unwrap();

    // The labelled codec must produce exactly what the positional `to_lf_value` produces for
    // the same record: it is a schema-aware layer over it, not a second format.
    assert_eq!(bytes, value.to_lf_value().encode_to_vec());
    assert_eq!(schema.decode(&bytes).unwrap(), value);
    // Re-encoding the decoded value is byte-stable (commitments hash these bytes).
    assert_eq!(
        schema.encode(&schema.decode(&bytes).unwrap()).unwrap(),
        bytes
    );
}

#[test]
fn encode_follows_schema_order_not_value_order() {
    let schema = template_schema();
    let Value::Record { tycon, mut fields } = holding_value(10) else {
        unreachable!()
    };
    fields.reverse();
    let shuffled = Value::Record { tycon, fields };
    assert_eq!(
        schema.encode(&shuffled).unwrap(),
        schema.encode(&holding_value(10)).unwrap()
    );
}

#[test]
fn json_round_trip_normalizes_numeric_scale() {
    let schema = template_schema();
    let input = json!({
        "bank": BANK_PARTY, "owner": OWNER_PARTY, "auditor": AUDITOR_PARTY,
        "assetSymbol": "USD", "amount": "100.0"
    });
    let value = schema.from_json(&input).unwrap();
    assert_eq!(
        value,
        holding_value(1000),
        "100.0 must become scale-10 Decimal"
    );
    let back = schema.to_json(&value).unwrap();
    assert_eq!(back["amount"], json!("100.0000000000"));
    assert_eq!(schema.from_json(&back).unwrap(), value);

    // An integer JSON number is accepted too (no f64 involved).
    let mut int_amount = input;
    int_amount["amount"] = json!(100);
    assert_eq!(schema.from_json(&int_amount).unwrap(), value);
}

#[test]
fn choice_argument_json_and_empty_record_wire_form() {
    let transfer = RecordSchema::choice_arg(&surfaces(), TEMPLATE, "Transfer").unwrap();
    let arg = transfer
        .from_json(&json!({ "newOwner": BANK_PARTY }))
        .unwrap();
    assert_eq!(
        arg,
        Value::Record {
            tycon: Some("AssetHolding:Transfer".into()),
            fields: vec![("newOwner".into(), Value::Party(BANK_PARTY.into()))],
        }
    );
    assert_eq!(
        transfer.decode(&transfer.encode(&arg).unwrap()).unwrap(),
        arg
    );

    // A zero-parameter choice takes an *empty record*: protobuf field 13, length 0.
    let settle = RecordSchema::choice_arg(&surfaces(), TEMPLATE, "Settle").unwrap();
    let empty = settle.from_json(&json!({})).unwrap();
    assert_eq!(settle.encode(&empty).unwrap(), vec![0x6a, 0x00]);
    assert_eq!(settle.decode(&[0x6a, 0x00]).unwrap(), empty);
}

#[test]
fn empty_and_garbage_bytes_are_rejected() {
    let schema = template_schema();
    assert_eq!(schema.decode(&[]).unwrap_err(), CodecError::EmptyInput);
    assert!(matches!(
        schema.decode(&[0xff, 0xff, 0xff]).unwrap_err(),
        CodecError::Wire(_)
    ));
    // `Unit` is valid protobuf but not a record.
    let unit = lf_archive::Value::Unit.encode_to_vec();
    assert!(matches!(
        schema.decode(&unit).unwrap_err(),
        CodecError::NotARecord { found, .. } if found == "Unit"
    ));
}

#[test]
fn non_canonical_bytes_are_rejected() {
    let schema = template_schema();
    let mut bytes = schema.encode(&holding_value(10)).unwrap();
    // Unknown protobuf field 20 (varint 0): prost would skip it, so only the canonical-form
    // check notices that these bytes are not the encoding of the value they decode to.
    bytes.extend_from_slice(&[0xa0, 0x01, 0x00]);
    assert_eq!(schema.decode(&bytes).unwrap_err(), CodecError::NonCanonical);
}

#[test]
fn wire_arity_and_type_mismatches_are_typed() {
    let schema = template_schema();
    let short = lf_archive::Value::Record {
        fields: vec![lf_archive::Value::Party(BANK_PARTY.into())],
    }
    .encode_to_vec();
    assert!(matches!(
        schema.decode(&short).unwrap_err(),
        CodecError::ArityMismatch {
            expected: 5,
            found: 1,
            ..
        }
    ));

    // Same arity, but `owner` carries a Text instead of a Party.
    let wrong = lf_archive::Value::Record {
        fields: vec![
            lf_archive::Value::Party(BANK_PARTY.into()),
            lf_archive::Value::Text("not-a-party".into()),
            lf_archive::Value::Party(AUDITOR_PARTY.into()),
            lf_archive::Value::Text("USD".into()),
            lf_archive::Value::Numeric("1.0000000000".into()),
        ],
    }
    .encode_to_vec();
    assert!(matches!(
        schema.decode(&wrong).unwrap_err(),
        CodecError::TypeMismatch { path, expected, found }
            if path == "AssetHolding:AssetHolding.owner" && expected == "Party" && found == "Text"
    ));
}

#[test]
fn json_unknown_missing_and_mistyped_fields_are_typed() {
    let schema = template_schema();
    let good = json!({
        "bank": BANK_PARTY, "owner": OWNER_PARTY, "auditor": AUDITOR_PARTY,
        "assetSymbol": "USD", "amount": "1.0"
    });

    let mut unknown = good.clone();
    unknown["ammount"] = json!("1.0"); // typo must never be ignored
    assert!(matches!(
        schema.from_json(&unknown).unwrap_err(),
        CodecError::UnknownField { field, .. } if field == "ammount"
    ));

    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("auditor");
    assert!(matches!(
        schema.from_json(&missing).unwrap_err(),
        CodecError::MissingField { field, .. } if field == "auditor"
    ));

    let mut mistyped = good;
    mistyped["bank"] = json!(5);
    assert!(matches!(
        schema.from_json(&mistyped).unwrap_err(),
        CodecError::TypeMismatch { path, found, .. }
            if path == "AssetHolding:AssetHolding.bank" && found == "number"
    ));

    assert!(matches!(
        schema.from_json(&json!("not an object")).unwrap_err(),
        CodecError::NotARecord { .. }
    ));
}

#[test]
fn json_numeric_garbage_and_lossy_scale_are_rejected() {
    let schema = template_schema();
    let with_amount = |amount: serde_json::Value| {
        schema.from_json(&json!({
            "bank": BANK_PARTY, "owner": OWNER_PARTY, "auditor": AUDITOR_PARTY,
            "assetSymbol": "USD", "amount": amount
        }))
    };
    for bad in ["1e5", "1.", ".5", "--5", "abc", "", "1.0.0", "+1"] {
        assert!(
            matches!(
                with_amount(json!(bad)),
                Err(CodecError::InvalidNumeric { .. })
            ),
            "{bad:?} must be an invalid numeric"
        );
    }
    // 11 fraction digits with a non-zero last digit would lose precision at scale 10 ...
    assert!(matches!(
        with_amount(json!("1.00000000001")),
        Err(CodecError::NumericScale { scale: 10, .. })
    ));
    // ... while a harmless trailing zero is fine.
    assert!(with_amount(json!("1.00000000000")).is_ok());
    // A fractional JSON *number* goes through f64 and is refused outright.
    assert!(matches!(
        with_amount(json!(1.5)),
        Err(CodecError::TypeMismatch { .. })
    ));
}

#[test]
fn encode_rejects_values_that_do_not_fit_the_schema() {
    let schema = template_schema();

    let Value::Record { tycon, mut fields } = holding_value(10) else {
        unreachable!()
    };
    fields.push(("extra".into(), Value::Unit));
    assert!(matches!(
        schema
            .encode(&Value::Record { tycon, fields })
            .unwrap_err(),
        CodecError::UnknownField { field, .. } if field == "extra"
    ));

    let Value::Record { tycon, mut fields } = holding_value(10) else {
        unreachable!()
    };
    fields.retain(|(name, _)| name != "owner");
    assert!(matches!(
        schema
            .encode(&Value::Record { tycon, fields })
            .unwrap_err(),
        CodecError::MissingField { field, .. } if field == "owner"
    ));

    // Wrong numeric scale in the evaluator value (a model bug, not user input).
    let Value::Record { tycon, mut fields } = holding_value(10) else {
        unreachable!()
    };
    fields.last_mut().unwrap().1 = Value::Numeric {
        coeff: 10,
        scale: 2,
    };
    assert!(matches!(
        schema.encode(&Value::Record { tycon, fields }).unwrap_err(),
        CodecError::NumericScale { scale: 10, .. }
    ));

    // A party the LF value layer refuses must not be encodable either.
    let bad_party = Value::Record {
        tycon: Some(TEMPLATE.into()),
        fields: vec![
            ("bank".into(), Value::Party("Bank!".into())),
            ("owner".into(), Value::Party(OWNER_PARTY.into())),
            ("auditor".into(), Value::Party(AUDITOR_PARTY.into())),
            ("assetSymbol".into(), Value::Text("USD".into())),
            (
                "amount".into(),
                Value::Numeric {
                    coeff: 10_000_000_000,
                    scale: 10,
                },
            ),
        ],
    };
    assert!(matches!(
        schema.encode(&bad_party).unwrap_err(),
        CodecError::Wire(_)
    ));
    assert!(matches!(
        schema.encode(&Value::Unit).unwrap_err(),
        CodecError::NotARecord { .. }
    ));
}

// --- Types the sample DAR does not use: SYNTHETIC schema, not taken from a DAR. -------------

fn synthetic_schema() -> RecordSchema {
    let field = |name: &str, ty: SurfaceType| {
        let def = FieldDef::new(name, ty);
        (def.name, def.ty)
    };
    RecordSchema {
        tycon: "Synthetic:Everything".into(),
        fields: vec![
            field("day", SurfaceType::Date),
            field("at", SurfaceType::Timestamp),
            field(
                "ids",
                SurfaceType::List(Box::new(SurfaceType::ContractId(Box::new(
                    SurfaceType::Text,
                )))),
            ),
            field("note", SurfaceType::Optional(Box::new(SurfaceType::Text))),
            field("count", SurfaceType::Int64),
            field("flag", SurfaceType::Bool),
            field("nothing", SurfaceType::Unit),
            field("rate", SurfaceType::Numeric(Some(4))),
        ],
    }
}

fn synthetic_value() -> Value {
    Value::Record {
        tycon: Some("Synthetic:Everything".into()),
        fields: vec![
            ("day".into(), Value::Int64(19_000)),
            ("at".into(), Value::Int64(1_700_000_000_000_000)),
            (
                "ids".into(),
                Value::List(
                    vec![
                        Value::ContractId("#1:0".into()),
                        Value::ContractId("#2:0".into()),
                    ]
                    .into(),
                ),
            ),
            (
                "note".into(),
                Value::Optional(Some(Box::new(Value::Text("hi".into())))),
            ),
            ("count".into(), Value::Int64(-7)),
            ("flag".into(), Value::Bool(true)),
            ("nothing".into(), Value::Unit),
            (
                "rate".into(),
                Value::Numeric {
                    coeff: 12_500,
                    scale: 4,
                },
            ),
        ],
    }
}

#[test]
fn synthetic_schema_round_trips_dates_lists_optionals_and_contract_ids() {
    let schema = synthetic_schema();
    let value = synthetic_value();
    let bytes = schema.encode(&value).unwrap();
    assert_eq!(schema.decode(&bytes).unwrap(), value);

    // The schema is what tells Date from Int64 on the wire: the positional encoding of the
    // same evaluator value would say Int64 and decoding it as a Date field must fail.
    let positional = value.to_lf_value().encode_to_vec();
    assert_ne!(positional, bytes);
    assert!(matches!(
        schema.decode(&positional).unwrap_err(),
        CodecError::TypeMismatch { expected, .. } if expected == "Date"
    ));
}

#[test]
fn synthetic_schema_json_covers_optional_numeric_and_missing_optional() {
    let schema = synthetic_schema();
    // Date/Timestamp have no JSON form here: stated, not guessed.
    assert!(matches!(
        schema.from_json(&json!({ "day": 1, "at": 1 })).unwrap_err(),
        CodecError::UnsupportedType { .. }
    ));

    // Everything except the Date/Timestamp pair can still be exercised on a reduced schema.
    let reduced = RecordSchema {
        tycon: "Synthetic:Reduced".into(),
        fields: schema.fields[2..].to_vec(),
    };
    let input = json!({
        "ids": ["#1:0"], "count": "-7", "flag": false, "nothing": null, "rate": "1.25"
    });
    let value = reduced.from_json(&input).unwrap();
    let Value::Record { fields, .. } = &value else {
        unreachable!()
    };
    assert_eq!(
        fields[1].1,
        Value::Optional(None),
        "absent Optional field is None"
    );
    assert_eq!(fields[2].1, Value::Int64(-7));
    assert_eq!(
        fields[5].1,
        Value::Numeric {
            coeff: 12_500,
            scale: 4
        }
    );
    let back = reduced.to_json(&value).unwrap();
    assert_eq!(back["note"], json!(null));
    assert_eq!(back["rate"], json!("1.2500"));
    assert_eq!(back["count"], json!("-7"));
    assert_eq!(
        reduced.decode(&reduced.encode(&value).unwrap()).unwrap(),
        value
    );
}

#[test]
fn date_out_of_range_and_unsupported_types_are_refused() {
    let schema = synthetic_schema();
    let mut value = synthetic_value();
    if let Value::Record { fields, .. } = &mut value {
        fields[0].1 = Value::Int64(i64::from(i32::MAX) + 1);
    }
    assert!(matches!(
        schema.encode(&value).unwrap_err(),
        CodecError::Wire(_)
    ));

    let unsupported = |ty: SurfaceType| RecordSchema {
        tycon: "Synthetic:Bad".into(),
        fields: vec![("f".into(), ty)],
    };
    // The value only needs to be plausible for the outer type: the refusal is by schema.
    let cases = [
        (
            SurfaceType::TypeCon {
                package_id: None,
                module_name: Some("M".into()),
                name: "Nested".into(),
                args: vec![],
            },
            Value::Unit,
        ),
        (
            SurfaceType::GenMap {
                key: Box::new(SurfaceType::Text),
                value: Box::new(SurfaceType::Text),
            },
            Value::Unit,
        ),
        (
            SurfaceType::Optional(Box::new(SurfaceType::Optional(Box::new(SurfaceType::Text)))),
            Value::Optional(None),
        ),
    ];
    for (ty, field_value) in cases {
        let record = Value::Record {
            tycon: None,
            fields: vec![("f".into(), field_value)],
        };
        assert!(
            matches!(
                unsupported(ty.clone()).encode(&record),
                Err(CodecError::UnsupportedType { .. })
            ),
            "{ty:?}"
        );
    }
}

#[test]
fn contract_id_bytes_that_are_not_utf8_are_rejected_on_decode() {
    let schema = RecordSchema {
        tycon: "Synthetic:Cid".into(),
        fields: vec![(
            "c".into(),
            SurfaceType::ContractId(Box::new(SurfaceType::Text)),
        )],
    };
    let bytes = lf_archive::Value::Record {
        fields: vec![lf_archive::Value::ContractId(vec![0xff, 0xfe])],
    }
    .encode_to_vec();
    assert!(matches!(
        schema.decode(&bytes).unwrap_err(),
        CodecError::InvalidContractId { .. }
    ));
}

/// U-21: a Daml tuple (a contract key, a choice argument) is a record of its values on the LF wire: no labels, no record id.
#[test]
fn a_tuple_is_a_record_of_its_values_on_the_wire_and_round_trips() {
    let schema = RecordSchema {
        tycon: "Keyed:ReadByKey".into(),
        fields: vec![(
            "wanted".into(),
            SurfaceType::Tuple(vec![SurfaceType::Party, SurfaceType::Text]),
        )],
    };
    let tuple = Value::Record {
        tycon: Some("DA.Types:Tuple2".into()),
        fields: vec![
            ("_1".into(), Value::Party("alice".into())),
            ("_2".into(), Value::Text("entry".into())),
        ],
    };
    let value = Value::Record {
        tycon: Some("Keyed:ReadByKey".into()),
        fields: vec![("wanted".into(), tuple)],
    };
    let bytes = schema.encode(&value).unwrap();
    // the same bytes as a record holding a record of the two values in order
    let expected = lf_archive::Value::Record {
        fields: vec![lf_archive::Value::Record {
            fields: vec![
                lf_archive::Value::Party("alice".into()),
                lf_archive::Value::Text("entry".into()),
            ],
        }],
    };
    assert_eq!(bytes, expected.encode_to_vec());
    let back = schema.decode(&bytes).unwrap();
    // the decoded tuple carries the labels `_1`, `_2` and the tuple type name
    assert_eq!(back, value);
    // a tuple of the wrong width is a mismatch, not a silent truncation
    let narrow = lf_archive::Value::Record {
        fields: vec![lf_archive::Value::Record {
            fields: vec![lf_archive::Value::Party("alice".into())],
        }],
    };
    assert!(schema.decode(&narrow.encode_to_vec()).is_err());
}
