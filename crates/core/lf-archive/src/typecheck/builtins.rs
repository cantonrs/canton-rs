//! Kinds and types of the builtin type constructors and builtin functions.

use std::collections::BTreeMap;

use crate::proto::daml_lf_2::{BuiltinFunction, BuiltinType};

use super::types::{LKind, LType};

pub(super) fn kind_of_builtin(bt: BuiltinType) -> LKind {
    match bt {
        BuiltinType::Int64
        | BuiltinType::Text
        | BuiltinType::Timestamp
        | BuiltinType::Party
        | BuiltinType::Bool
        | BuiltinType::Date
        | BuiltinType::Unit
        | BuiltinType::Any
        | BuiltinType::TypeRep
        | BuiltinType::AnyException
        | BuiltinType::RoundingMode
        | BuiltinType::Bignumeric
        | BuiltinType::FailureCategory => LKind::Star,
        BuiltinType::Numeric => LKind::k_arrow(LKind::Nat, LKind::Star),
        BuiltinType::List
        | BuiltinType::Update
        | BuiltinType::ContractId
        | BuiltinType::Optional
        | BuiltinType::Textmap => LKind::k_arrow(LKind::Star, LKind::Star),
        BuiltinType::Arrow | BuiltinType::Genmap => {
            LKind::k_arrow(LKind::Star, LKind::k_arrow(LKind::Star, LKind::Star))
        }
    }
}

pub(super) fn type_of_builtin_fn(bf: BuiltinFunction) -> LType {
    let alpha = || LType::Var("$alpha$".to_string());
    let beta = || LType::Var("$beta$".to_string());
    let gamma = || LType::Var("$gamma$".to_string());
    let forall_star = |name: &str, body: LType| LType::Forall {
        param: name.to_string(),
        kind: LKind::Star,
        body: Box::new(body),
    };
    let forall_nat = |name: &str, body: LType| LType::Forall {
        param: name.to_string(),
        kind: LKind::Nat,
        body: Box::new(body),
    };
    let binop = |t: LType| LType::arrow(t.clone(), LType::arrow(t.clone(), t));
    let text_pair_struct = || {
        let mut fields = BTreeMap::new();
        fields.insert("key".to_string(), LType::t_text());
        fields.insert("value".to_string(), alpha());
        LType::Struct(fields)
    };

    match bf {
        BuiltinFunction::Trace => forall_star(
            "$alpha$",
            LType::arrow(LType::t_text(), LType::arrow(alpha(), alpha())),
        ),
        BuiltinFunction::Error => forall_star("$alpha$", LType::arrow(LType::t_text(), alpha())),
        BuiltinFunction::Equal
        | BuiltinFunction::LessEq
        | BuiltinFunction::Less
        | BuiltinFunction::GreaterEq
        | BuiltinFunction::Greater => forall_star(
            "$alpha$",
            LType::arrow(alpha(), LType::arrow(alpha(), LType::t_bool())),
        ),
        BuiltinFunction::EqualList => forall_star(
            "$alpha$",
            LType::arrow(
                LType::arrow(alpha(), LType::arrow(alpha(), LType::t_bool())),
                LType::arrow(
                    LType::t_list(alpha()),
                    LType::arrow(LType::t_list(alpha()), LType::t_bool()),
                ),
            ),
        ),
        BuiltinFunction::AddInt64
        | BuiltinFunction::SubInt64
        | BuiltinFunction::MulInt64
        | BuiltinFunction::DivInt64
        | BuiltinFunction::ModInt64
        | BuiltinFunction::ExpInt64 => binop(LType::t_int64()),
        BuiltinFunction::AddNumeric | BuiltinFunction::SubNumeric => {
            forall_nat("$alpha$", binop(LType::t_numeric(alpha())))
        }
        BuiltinFunction::MulNumeric | BuiltinFunction::DivNumeric => forall_nat(
            "$alpha$",
            forall_nat(
                "$beta$",
                forall_nat(
                    "$gamma$",
                    LType::arrow(
                        LType::t_numeric(gamma()),
                        LType::arrow(
                            LType::t_numeric(alpha()),
                            LType::arrow(LType::t_numeric(beta()), LType::t_numeric(gamma())),
                        ),
                    ),
                ),
            ),
        ),
        BuiltinFunction::RoundNumeric => forall_nat(
            "$alpha$",
            LType::arrow(
                LType::t_int64(),
                LType::arrow(LType::t_numeric(alpha()), LType::t_numeric(alpha())),
            ),
        ),
        BuiltinFunction::CastNumeric | BuiltinFunction::ShiftNumeric => forall_nat(
            "$alpha$",
            forall_nat(
                "$beta$",
                LType::arrow(
                    LType::t_numeric(beta()),
                    LType::arrow(LType::t_numeric(alpha()), LType::t_numeric(beta())),
                ),
            ),
        ),
        BuiltinFunction::Int64ToNumeric => forall_nat(
            "$alpha$",
            LType::arrow(
                LType::t_numeric(alpha()),
                LType::arrow(LType::t_int64(), LType::t_numeric(alpha())),
            ),
        ),
        BuiltinFunction::NumericToInt64 => forall_nat(
            "$alpha$",
            LType::arrow(LType::t_numeric(alpha()), LType::t_int64()),
        ),
        BuiltinFunction::Int64ToText => LType::arrow(LType::t_int64(), LType::t_text()),
        BuiltinFunction::NumericToText => forall_nat(
            "$alpha$",
            LType::arrow(LType::t_numeric(alpha()), LType::t_text()),
        ),
        BuiltinFunction::TimestampToText => LType::arrow(LType::t_timestamp(), LType::t_text()),
        BuiltinFunction::DateToText => LType::arrow(LType::t_date(), LType::t_text()),
        BuiltinFunction::PartyToText => LType::arrow(LType::t_party(), LType::t_text()),
        BuiltinFunction::TextToParty => {
            LType::arrow(LType::t_text(), LType::t_optional(LType::t_party()))
        }
        BuiltinFunction::TextToInt64 => {
            LType::arrow(LType::t_text(), LType::t_optional(LType::t_int64()))
        }
        BuiltinFunction::TextToNumeric => forall_nat(
            "$alpha$",
            LType::arrow(
                LType::t_numeric(alpha()),
                LType::arrow(
                    LType::t_text(),
                    LType::t_optional(LType::t_numeric(alpha())),
                ),
            ),
        ),
        BuiltinFunction::ContractIdToText => forall_star(
            "$alpha$",
            LType::arrow(
                LType::t_contract_id(alpha()),
                LType::t_optional(LType::t_text()),
            ),
        ),
        BuiltinFunction::Sha256Text
        | BuiltinFunction::Sha256Hex
        | BuiltinFunction::Keccak256Text
        | BuiltinFunction::HexToText
        | BuiltinFunction::TextToHex => LType::arrow(LType::t_text(), LType::t_text()),
        BuiltinFunction::ExplodeText => {
            LType::arrow(LType::t_text(), LType::t_list(LType::t_text()))
        }
        BuiltinFunction::AppendText => binop(LType::t_text()),
        BuiltinFunction::ImplodeText => {
            LType::arrow(LType::t_list(LType::t_text()), LType::t_text())
        }
        BuiltinFunction::CodePointsToText => {
            LType::arrow(LType::t_list(LType::t_int64()), LType::t_text())
        }
        BuiltinFunction::TextToCodePoints => {
            LType::arrow(LType::t_text(), LType::t_list(LType::t_int64()))
        }
        BuiltinFunction::DateToUnixDays => LType::arrow(LType::t_date(), LType::t_int64()),
        BuiltinFunction::UnixDaysToDate => LType::arrow(LType::t_int64(), LType::t_date()),
        BuiltinFunction::TimestampToUnixMicroseconds => {
            LType::arrow(LType::t_timestamp(), LType::t_int64())
        }
        BuiltinFunction::UnixMicrosecondsToTimestamp => {
            LType::arrow(LType::t_int64(), LType::t_timestamp())
        }
        BuiltinFunction::CoerceContractId => forall_star(
            "$alpha$",
            forall_star(
                "$beta$",
                LType::arrow(LType::t_contract_id(alpha()), LType::t_contract_id(beta())),
            ),
        ),
        BuiltinFunction::Foldl => forall_star(
            "$alpha$",
            forall_star(
                "$beta$",
                LType::arrow(
                    LType::arrow(beta(), LType::arrow(alpha(), beta())),
                    LType::arrow(beta(), LType::arrow(LType::t_list(alpha()), beta())),
                ),
            ),
        ),
        BuiltinFunction::Foldr => forall_star(
            "$alpha$",
            forall_star(
                "$beta$",
                LType::arrow(
                    LType::arrow(alpha(), LType::arrow(beta(), beta())),
                    LType::arrow(beta(), LType::arrow(LType::t_list(alpha()), beta())),
                ),
            ),
        ),
        BuiltinFunction::GenmapEmpty => forall_star(
            "$alpha$",
            forall_star("$beta$", LType::t_genmap(alpha(), beta())),
        ),
        BuiltinFunction::GenmapInsert => forall_star(
            "$alpha$",
            forall_star(
                "$beta$",
                LType::arrow(
                    alpha(),
                    LType::arrow(
                        beta(),
                        LType::arrow(
                            LType::t_genmap(alpha(), beta()),
                            LType::t_genmap(alpha(), beta()),
                        ),
                    ),
                ),
            ),
        ),
        BuiltinFunction::GenmapLookup => forall_star(
            "$alpha$",
            forall_star(
                "$beta$",
                LType::arrow(
                    alpha(),
                    LType::arrow(LType::t_genmap(alpha(), beta()), LType::t_optional(beta())),
                ),
            ),
        ),
        BuiltinFunction::GenmapDelete => forall_star(
            "$alpha$",
            forall_star(
                "$beta$",
                LType::arrow(
                    alpha(),
                    LType::arrow(
                        LType::t_genmap(alpha(), beta()),
                        LType::t_genmap(alpha(), beta()),
                    ),
                ),
            ),
        ),
        BuiltinFunction::GenmapKeys => forall_star(
            "$alpha$",
            forall_star(
                "$beta$",
                LType::arrow(LType::t_genmap(alpha(), beta()), LType::t_list(alpha())),
            ),
        ),
        BuiltinFunction::GenmapValues => forall_star(
            "$alpha$",
            forall_star(
                "$beta$",
                LType::arrow(LType::t_genmap(alpha(), beta()), LType::t_list(beta())),
            ),
        ),
        BuiltinFunction::GenmapSize => forall_star(
            "$alpha$",
            forall_star(
                "$beta$",
                LType::arrow(LType::t_genmap(alpha(), beta()), LType::t_int64()),
            ),
        ),
        BuiltinFunction::TextmapEmpty => forall_star("$alpha$", LType::t_textmap(alpha())),
        BuiltinFunction::TextmapInsert => forall_star(
            "$alpha$",
            LType::arrow(
                LType::t_text(),
                LType::arrow(
                    alpha(),
                    LType::arrow(LType::t_textmap(alpha()), LType::t_textmap(alpha())),
                ),
            ),
        ),
        BuiltinFunction::TextmapLookup => forall_star(
            "$alpha$",
            LType::arrow(
                LType::t_text(),
                LType::arrow(LType::t_textmap(alpha()), LType::t_optional(alpha())),
            ),
        ),
        BuiltinFunction::TextmapDelete => forall_star(
            "$alpha$",
            LType::arrow(
                LType::t_text(),
                LType::arrow(LType::t_textmap(alpha()), LType::t_textmap(alpha())),
            ),
        ),
        BuiltinFunction::TextmapToList => forall_star(
            "$alpha$",
            LType::arrow(LType::t_textmap(alpha()), LType::t_list(text_pair_struct())),
        ),
        BuiltinFunction::TextmapSize => forall_star(
            "$alpha$",
            LType::arrow(LType::t_textmap(alpha()), LType::t_int64()),
        ),
        BuiltinFunction::AnyExceptionMessage => {
            LType::arrow(LType::t_any_exception(), LType::t_text())
        }
        BuiltinFunction::FailWithStatus => forall_star(
            "$alpha$",
            LType::arrow(
                LType::t_text(),
                LType::arrow(
                    LType::t_failure_category(),
                    LType::arrow(
                        LType::t_text(),
                        LType::arrow(LType::t_textmap(LType::t_text()), alpha()),
                    ),
                ),
            ),
        ),
        BuiltinFunction::Secp256k1Bool | BuiltinFunction::Secp256k1WithEcdsaBool => LType::arrow(
            LType::t_text(),
            LType::arrow(
                LType::t_text(),
                LType::arrow(LType::t_text(), LType::t_bool()),
            ),
        ),
        BuiltinFunction::Secp256k1ValidateKey => LType::arrow(LType::t_text(), LType::t_bool()),
        BuiltinFunction::ExternalCall | BuiltinFunction::ExternalCallLegacyDev => LType::arrow(
            LType::t_text(),
            LType::arrow(
                LType::t_text(),
                LType::arrow(
                    LType::t_text(),
                    LType::arrow(LType::t_text(), LType::t_update(LType::t_text())),
                ),
            ),
        ),
        BuiltinFunction::ScaleBignumeric | BuiltinFunction::PrecisionBignumeric => {
            LType::arrow(LType::t_bignumeric(), LType::t_int64())
        }
        BuiltinFunction::AddBignumeric
        | BuiltinFunction::SubBignumeric
        | BuiltinFunction::MulBignumeric => binop(LType::t_bignumeric()),
        BuiltinFunction::DivBignumeric => LType::arrow(
            LType::t_int64(),
            LType::arrow(
                LType::t_rounding_mode(),
                LType::arrow(
                    LType::t_bignumeric(),
                    LType::arrow(LType::t_bignumeric(), LType::t_bignumeric()),
                ),
            ),
        ),
        BuiltinFunction::ShiftRightBignumeric => LType::arrow(
            LType::t_int64(),
            LType::arrow(LType::t_bignumeric(), LType::t_bignumeric()),
        ),
        BuiltinFunction::BignumericToNumeric => forall_nat(
            "$alpha$",
            LType::arrow(
                LType::t_numeric(alpha()),
                LType::arrow(LType::t_bignumeric(), LType::t_numeric(alpha())),
            ),
        ),
        BuiltinFunction::NumericToBignumeric => forall_nat(
            "$alpha$",
            LType::arrow(LType::t_numeric(alpha()), LType::t_bignumeric()),
        ),
        BuiltinFunction::BignumericToText => LType::arrow(LType::t_bignumeric(), LType::t_text()),
        BuiltinFunction::TypeRepTyconName => {
            LType::arrow(LType::t_typerep(), LType::t_optional(LType::t_text()))
        }
    }
}

pub(super) fn minor_rank(ver: &str) -> Option<u32> {
    let minor = ver.strip_prefix("2.").unwrap_or(ver);
    if minor == "dev" {
        Some(1_000_000)
    } else {
        minor.parse::<u32>().ok()
    }
}
