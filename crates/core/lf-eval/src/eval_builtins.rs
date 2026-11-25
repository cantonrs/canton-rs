//! Daml-LF builtin function registry, arity table, and pure builtin execution.

use sha2::Digest;

use crate::{
    compare_values, crypto_secp, map_position, numeric_ops, render_numeric, time_text,
    values_equal, BigNumericValue, EvalError, Value, ADD_BIGNUMERIC, ADD_INT64, ADD_NUMERIC,
    ANY_EXCEPTION_MESSAGE, APPEND_TEXT, ARITHMETIC_ERROR, BIGNUMERIC_TO_NUMERIC,
    BIGNUMERIC_TO_TEXT, CAST_NUMERIC, CODE_POINTS_TO_TEXT, COERCE_CONTRACT_ID, CONTRACT_ID_TO_TEXT,
    DATE_TO_TEXT, DATE_TO_UNIX_DAYS, DIV_BIGNUMERIC, DIV_INT64, DIV_NUMERIC, EQUAL, EQUAL_LIST,
    ERROR, EXPLODE_TEXT, EXP_INT64, FAIL_WITH_STATUS, FOLDL, FOLDR, GENMAP_DELETE, GENMAP_EMPTY,
    GENMAP_INSERT, GENMAP_KEYS, GENMAP_LOOKUP, GENMAP_SIZE, GENMAP_VALUES, GREATER, GREATER_EQ,
    HEX_TO_TEXT, IMPLODE_TEXT, INT64_TO_NUMERIC, INT64_TO_TEXT, KECCAK256_TEXT, LESS, LESS_EQ,
    MAX_DATE_DAYS, MAX_TIMESTAMP_MICROS, MIN_DATE_DAYS, MIN_TIMESTAMP_MICROS, MOD_INT64,
    MUL_BIGNUMERIC, MUL_INT64, MUL_NUMERIC, NUMERIC_TO_BIGNUMERIC, NUMERIC_TO_INT64,
    NUMERIC_TO_TEXT, PARTY_TO_TEXT, PRECISION_BIGNUMERIC, ROUND_NUMERIC, SCALE_BIGNUMERIC,
    SCRIPT_DANGEROUS_CAST, SECP256K1_BOOL, SECP256K1_VALIDATE_KEY, SECP256K1_WITH_ECDSA_BOOL,
    SHA256_HEX, SHA256_TEXT, SHIFT_NUMERIC, SHIFT_RIGHT_BIGNUMERIC, SUB_BIGNUMERIC, SUB_INT64,
    SUB_NUMERIC, TEXTMAP_DELETE, TEXTMAP_EMPTY, TEXTMAP_INSERT, TEXTMAP_LOOKUP, TEXTMAP_SIZE,
    TEXTMAP_TO_LIST, TEXT_TO_CODE_POINTS, TEXT_TO_HEX, TEXT_TO_INT64, TEXT_TO_NUMERIC,
    TEXT_TO_PARTY, TIMESTAMP_TO_TEXT, TIMESTAMP_TO_UNIX_MICROSECONDS, TRACE, TYPE_REP_TYCON_NAME,
    UNIX_DAYS_TO_DATE, UNIX_MICROSECONDS_TO_TIMESTAMP,
};

/// Whether the evaluator implements a builtin function (the census of `splice-census` uses this).
pub fn builtin_supported(code: i32) -> bool {
    arity(code) != usize::MAX
}

/// `Expr` forms `step_expr` evaluates (besides `InternedExpr`, which is resolved first). Kept next to the match it
/// mirrors; `splice-census` compares the forms real packages use with this list.
pub const SUPPORTED_EXPR_FORMS: &[&str] = &[
    "VarInternedStr",
    "Val",
    "Builtin",
    "BuiltinCon",
    "BuiltinLit",
    "RecCon",
    "RecProj",
    "RecUpd",
    "VariantCon",
    "EnumCon",
    "StructCon",
    "StructProj",
    "StructUpd",
    "App",
    "TyApp",
    "Abs",
    "TyAbs",
    "Case",
    "Let",
    "Nil",
    "Cons",
    "Update",
    "OptionalNone",
    "OptionalSome",
    "ToAny",
    "ToAnyException",
    "FromAnyException",
    "Throw",
    "InternedExpr",
    "FromAny",
    "TypeRep",
    "InterfaceTemplateTypeRep",
    "ToInterface",
    "FromInterface",
    "UnsafeFromInterface",
    "CallInterface",
    "ViewInterface",
    "SignatoryInterface",
    "ObserverInterface",
    "ToRequiredInterface",
    "FromRequiredInterface",
    "UnsafeFromRequiredInterface",
];

/// `Update` forms `step_update` evaluates.
pub const SUPPORTED_UPDATE_FORMS: &[&str] = &[
    "Pure",
    "Block",
    "Create",
    "Exercise",
    "Fetch",
    "GetTime",
    "TryCatch",
    "EmbedExpr",
    "LedgerTimeLt",
    "CreateInterface",
    "ExerciseInterface",
    "FetchInterface",
    "ExerciseByKey",
    "FetchByKey",
    "QueryNByKey",
];

pub(crate) fn arity(builtin: i32) -> usize {
    match builtin {
        ERROR
        | INT64_TO_TEXT
        | NUMERIC_TO_TEXT
        | PARTY_TO_TEXT
        | TEXT_TO_PARTY
        | CONTRACT_ID_TO_TEXT
        | EXPLODE_TEXT
        | IMPLODE_TEXT
        | CODE_POINTS_TO_TEXT
        | TEXT_TO_CODE_POINTS
        | NUMERIC_TO_INT64
        | TEXT_TO_INT64
        | TIMESTAMP_TO_TEXT
        | DATE_TO_TEXT
        | DATE_TO_UNIX_DAYS
        | UNIX_DAYS_TO_DATE
        | TIMESTAMP_TO_UNIX_MICROSECONDS
        | UNIX_MICROSECONDS_TO_TIMESTAMP
        | SHA256_TEXT
        | SHA256_HEX
        | KECCAK256_TEXT
        | HEX_TO_TEXT
        | TEXT_TO_HEX
        | COERCE_CONTRACT_ID
        | SCRIPT_DANGEROUS_CAST
        | ANY_EXCEPTION_MESSAGE
        | SECP256K1_VALIDATE_KEY
        | TYPE_REP_TYCON_NAME
        | SCALE_BIGNUMERIC
        | PRECISION_BIGNUMERIC
        | NUMERIC_TO_BIGNUMERIC
        | BIGNUMERIC_TO_TEXT => 1,
        TRACE
        | EQUAL
        | LESS_EQ
        | LESS
        | GREATER_EQ
        | GREATER
        | ADD_INT64
        | SUB_INT64
        | MUL_INT64
        | DIV_INT64
        | MOD_INT64
        | ADD_NUMERIC
        | SUB_NUMERIC
        | APPEND_TEXT
        | EXP_INT64
        | INT64_TO_NUMERIC
        | ROUND_NUMERIC
        | CAST_NUMERIC
        | SHIFT_NUMERIC
        | TEXT_TO_NUMERIC
        | ADD_BIGNUMERIC
        | SUB_BIGNUMERIC
        | MUL_BIGNUMERIC
        | SHIFT_RIGHT_BIGNUMERIC
        | BIGNUMERIC_TO_NUMERIC => 2,
        FOLDL | FOLDR | EQUAL_LIST | MUL_NUMERIC | DIV_NUMERIC | GENMAP_INSERT | TEXTMAP_INSERT => {
            3
        }
        GENMAP_EMPTY | TEXTMAP_EMPTY => 0,
        GENMAP_LOOKUP | GENMAP_DELETE | TEXTMAP_LOOKUP | TEXTMAP_DELETE => 2,
        GENMAP_KEYS | GENMAP_VALUES | GENMAP_SIZE | TEXTMAP_TO_LIST | TEXTMAP_SIZE => 1,
        SECP256K1_BOOL | SECP256K1_WITH_ECDSA_BOOL => 3,
        FAIL_WITH_STATUS | DIV_BIGNUMERIC => 4,
        _ => usize::MAX,
    }
}

/// Decode a Daml `HexString`: lower-case hex digits in pairs (possibly none). Anything else is a Crypto error.
pub(crate) fn hex_bytes(text: &str) -> Result<Vec<u8>, EvalError> {
    if text.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(EvalError::Arithmetic(format!(
            "malformed hex string {text}"
        )));
    }
    hex::decode(text).map_err(|_| EvalError::Arithmetic(format!("malformed hex string {text}")))
}

/// [CANTON-NOTE: SEMANTICS] Speedy's `SBuiltinArithmetic` builtins (Int64 and Numeric arithmetic, `roundBankers`, `cast`,
/// conversions between them) raise the Daml exception `ArithmeticError` on overflow, division by zero or a result that
/// does not fit. It is an ordinary `AnyException`, so a Daml `try` can catch it and the command fails with the category
/// `exception` otherwise (measured on the JVM: a division of tiny Decimals in `StartIssuing`,
/// `mr_start_issuing_tiny_coupon_totals`). Other builtin failures (hex, crypto, `error`) stay plain errors.
/// [CANTON-NOTE: SEMANTICS] The message is Speedy's (`SArithmeticError`): `ArithmeticError while evaluating (<NAME>
/// <args>).`, the arguments printed by `litToText` (Int64 as a number, Numeric as its trimmed unscaled string). Like
/// Speedy, the builtins that take an output scale (`MUL_NUMERIC`, `DIV_NUMERIC`, ...) receive it as a leading Numeric
/// argument here too, so it is printed with the rest (`1.0`). Measured on JVM 3.7.2 for `ADD_INT64`, `ADD_NUMERIC` and
/// `DIV_NUMERIC`.
pub(crate) fn exec_builtin_checked(builtin: i32, args: &[Value]) -> Result<Value, EvalError> {
    match exec_builtin(builtin, args) {
        Err(EvalError::Arithmetic(_)) if is_arithmetic_builtin(builtin) => {
            let shown: Vec<String> = args.iter().filter_map(lit_to_text).collect();
            let message = format!(
                "ArithmeticError while evaluating ({} {}).",
                arithmetic_builtin_name(builtin),
                shown.join(" ")
            );
            Err(EvalError::Thrown(Box::new(Value::AnyException {
                tycon: ARITHMETIC_ERROR.to_string(),
                payload: Box::new(Value::Record {
                    tycon: Some(ARITHMETIC_ERROR.to_string()),
                    fields: vec![("message".to_string(), Value::Text(message))],
                }),
            })))
        }
        other => other,
    }
}

/// Whether a value holds a Text with a NUL character anywhere (a contract payload, a choice argument or result).
pub fn value_contains_nul(value: &Value) -> bool {
    match value {
        Value::Text(t) => t.contains('\0'),
        Value::List(items) => items.iter().any(value_contains_nul),
        Value::Optional(Some(inner)) => value_contains_nul(inner),
        Value::Record { fields, .. } => fields.iter().any(|(_, v)| value_contains_nul(v)),
        Value::Variant { value, .. } => value_contains_nul(value),
        Value::Map(entries) => entries
            .iter()
            .any(|(k, v)| value_contains_nul(k) || value_contains_nul(v)),
        _ => false,
    }
}

/// Speedy `litToText` for the argument kinds the arithmetic builtins take.
fn lit_to_text(value: &Value) -> Option<String> {
    match value {
        Value::Int64(n) => Some(n.to_string()),
        Value::Numeric { coeff, scale } => Some(numeric_text(*coeff, *scale)),
        Value::BigNumeric(bn) => Some(bn.to_unscaled_string()),
        _ => None,
    }
}

/// The text of a Numeric as Daml `show` prints it: no trailing zeros, at least one decimal digit.
fn numeric_text(coeff: i128, scale: u8) -> String {
    let s = render_numeric(coeff, scale);
    match s.split_once('.') {
        Some((whole, frac)) if frac.trim_end_matches('0').is_empty() => format!("{whole}.0"),
        Some((whole, frac)) => format!("{whole}.{}", frac.trim_end_matches('0')),
        None => format!("{s}.0"),
    }
}

fn arithmetic_builtin_name(builtin: i32) -> &'static str {
    match builtin {
        ADD_INT64 => "ADD_INT64",
        SUB_INT64 => "SUB_INT64",
        MUL_INT64 => "MUL_INT64",
        DIV_INT64 => "DIV_INT64",
        MOD_INT64 => "MOD_INT64",
        EXP_INT64 => "EXP_INT64",
        ADD_NUMERIC => "ADD_NUMERIC",
        SUB_NUMERIC => "SUB_NUMERIC",
        MUL_NUMERIC => "MUL_NUMERIC",
        DIV_NUMERIC => "DIV_NUMERIC",
        ROUND_NUMERIC => "ROUND_NUMERIC",
        CAST_NUMERIC => "CAST_NUMERIC",
        INT64_TO_NUMERIC => "INT64_TO_NUMERIC",
        NUMERIC_TO_INT64 => "NUMERIC_TO_INT64",
        ADD_BIGNUMERIC => "ADD_BIGNUMERIC",
        SUB_BIGNUMERIC => "SUB_BIGNUMERIC",
        MUL_BIGNUMERIC => "MUL_BIGNUMERIC",
        DIV_BIGNUMERIC => "DIV_BIGNUMERIC",
        SHIFT_RIGHT_BIGNUMERIC => "SHIFT_RIGHT_BIGNUMERIC",
        BIGNUMERIC_TO_NUMERIC => "BIGNUMERIC_TO_NUMERIC",
        UNIX_DAYS_TO_DATE => "UNIX_DAYS_TO_DATE",
        UNIX_MICROSECONDS_TO_TIMESTAMP => "UNIX_MICROSECONDS_TO_TIMESTAMP",
        _ => "ARITHMETIC",
    }
}

fn is_arithmetic_builtin(builtin: i32) -> bool {
    matches!(
        builtin,
        ADD_INT64
            | SUB_INT64
            | MUL_INT64
            | DIV_INT64
            | MOD_INT64
            | EXP_INT64
            | ADD_NUMERIC
            | SUB_NUMERIC
            | MUL_NUMERIC
            | DIV_NUMERIC
            | ROUND_NUMERIC
            | CAST_NUMERIC
            | INT64_TO_NUMERIC
            | NUMERIC_TO_INT64
            | ADD_BIGNUMERIC
            | SUB_BIGNUMERIC
            | MUL_BIGNUMERIC
            | DIV_BIGNUMERIC
            | SHIFT_RIGHT_BIGNUMERIC
            | BIGNUMERIC_TO_NUMERIC
            | UNIX_DAYS_TO_DATE
            | UNIX_MICROSECONDS_TO_TIMESTAMP
    )
}

pub(crate) fn exec_builtin(builtin: i32, args: &[Value]) -> Result<Value, EvalError> {
    match builtin {
        TRACE => match args {
            [_, val] => Ok(val.clone()),
            _ => Err(EvalError::unsupported()),
        },
        ERROR => match args {
            [Value::Text(msg)] => Err(EvalError::Arithmetic(msg.clone())),
            _ => Err(EvalError::unsupported()),
        },
        ADD_INT64 => int2(args, "ADD_INT64", i64::checked_add),
        SUB_INT64 => int2(args, "SUB_INT64", i64::checked_sub),
        MUL_INT64 => int2(args, "MUL_INT64", i64::checked_mul),
        DIV_INT64 => int_div(args, "DIV_INT64", |a, b| a.checked_div(b)),
        // Speedy returns 0 for `Int64.min % -1` (JVM `%` semantics); only division by zero is an error.
        MOD_INT64 => int_div(args, "MOD_INT64", |a, b| Some(a.wrapping_rem(b))),
        TIMESTAMP_TO_TEXT => match args {
            [Value::Int64(micros)] => Ok(Value::Text(time_text::timestamp_to_text(*micros))),
            _ => Err(EvalError::unsupported()),
        },
        // [CANTON-NOTE: SEMANTICS] Timestamps are Int64 microseconds and dates Int64 days since the Unix epoch in this
        // evaluator, so the "to unix" conversions are the identity and the "from unix" ones only check the range Daml
        // allows (Timestamp 0001-01-01T00:00:00Z..9999-12-31T23:59:59.999999Z, Date 0001-01-01..9999-12-31). Daml's
        // `addRelTime`/`subTime`/`addDays` are built from these, which is why the Splice `DsoRules` confirmation
        // (`now `addRelTime` timeout`) needs them.
        TIMESTAMP_TO_UNIX_MICROSECONDS | DATE_TO_UNIX_DAYS => match args {
            [Value::Int64(n)] => Ok(Value::Int64(*n)),
            _ => Err(EvalError::unsupported()),
        },
        UNIX_MICROSECONDS_TO_TIMESTAMP => match args {
            [Value::Int64(n)] if (MIN_TIMESTAMP_MICROS..=MAX_TIMESTAMP_MICROS).contains(n) => {
                Ok(Value::Int64(*n))
            }
            [Value::Int64(n)] => Err(EvalError::Arithmetic(format!(
                "timestamp out of range: {n}"
            ))),
            _ => Err(EvalError::unsupported()),
        },
        UNIX_DAYS_TO_DATE => match args {
            [Value::Int64(n)] if (MIN_DATE_DAYS..=MAX_DATE_DAYS).contains(n) => {
                Ok(Value::Int64(*n))
            }
            [Value::Int64(n)] => Err(EvalError::Arithmetic(format!("date out of range: {n}"))),
            _ => Err(EvalError::unsupported()),
        },
        // [CANTON-NOTE: SEMANTICS] Numeric builtins that change scale take a witness Numeric first (its scale is the
        // result scale), like INT64_TO_NUMERIC above. `ROUND_NUMERIC` instead takes the number of places as an Int64.
        ROUND_NUMERIC => match args {
            [Value::Int64(prec), Value::Numeric { coeff, scale }] => {
                numeric_ops::round_numeric(*prec, *coeff, *scale).map(|coeff| Value::Numeric {
                    coeff,
                    scale: *scale,
                })
            }
            _ => Err(EvalError::unsupported()),
        },
        CAST_NUMERIC => match args {
            [Value::Numeric { scale: out, .. }, Value::Numeric { coeff, scale }] => {
                numeric_ops::cast_numeric(*coeff, *scale, *out)
                    .map(|coeff| Value::Numeric { coeff, scale: *out })
            }
            _ => Err(EvalError::unsupported()),
        },
        // `shift` keeps the digits and only moves the decimal point (multiplies by 10^(in - out)), so it cannot
        // overflow.
        SHIFT_NUMERIC => match args {
            [Value::Numeric { scale: out, .. }, Value::Numeric { coeff, .. }] => {
                Ok(Value::Numeric {
                    coeff: *coeff,
                    scale: *out,
                })
            }
            _ => Err(EvalError::unsupported()),
        },
        TEXT_TO_NUMERIC => match args {
            [Value::Numeric { scale, .. }, Value::Text(text)] => Ok(Value::Optional(
                numeric_ops::text_to_numeric(text, *scale).map(|coeff| {
                    Box::new(Value::Numeric {
                        coeff,
                        scale: *scale,
                    })
                }),
            )),
            _ => Err(EvalError::unsupported()),
        },
        // Hashes return lower-case hex. `SHA256_TEXT` hashes the UTF-8 bytes of its argument, the `*_HEX` forms and
        // `KECCAK256_TEXT` hash the bytes the (lower-case, even-length) hex argument decodes to; anything else is a
        // Crypto error.
        SHA256_TEXT => match args {
            [Value::Text(t)] => Ok(Value::Text(hex::encode(sha2::Sha256::digest(t.as_bytes())))),
            _ => Err(EvalError::unsupported()),
        },
        SHA256_HEX => match args {
            [Value::Text(h)] => {
                hex_bytes(h).map(|b| Value::Text(hex::encode(sha2::Sha256::digest(b))))
            }
            _ => Err(EvalError::unsupported()),
        },
        KECCAK256_TEXT => match args {
            [Value::Text(h)] => hex_bytes(h).map(|b| {
                let mut out = [0u8; 32];
                let mut k = tiny_keccak::Keccak::v256();
                tiny_keccak::Hasher::update(&mut k, &b);
                tiny_keccak::Hasher::finalize(k, &mut out);
                Value::Text(hex::encode(out))
            }),
            _ => Err(EvalError::unsupported()),
        },
        TEXT_TO_HEX => match args {
            [Value::Text(t)] => Ok(Value::Text(hex::encode(t.as_bytes()))),
            _ => Err(EvalError::unsupported()),
        },
        HEX_TO_TEXT => match args {
            // [CANTON-NOTE: SEMANTICS] A Text with a NUL character is a normal value while it is computed (the JVM:
            // `fromHex "00"` has length 1); it is refused only where a Value leaves the evaluator for the ledger or a
            // script result (`value_contains_nul`, `EvalError::MalformedText`; measured in tests/oracle/lf-fatal).
            [Value::Text(h)] => {
                hex_bytes(h).map(|b| Value::Text(String::from_utf8_lossy(&b).into_owned()))
            }
            _ => Err(EvalError::unsupported()),
        },
        // [CANTON-NOTE: SEMANTICS] secp256k1 over DER: the signature is an ASN.1 DER ECDSA signature, the key a DER
        // SubjectPublicKeyInfo. `SECP256K1_WITH_ECDSA_BOOL` verifies the message bytes as the digest, `SECP256K1_BOOL`
        // verifies sha256(message). Hex arguments are decoded like the hash builtins above.
        SECP256K1_BOOL | SECP256K1_WITH_ECDSA_BOOL => match args {
            [Value::Text(sig), Value::Text(msg), Value::Text(key)] => {
                crypto_secp::verify(sig, msg, key, builtin == SECP256K1_BOOL).map(Value::Bool)
            }
            _ => Err(EvalError::unsupported()),
        },
        SECP256K1_VALIDATE_KEY => match args {
            [Value::Text(key)] => crypto_secp::validate_key(key).map(Value::Bool),
            _ => Err(EvalError::unsupported()),
        },
        SCRIPT_DANGEROUS_CAST => match args {
            [v] => Ok(v.clone()),
            _ => Err(EvalError::unsupported()),
        },
        // Contract ids carry no type at runtime, so coercing one is the identity.
        COERCE_CONTRACT_ID => match args {
            [v @ Value::ContractId(_)] => Ok(v.clone()),
            _ => Err(EvalError::unsupported()),
        },
        DATE_TO_TEXT => match args {
            [Value::Int64(days)] => Ok(Value::Text(time_text::date_to_text(*days))),
            _ => Err(EvalError::unsupported()),
        },
        EXP_INT64 => match args {
            [Value::Int64(base), Value::Int64(exponent)] => {
                numeric_ops::exp_int64(*base, *exponent).map(Value::Int64)
            }
            _ => Err(EvalError::unsupported()),
        },
        TEXT_TO_INT64 => match args {
            [Value::Text(text)] => Ok(Value::Optional(
                numeric_ops::text_to_int64(text).map(|n| Box::new(Value::Int64(n))),
            )),
            _ => Err(EvalError::unsupported()),
        },
        // The first argument of INT64_TO_NUMERIC, MUL_NUMERIC and DIV_NUMERIC is a witness Numeric whose scale
        // is the scale of the result (daml-lf-2.rst: "The first argument is used as a witness for the scale").
        INT64_TO_NUMERIC => match args {
            [Value::Numeric { scale, .. }, Value::Int64(x)] => {
                numeric_ops::int64_to_numeric(*x, *scale).map(|coeff| Value::Numeric {
                    coeff,
                    scale: *scale,
                })
            }
            _ => Err(EvalError::unsupported()),
        },
        NUMERIC_TO_INT64 => match args {
            [Value::Numeric { coeff, scale }] => {
                numeric_ops::numeric_to_int64(*coeff, *scale).map(Value::Int64)
            }
            _ => Err(EvalError::unsupported()),
        },
        MUL_NUMERIC | DIV_NUMERIC => match args {
            [Value::Numeric { scale: s3, .. }, Value::Numeric {
                coeff: a,
                scale: s1,
            }, Value::Numeric {
                coeff: b,
                scale: s2,
            }] => {
                let op = if builtin == MUL_NUMERIC {
                    numeric_ops::mul_numeric
                } else {
                    numeric_ops::div_numeric
                };
                op(*a, *s1, *b, *s2, *s3).map(|coeff| Value::Numeric { coeff, scale: *s3 })
            }
            _ => Err(EvalError::unsupported()),
        },
        ADD_NUMERIC => num2(args, |a, b| a.checked_add(b), "ADD_NUMERIC"),
        SUB_NUMERIC => num2(args, |a, b| a.checked_sub(b), "SUB_NUMERIC"),
        INT64_TO_TEXT => match args {
            [Value::Int64(n)] => Ok(Value::Text(n.to_string())),
            _ => Err(EvalError::unsupported()),
        },
        NUMERIC_TO_TEXT => match args {
            [Value::Numeric { coeff, scale }] => Ok(Value::Text(numeric_text(*coeff, *scale))),
            _ => Err(EvalError::unsupported()),
        },
        PARTY_TO_TEXT => match args {
            [Value::Party(p)] => Ok(Value::Text(p.clone())),
            _ => Err(EvalError::unsupported()),
        },
        TEXT_TO_PARTY => match args {
            [Value::Text(s)] => Ok(Value::Optional(
                is_party_id(s).then(|| Box::new(Value::Party(s.clone()))),
            )),
            _ => Err(EvalError::unsupported()),
        },
        CONTRACT_ID_TO_TEXT => match args {
            [Value::ContractId(cid)] => {
                Ok(Value::Optional(Some(Box::new(Value::Text(cid.clone())))))
            }
            _ => Err(EvalError::unsupported()),
        },
        EXPLODE_TEXT => match args {
            [Value::Text(s)] => Ok(Value::List(
                s.chars().map(|c| Value::Text(c.to_string())).collect(),
            )),
            _ => Err(EvalError::unsupported()),
        },
        APPEND_TEXT => match args {
            [Value::Text(left), Value::Text(right)] => Ok(Value::Text(format!("{left}{right}"))),
            _ => Err(EvalError::unsupported()),
        },
        IMPLODE_TEXT => match args {
            [Value::List(items)] => {
                let mut out = String::new();
                for item in items {
                    match item {
                        Value::Text(s) => out.push_str(s),
                        _ => return Err(EvalError::unsupported()),
                    }
                }
                Ok(Value::Text(out))
            }
            _ => Err(EvalError::unsupported()),
        },
        TEXT_TO_CODE_POINTS => match args {
            [Value::Text(s)] => Ok(Value::List(
                s.chars().map(|c| Value::Int64(c as u32 as i64)).collect(),
            )),
            _ => Err(EvalError::unsupported()),
        },
        CODE_POINTS_TO_TEXT => match args {
            [Value::List(items)] => {
                let mut out = String::with_capacity(items.len());
                for item in items {
                    match item {
                        Value::Int64(cp) => {
                            // Speedy `Utf8.pack`: surrogates and values outside 0..=0x10FFFF crash, the code point
                            // printed as Java's `Long.toHexString` (two's complement for a negative one).
                            let ch = u32::try_from(*cp)
                                .ok()
                                .and_then(char::from_u32)
                                .ok_or_else(|| {
                                    EvalError::Crash(format!(
                                        "invalid code point {:#x}.",
                                        *cp as u64
                                    ))
                                })?;
                            out.push(ch);
                        }
                        _ => return Err(EvalError::unsupported()),
                    }
                }
                Ok(Value::Text(out))
            }
            _ => Err(EvalError::unsupported()),
        },
        FAIL_WITH_STATUS => match args {
            [Value::Text(error_id), _, Value::Text(message), _] => {
                Err(EvalError::UnhandledException {
                    error_id: error_id.clone(),
                    message: message.clone(),
                })
            }
            _ => Err(EvalError::unsupported()),
        },
        GENMAP_EMPTY | TEXTMAP_EMPTY => Ok(Value::Map(Vec::new())),
        GENMAP_INSERT | TEXTMAP_INSERT => match args {
            [key, value, Value::Map(entries)] => {
                if builtin == TEXTMAP_INSERT && !matches!(key, Value::Text(_)) {
                    return Err(EvalError::unsupported());
                }
                let mut entries = entries.clone();
                match map_position(&entries, key)? {
                    Ok(i) => entries[i].1 = value.clone(),
                    Err(i) => entries.insert(i, (key.clone(), value.clone())),
                }
                Ok(Value::Map(entries))
            }
            _ => Err(EvalError::unsupported()),
        },
        GENMAP_LOOKUP | TEXTMAP_LOOKUP => match args {
            [key, Value::Map(entries)] => Ok(Value::Optional(
                map_position(entries, key)?
                    .ok()
                    .map(|i| Box::new(entries[i].1.clone())),
            )),
            _ => Err(EvalError::unsupported()),
        },
        GENMAP_DELETE | TEXTMAP_DELETE => match args {
            [key, Value::Map(entries)] => {
                let mut entries = entries.clone();
                if let Ok(i) = map_position(&entries, key)? {
                    entries.remove(i);
                }
                Ok(Value::Map(entries))
            }
            _ => Err(EvalError::unsupported()),
        },
        GENMAP_KEYS => match args {
            [Value::Map(entries)] => Ok(Value::List(
                entries.iter().map(|(k, _)| k.clone()).collect(),
            )),
            _ => Err(EvalError::unsupported()),
        },
        GENMAP_VALUES => match args {
            [Value::Map(entries)] => Ok(Value::List(
                entries.iter().map(|(_, v)| v.clone()).collect(),
            )),
            _ => Err(EvalError::unsupported()),
        },
        GENMAP_SIZE | TEXTMAP_SIZE => match args {
            [Value::Map(entries)] => Ok(Value::Int64(entries.len() as i64)),
            _ => Err(EvalError::unsupported()),
        },
        TEXTMAP_TO_LIST => match args {
            [Value::Map(entries)] => Ok(Value::List(
                entries
                    .iter()
                    .map(|(k, v)| {
                        Value::Struct(vec![
                            ("key".to_string(), k.clone()),
                            ("value".to_string(), v.clone()),
                        ])
                    })
                    .collect(),
            )),
            _ => Err(EvalError::unsupported()),
        },
        EQUAL => match args {
            [a, b] => Ok(Value::Bool(values_equal(a, b)?)),
            _ => Err(EvalError::unsupported()),
        },
        LESS => cmp(args, |ord| ord.is_lt()),
        LESS_EQ => cmp(args, |ord| ord.is_le()),
        GREATER => cmp(args, |ord| ord.is_gt()),
        GREATER_EQ => cmp(args, |ord| ord.is_ge()),
        TYPE_REP_TYCON_NAME => match args {
            [Value::TypeRep { tycon, .. }] => Ok(Value::Optional(
                tycon.clone().map(|s| Box::new(Value::Text(s))),
            )),
            _ => Err(EvalError::unsupported()),
        },
        SCALE_BIGNUMERIC => match args {
            [Value::BigNumeric(bn)] => Ok(Value::Int64(bn.scale())),
            _ => Err(EvalError::unsupported()),
        },
        PRECISION_BIGNUMERIC => match args {
            [Value::BigNumeric(bn)] => Ok(Value::Int64(bn.precision())),
            _ => Err(EvalError::unsupported()),
        },
        ADD_BIGNUMERIC => match args {
            [Value::BigNumeric(x), Value::BigNumeric(y)] => Ok(Value::BigNumeric(x.add(y)?)),
            _ => Err(EvalError::unsupported()),
        },
        SUB_BIGNUMERIC => match args {
            [Value::BigNumeric(x), Value::BigNumeric(y)] => Ok(Value::BigNumeric(x.sub(y)?)),
            _ => Err(EvalError::unsupported()),
        },
        MUL_BIGNUMERIC => match args {
            [Value::BigNumeric(x), Value::BigNumeric(y)] => Ok(Value::BigNumeric(x.mul(y)?)),
            _ => Err(EvalError::unsupported()),
        },
        DIV_BIGNUMERIC => match args {
            [Value::Int64(scale), Value::Int64(rm), Value::BigNumeric(x), Value::BigNumeric(y)] => {
                Ok(Value::BigNumeric(x.div(y, *scale, *rm)?))
            }
            _ => Err(EvalError::unsupported()),
        },
        SHIFT_RIGHT_BIGNUMERIC => match args {
            [Value::Int64(shifting), Value::BigNumeric(x)] => {
                Ok(Value::BigNumeric(x.shift_right(*shifting)?))
            }
            _ => Err(EvalError::unsupported()),
        },
        BIGNUMERIC_TO_NUMERIC => match args {
            [Value::Numeric { scale, .. }, Value::BigNumeric(x)] => Ok(Value::Numeric {
                coeff: x.to_numeric(*scale)?,
                scale: *scale,
            }),
            _ => Err(EvalError::unsupported()),
        },
        NUMERIC_TO_BIGNUMERIC => match args {
            [Value::Numeric { coeff, scale }] => Ok(Value::BigNumeric(
                BigNumericValue::from_numeric(*coeff, *scale)?,
            )),
            _ => Err(EvalError::unsupported()),
        },
        BIGNUMERIC_TO_TEXT => match args {
            [Value::BigNumeric(x)] => Ok(Value::Text(x.to_unscaled_string())),
            _ => Err(EvalError::unsupported()),
        },
        _ => Err(EvalError::unsupported()),
    }
}

fn int2(args: &[Value], name: &str, op: fn(i64, i64) -> Option<i64>) -> Result<Value, EvalError> {
    match args {
        [Value::Int64(left), Value::Int64(right)] => op(*left, *right)
            .map(Value::Int64)
            .ok_or_else(|| EvalError::Arithmetic(format!("{name} {left} {right}"))),
        _ => Err(EvalError::unsupported()),
    }
}

fn int_div(
    args: &[Value],
    name: &str,
    op: fn(i64, i64) -> Option<i64>,
) -> Result<Value, EvalError> {
    match args {
        [Value::Int64(left), Value::Int64(0)] => {
            Err(EvalError::Arithmetic(format!("{name} {left} 0")))
        }
        [Value::Int64(left), Value::Int64(right)] => op(*left, *right)
            .map(Value::Int64)
            .ok_or_else(|| EvalError::Arithmetic(format!("{name} {left} {right}"))),
        _ => Err(EvalError::unsupported()),
    }
}

use crate::numeric_ops::NUMERIC_BOUND;

/// Daml-LF 2 `PartyIdString`: `[a-zA-Z0-9:\-_ ]{1,255}` (daml-lf-2.rst, "PartyId strings").
fn is_party_id(text: &str) -> bool {
    (1..=255).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'_' | b' '))
}

fn num2(
    args: &[Value],
    op: fn(i128, i128) -> Option<i128>,
    name: &str,
) -> Result<Value, EvalError> {
    match args {
        [Value::Numeric {
            coeff: left,
            scale: left_scale,
        }, Value::Numeric {
            coeff: right,
            scale: right_scale,
        }] if left_scale == right_scale => op(*left, *right)
            // Numeric has at most 38 significant digits (Speedy `Numeric.checkedAdd/Subtract`).
            .filter(|coeff| coeff.unsigned_abs() < NUMERIC_BOUND)
            .map(|coeff| Value::Numeric {
                coeff,
                scale: *left_scale,
            })
            .ok_or_else(|| EvalError::Arithmetic(name.to_string())),
        _ => Err(EvalError::unsupported()),
    }
}

fn cmp(args: &[Value], pred: fn(std::cmp::Ordering) -> bool) -> Result<Value, EvalError> {
    match args {
        [left, right] => Ok(Value::Bool(pred(compare_values(left, right)?))),
        _ => Err(EvalError::unsupported()),
    }
}
