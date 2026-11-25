//! S-LF-003: builtins that need exact arithmetic wider than `i128` or a type argument: `MUL_NUMERIC`,
//! `DIV_NUMERIC`, `INT64_TO_NUMERIC`, `NUMERIC_TO_INT64`, plus `EXP_INT64` and `TEXT_TO_INT64`.
//!
//! The expected behaviour is what the JVM 3.7.2 (Speedy through `daml script`) returned in the differential
//! `tests/oracle/lf-diff/`, not what this code derives: a Numeric has at most 38 digits, products and quotients
//! round half-even to the result scale, and out-of-range results are errors. Intermediate products can exceed
//! `i128` while the rounded result still fits, so the multiplication and division use `BigInt`.
use num_bigint::BigInt;

use crate::EvalError;

/// 10^38: an unscaled Numeric value must stay strictly below it in absolute value.
pub(crate) const NUMERIC_BOUND: u128 = 10u128.pow(38);

fn err(name: &str) -> EvalError {
    EvalError::Arithmetic(name.to_string())
}

fn pow10(n: u32) -> BigInt {
    BigInt::from(10).pow(n)
}

/// `numerator / denominator` rounded half-even (Java `BigDecimal.setScale(_, HALF_EVEN)`).
fn div_half_even(numerator: BigInt, denominator: BigInt) -> BigInt {
    let zero = BigInt::from(0);
    let (n, d) = if denominator < zero {
        (-numerator, -denominator)
    } else {
        (numerator, denominator)
    };
    let q = &n / &d; // truncates toward zero
    let r = &n % &d; // has the sign of n
    if r == zero {
        return q;
    }
    let twice = if r < zero { -&r } else { r } * 2;
    let step = if n < zero {
        BigInt::from(-1)
    } else {
        BigInt::from(1)
    };
    let odd = &q % 2 != zero;
    if twice > d || (twice == d && odd) {
        q + step
    } else {
        q
    }
}

fn to_numeric(value: BigInt, name: &str) -> Result<i128, EvalError> {
    let coeff = i128::try_from(&value).map_err(|_| err(name))?;
    if coeff.unsigned_abs() < NUMERIC_BOUND {
        Ok(coeff)
    } else {
        Err(err(name))
    }
}

/// `MUL_NUMERIC @s1 @s2 @s3`: exact product at scale `s1 + s2`, rounded half-even to `s3`.
pub(crate) fn mul_numeric(a: i128, s1: u8, b: i128, s2: u8, s3: u8) -> Result<i128, EvalError> {
    let product = BigInt::from(a) * BigInt::from(b);
    let from = u32::from(s1) + u32::from(s2);
    let to = u32::from(s3);
    let value = if from >= to {
        div_half_even(product, pow10(from - to))
    } else {
        product * pow10(to - from)
    };
    to_numeric(value, "MUL_NUMERIC")
}

/// `DIV_NUMERIC @s1 @s2 @s3`: the quotient rounded half-even to `s3`; division by zero is an error.
pub(crate) fn div_numeric(a: i128, s1: u8, b: i128, s2: u8, s3: u8) -> Result<i128, EvalError> {
    if b == 0 {
        return Err(err("DIV_NUMERIC"));
    }
    let shift = i64::from(s3) + i64::from(s2) - i64::from(s1);
    let (n, d) = if shift >= 0 {
        (BigInt::from(a) * pow10(shift as u32), BigInt::from(b))
    } else {
        (BigInt::from(a), BigInt::from(b) * pow10((-shift) as u32))
    };
    to_numeric(div_half_even(n, d), "DIV_NUMERIC")
}

/// `INT64_TO_NUMERIC @s`: `x * 10^s`, an error when it needs more than 38 digits.
pub(crate) fn int64_to_numeric(x: i64, scale: u8) -> Result<i128, EvalError> {
    to_numeric(
        BigInt::from(x) * pow10(u32::from(scale)),
        "INT64_TO_NUMERIC",
    )
}

/// `NUMERIC_TO_INT64`: the integer part (truncation toward zero), an error outside the Int64 range.
pub(crate) fn numeric_to_int64(coeff: i128, scale: u8) -> Result<i64, EvalError> {
    let divisor = 10i128
        .checked_pow(u32::from(scale))
        .ok_or_else(|| err("NUMERIC_TO_INT64"))?;
    i64::try_from(coeff / divisor).map_err(|_| err("NUMERIC_TO_INT64"))
}

/// `EXP_INT64`: `base ^ exponent`; a negative exponent or an overflow is an error.
pub(crate) fn exp_int64(base: i64, exponent: i64) -> Result<i64, EvalError> {
    if exponent < 0 {
        return Err(err("EXP_INT64"));
    }
    match base {
        0 => Ok(if exponent == 0 { 1 } else { 0 }),
        1 => Ok(1),
        -1 => Ok(if exponent % 2 == 0 { 1 } else { -1 }),
        _ => {
            let e = u32::try_from(exponent).map_err(|_| err("EXP_INT64"))?;
            base.checked_pow(e).ok_or_else(|| err("EXP_INT64"))
        }
    }
}

/// `TEXT_TO_INT64`: an optional sign and ASCII digits only, within the Int64 range.
pub(crate) fn text_to_int64(text: &str) -> Option<i64> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<i64>().ok()
}

/// Daml's `Numeric.maxPrecision`: a Numeric has at most this many digits.
const MAX_PRECISION_DIGITS: i64 = 38;

/// `ROUND_NUMERIC prec x`: round `x` half-even to `prec` decimal places, keeping the scale of `x` (`roundBankers`).
/// [CANTON-NOTE: SEMANTICS] A `prec` beyond the scale, or at or below `scale - 38` (rounding to the whole 38-digit
/// range or more), is an error, and so is a result over 38 digits; a negative `prec` rounds to tens, hundreds, ...
/// (bounds measured on the JVM, tests/oracle/lf-diff ops `roundBankers*`).
pub(crate) fn round_numeric(prec: i64, coeff: i128, scale: u8) -> Result<i128, EvalError> {
    if prec > i64::from(scale) || prec <= i64::from(scale) - MAX_PRECISION_DIGITS {
        return Err(err("ROUND_NUMERIC"));
    }
    let drop = i64::from(scale) - prec;
    if drop > 40 {
        // |coeff| < 10^38 is below half of 10^39, so every such value rounds to zero
        return Ok(0);
    }
    let unit = pow10(drop as u32);
    let q = div_half_even(BigInt::from(coeff), unit.clone());
    to_numeric(q * unit, "ROUND_NUMERIC")
}

/// `CAST_NUMERIC @in @out x`: the same value at another scale; an error when digits would be lost or the result
/// needs more than 38 digits (`DA.Numeric.cast`).
pub(crate) fn cast_numeric(coeff: i128, s_in: u8, s_out: u8) -> Result<i128, EvalError> {
    if s_out >= s_in {
        let widened = BigInt::from(coeff) * pow10(u32::from(s_out - s_in));
        return to_numeric(widened, "CAST_NUMERIC");
    }
    let unit = pow10(u32::from(s_in - s_out));
    let value = BigInt::from(coeff);
    if &value % &unit != BigInt::from(0) {
        return Err(err("CAST_NUMERIC"));
    }
    to_numeric(value / unit, "CAST_NUMERIC")
}

/// `TEXT_TO_NUMERIC @scale text` (`parseNumeric`): `[+-]?digits(.digits)?` with any number of leading zeros and
/// trailing fraction zeros, as long as the value fits `scale` fraction digits and 38 digits in total.
/// A missing digit before or after the point, whitespace or non-ASCII digits give `None`.
pub(crate) fn text_to_numeric(text: &str, scale: u8) -> Option<i128> {
    let (negative, body) = match text.strip_prefix(['+', '-']) {
        Some(rest) => (text.starts_with('-'), rest),
        None => (false, text),
    };
    let (int_part, frac_part) = match body.split_once('.') {
        Some((i, f)) => (i, f),
        None => (body, ""),
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(int_part) || (body.contains('.') && !digits(frac_part)) {
        return None;
    }
    let int_sig = int_part.trim_start_matches('0');
    let frac_sig = frac_part.trim_end_matches('0');
    if int_sig.len() > 38usize.saturating_sub(usize::from(scale))
        || frac_sig.len() > usize::from(scale)
    {
        return None;
    }
    let mut digits_str = String::from(int_sig);
    digits_str.push_str(frac_sig);
    digits_str.push_str(&"0".repeat(usize::from(scale) - frac_sig.len()));
    let coeff: i128 = if digits_str.is_empty() {
        0
    } else {
        digits_str.parse().ok()?
    };
    Some(if negative { -coeff } else { coeff })
}

#[cfg(test)]
mod tests {
    //! The expected values are JVM 3.7.2 answers from the differential (`tests/oracle/lf-diff/`), not derived here.
    use super::*;

    #[test]
    fn mul_rounds_half_even_to_the_result_scale() {
        // Numeric 2: 0.05*0.05=0.0025 -> 0.00; 0.05*1.50=0.075 -> 0.08; 0.15*0.05=0.0075 -> 0.01; 0.25*0.05=0.0125 -> 0.01
        assert_eq!(mul_numeric(5, 2, 5, 2, 2).unwrap(), 0);
        assert_eq!(mul_numeric(5, 2, 150, 2, 2).unwrap(), 8);
        assert_eq!(mul_numeric(-5, 2, 150, 2, 2).unwrap(), -8);
        assert_eq!(mul_numeric(15, 2, 5, 2, 2).unwrap(), 1);
        assert_eq!(mul_numeric(25, 2, 5, 2, 2).unwrap(), 1);
    }

    #[test]
    fn mul_keeps_a_product_wider_than_i128_when_the_rounded_result_fits() {
        // Numeric 20: 1.5 * 100000000000000000.0 = 150000000000000000.0; the exact product has 57 digits
        let one_and_a_half = 15 * 10i128.pow(19);
        let big = 10i128.pow(37);
        assert_eq!(
            mul_numeric(one_and_a_half, 20, big, 20, 20).unwrap(),
            15 * 10i128.pow(36)
        );
        // and a result over 38 digits is an error
        assert!(mul_numeric(big, 20, big, 20, 20).is_err());
    }

    #[test]
    fn div_rounds_half_even_and_rejects_zero() {
        assert_eq!(div_numeric(5, 2, 150, 2, 2).unwrap(), 3); // 0.05 / 1.50 = 0.0333 -> 0.03
        assert_eq!(div_numeric(100, 2, 5, 2, 2).unwrap(), 2000); // 1.00 / 0.05 = 20.00
        assert_eq!(div_numeric(1, 0, 5, 0, 0).unwrap(), 0); // 1 / 5 at scale 0
        assert!(div_numeric(1, 0, 0, 0, 0).is_err());
    }

    #[test]
    fn int_numeric_conversions() {
        assert_eq!(
            int64_to_numeric(2_147_483_648, 20).unwrap(),
            2_147_483_648 * 10i128.pow(20)
        );
        assert!(int64_to_numeric(7_460_506_064_278_070_085, 20).is_err()); // needs 39 digits
        assert_eq!(numeric_to_int64(-15, 2).unwrap(), 0); // truncation toward zero
        assert_eq!(numeric_to_int64(150, 2).unwrap(), 1);
        assert_eq!(numeric_to_int64(-100, 2).unwrap(), -1);
        assert!(numeric_to_int64(10i128.pow(36), 2).is_err()); // outside Int64
    }

    #[test]
    fn exp_int64_edges() {
        assert_eq!(exp_int64(2, 62).unwrap(), 4_611_686_018_427_387_904);
        assert!(exp_int64(2, 63).is_err());
        assert_eq!(exp_int64(-2, 63).unwrap(), i64::MIN);
        assert_eq!(exp_int64(10, 10).unwrap(), 10_000_000_000);
        assert_eq!(exp_int64(-10, 3).unwrap(), -1000);
        assert_eq!(exp_int64(-1, 7_460_506_064_278_070_085).unwrap(), -1);
        assert_eq!(exp_int64(0, 0).unwrap(), 1);
        assert!(exp_int64(2, -1).is_err());
    }

    #[test]
    fn text_to_int64_grammar() {
        assert_eq!(text_to_int64("+1"), Some(1));
        assert_eq!(text_to_int64("007"), Some(7));
        assert_eq!(text_to_int64("-9223372036854775808"), Some(i64::MIN));
        for bad in [
            "9223372036854775808",
            "",
            " 1",
            "1 ",
            "1.0",
            "abc",
            "0x10",
            "--1",
            "٣",
        ] {
            assert_eq!(text_to_int64(bad), None, "{bad:?}");
        }
    }
}
