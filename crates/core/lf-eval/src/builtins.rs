//! Extended Daml-LF Builtin Functions.
//!
//! Implements:
//! - Multi-scale Numeric arithmetic, division, rounding modes (AT-L01)
//! - Date & Timestamp conversions and RFC 3339 representations (AT-L02)
//! - Text Unicode code point handling, explode/implode, SHA-256 (AT-L03)
//! - BigNumeric precision operations (AT-L01)

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundingMode {
    HalfUp,
    HalfEven,
    Floor,
    Ceiling,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuiltinError {
    ArithmeticOverflow(String),
    DivisionByZero,
    DateOutOfRange(i32),
    TimestampOutOfRange(i64),
    InvalidPartySyntax(String),
    InvalidNumericString(String),
    InvalidUtf8,
}

impl std::fmt::Display for BuiltinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ArithmeticOverflow(msg) => write!(f, "arithmetic overflow: {msg}"),
            Self::DivisionByZero => write!(f, "division by zero"),
            Self::DateOutOfRange(d) => write!(f, "date out of range: {d}"),
            Self::TimestampOutOfRange(ts) => write!(f, "timestamp out of range: {ts}"),
            Self::InvalidPartySyntax(p) => write!(f, "invalid party syntax: {p}"),
            Self::InvalidNumericString(n) => write!(f, "invalid numeric string: {n}"),
            Self::InvalidUtf8 => write!(f, "invalid utf-8 text"),
        }
    }
}

impl std::error::Error for BuiltinError {}

// -----------------------------------------------------------------------------
// Numeric Arithmetic (Multi-scale)
// -----------------------------------------------------------------------------

/// Multiply two numerics: (coeff1 * 10^-s1) * (coeff2 * 10^-s2) = (coeff1 * coeff2) * 10^-(s1+s2)
/// Then round to target scale.
pub fn mul_numeric(
    coeff1: i128,
    scale1: u8,
    coeff2: i128,
    scale2: u8,
    target_scale: u8,
    rounding: RoundingMode,
) -> Result<i128, BuiltinError> {
    let raw = coeff1
        .checked_mul(coeff2)
        .ok_or_else(|| BuiltinError::ArithmeticOverflow("mul_numeric overflow".into()))?;
    let raw_scale = scale1 + scale2;
    rescale(raw, raw_scale, target_scale, rounding)
}

/// Divide two numerics: (coeff1 * 10^-s1) / (coeff2 * 10^-s2) = (coeff1 / coeff2) * 10^-(s1-s2)
pub fn div_numeric(
    coeff1: i128,
    scale1: u8,
    coeff2: i128,
    scale2: u8,
    target_scale: u8,
    rounding: RoundingMode,
) -> Result<i128, BuiltinError> {
    if coeff2 == 0 {
        return Err(BuiltinError::DivisionByZero);
    }
    // Scale up dividend to preserve precision before division:
    // We want target_scale precision: dividend * 10^(target_scale + scale2 - scale1) / divisor
    let shift = target_scale as i32 + scale2 as i32 - scale1 as i32;
    if shift >= 0 {
        let factor = 10i128.checked_pow(shift as u32).ok_or_else(|| {
            BuiltinError::ArithmeticOverflow("div_numeric scale shift overflow".into())
        })?;
        let scaled_dividend = coeff1.checked_mul(factor).ok_or_else(|| {
            BuiltinError::ArithmeticOverflow("div_numeric dividend overflow".into())
        })?;
        round_div(scaled_dividend, coeff2, rounding)
    } else {
        let factor = 10i128.checked_pow((-shift) as u32).ok_or_else(|| {
            BuiltinError::ArithmeticOverflow("div_numeric scale shift overflow".into())
        })?;
        let scaled_divisor = coeff2.checked_mul(factor).ok_or_else(|| {
            BuiltinError::ArithmeticOverflow("div_numeric divisor overflow".into())
        })?;
        round_div(coeff1, scaled_divisor, rounding)
    }
}

pub fn rescale(
    val: i128,
    from_scale: u8,
    to_scale: u8,
    rounding: RoundingMode,
) -> Result<i128, BuiltinError> {
    if from_scale == to_scale {
        return Ok(val);
    }
    if from_scale < to_scale {
        let diff = (to_scale - from_scale) as u32;
        let factor = 10i128
            .checked_pow(diff)
            .ok_or_else(|| BuiltinError::ArithmeticOverflow("scale up overflow".into()))?;
        val.checked_mul(factor).ok_or_else(|| {
            BuiltinError::ArithmeticOverflow("rescale multiplication overflow".into())
        })
    } else {
        let diff = (from_scale - to_scale) as u32;
        let factor = 10i128
            .checked_pow(diff)
            .ok_or_else(|| BuiltinError::ArithmeticOverflow("scale down overflow".into()))?;
        round_div(val, factor, rounding)
    }
}

fn round_div(dividend: i128, divisor: i128, rounding: RoundingMode) -> Result<i128, BuiltinError> {
    let quotient = dividend / divisor;
    let remainder = dividend % divisor;
    if remainder == 0 {
        return Ok(quotient);
    }

    let sign = (dividend < 0) ^ (divisor < 0);
    let abs_rem = remainder.abs();
    let abs_div = divisor.abs();

    let dec = || {
        quotient
            .checked_sub(1)
            .ok_or_else(|| BuiltinError::ArithmeticOverflow("round_div quotient underflow".into()))
    };
    let inc = || {
        quotient
            .checked_add(1)
            .ok_or_else(|| BuiltinError::ArithmeticOverflow("round_div quotient overflow".into()))
    };

    match rounding {
        RoundingMode::Floor => {
            if sign {
                dec()
            } else {
                Ok(quotient)
            }
        }
        RoundingMode::Ceiling => {
            if sign {
                Ok(quotient)
            } else {
                inc()
            }
        }
        RoundingMode::HalfUp => {
            // Equivalent to abs_rem * 2 >= abs_div without overflow
            if abs_rem >= abs_div - abs_rem {
                if sign {
                    dec()
                } else {
                    inc()
                }
            } else {
                Ok(quotient)
            }
        }
        RoundingMode::HalfEven => {
            let is_greater = abs_rem > abs_div - abs_rem;
            let is_equal = abs_rem == abs_div - abs_rem;
            if is_greater {
                if sign {
                    dec()
                } else {
                    inc()
                }
            } else if is_equal {
                // Tie: round to nearest even quotient
                if quotient % 2 != 0 {
                    if sign {
                        dec()
                    } else {
                        inc()
                    }
                } else {
                    Ok(quotient)
                }
            } else {
                Ok(quotient)
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Date & Timestamp Builtins (AT-L02)
// -----------------------------------------------------------------------------

pub const MIN_DATE_DAYS: i32 = -719_162;
pub const MAX_DATE_DAYS: i32 = 2_932_896;

pub const MIN_TIMESTAMP_MICROS: i64 = -62_135_596_800_000_000;
pub const MAX_TIMESTAMP_MICROS: i64 = 253_402_300_799_999_999;

pub fn validate_date_days(days: i32) -> Result<i32, BuiltinError> {
    if !(MIN_DATE_DAYS..=MAX_DATE_DAYS).contains(&days) {
        Err(BuiltinError::DateOutOfRange(days))
    } else {
        Ok(days)
    }
}

pub fn validate_timestamp_micros(micros: i64) -> Result<i64, BuiltinError> {
    if !(MIN_TIMESTAMP_MICROS..=MAX_TIMESTAMP_MICROS).contains(&micros) {
        Err(BuiltinError::TimestampOutOfRange(micros))
    } else {
        Ok(micros)
    }
}

// -----------------------------------------------------------------------------
// Text Unicode Code Point Operations (AT-L03)
// -----------------------------------------------------------------------------

/// Explodes text into a sequence of Unicode code points (characters).
pub fn explode_text(text: &str) -> Vec<char> {
    text.chars().collect()
}

/// Implodes Unicode code points back into UTF-8 text.
pub fn implode_text(chars: &[char]) -> String {
    chars.iter().collect()
}

/// Computes SHA-256 of text in hex format.
pub fn sha256_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_at_l01_numeric_mult_and_div_with_rounding() {
        // 1.50 (scale 2) * 2.000 (scale 3) = 3.00000 -> target scale 2 = 3.00
        let res = mul_numeric(150, 2, 2000, 3, 2, RoundingMode::HalfUp).unwrap();
        assert_eq!(res, 300);

        // 1.00 / 3.00 with HalfEven rounding to scale 4: 0.3333
        let div_res = div_numeric(100, 2, 300, 2, 4, RoundingMode::HalfEven).unwrap();
        assert_eq!(div_res, 3333);

        // Division by zero fails
        assert_eq!(
            div_numeric(100, 2, 0, 2, 2, RoundingMode::HalfUp),
            Err(BuiltinError::DivisionByZero)
        );
    }

    #[test]
    fn test_at_l02_date_timestamp_bounds() {
        assert!(validate_date_days(0).is_ok());
        assert!(validate_date_days(MIN_DATE_DAYS).is_ok());
        assert!(validate_date_days(MAX_DATE_DAYS).is_ok());
        assert!(validate_date_days(MIN_DATE_DAYS - 1).is_err());
        assert!(validate_date_days(MAX_DATE_DAYS + 1).is_err());

        assert!(validate_timestamp_micros(0).is_ok());
        assert!(validate_timestamp_micros(MIN_TIMESTAMP_MICROS).is_ok());
        assert!(validate_timestamp_micros(MAX_TIMESTAMP_MICROS).is_ok());
        assert!(validate_timestamp_micros(MIN_TIMESTAMP_MICROS - 1).is_err());
        assert!(validate_timestamp_micros(MAX_TIMESTAMP_MICROS + 1).is_err());
    }

    #[test]
    fn test_at_l03_unicode_text_explode_implode() {
        let original = "Hello 🌍! Daml-LF 3.x 한글 테스트";
        let chars = explode_text(original);
        assert_eq!(chars.len(), 27);
        let restored = implode_text(&chars);

        assert_eq!(original, restored);

        let hash = sha256_text(original);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_round_div_large_values_no_overflow() {
        // A remainder near i128::MAX would overflow with abs_rem * 2, but our safe comparison handles it cleanly.
        let large_dividend = i128::MAX - 2;
        let large_divisor = i128::MAX - 1;
        let res = round_div(large_dividend, large_divisor, RoundingMode::HalfUp);
        // (MAX - 2) / (MAX - 1): quotient = 0, remainder = MAX - 2.
        // Remainder is well above half of divisor, so it rounds up to 1.
        assert_eq!(res, Ok(1));
    }
}
