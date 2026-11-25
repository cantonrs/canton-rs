//! Canton 3.7.2 `BigNumeric` representation and arithmetic (`SValue.SBigNumeric`, `SBuiltinFun.scala`).
//!
//! Normalized invariant: zero is `(coeff = 0, scale = 0)`; every non-zero value has
//! trailing decimal zeros stripped (`coeff % 10 != 0`) with `scale <= 32768` and
//! `precision - scale <= 32768` (`MaxPrecision = 65536`, `MaxScale = 32768`, `MinScale = -32767`).

use num_bigint::BigInt;

use crate::{numeric_ops::NUMERIC_BOUND, EvalError};

pub(crate) const MAX_PRECISION: i64 = 1 << 16; // 65536
pub(crate) const MAX_SCALE: i32 = 32_768;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigNumericValue {
    pub coeff: BigInt,
    pub scale: i32,
}

fn pow10(exp: u32) -> BigInt {
    BigInt::from(10u8).pow(exp)
}

fn decimal_digits(n: &BigInt) -> usize {
    if n == &BigInt::ZERO {
        return 1;
    }
    n.magnitude().to_str_radix(10).len()
}

impl BigNumericValue {
    pub fn zero() -> Self {
        Self {
            coeff: BigInt::ZERO,
            scale: 0,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.coeff == BigInt::ZERO
    }

    pub fn to_signed_bytes_le(&self) -> (Vec<u8>, i32) {
        (self.coeff.to_signed_bytes_le(), self.scale)
    }

    pub fn from_signed_bytes_le(bytes: &[u8], scale: i32) -> Result<Self, EvalError> {
        Self::from_scaled(BigInt::from_signed_bytes_le(bytes), i64::from(scale))
    }

    /// Normalize `(coeff * 10^-scale)` matching `SValue.SBigNumeric.fromBigDecimal`.
    pub fn from_scaled(coeff: BigInt, scale: i64) -> Result<Self, EvalError> {
        if coeff == BigInt::ZERO {
            return Ok(Self::zero());
        }
        let digits_str = coeff.magnitude().to_str_radix(10);
        let digits = digits_str.len() as i64;
        let trailing_zeros = digits_str.bytes().rev().take_while(|&b| b == b'0').count() as i64;
        let norm_precision = digits - trailing_zeros;
        let norm_scale = scale - trailing_zeros;
        if norm_scale > i64::from(MAX_SCALE) || (norm_precision - norm_scale) > i64::from(MAX_SCALE)
        {
            return Err(EvalError::Arithmetic(
                "BigNumeric overflow or underflow".to_string(),
            ));
        }
        let norm_coeff = if trailing_zeros > 0 {
            coeff / pow10(trailing_zeros as u32)
        } else {
            coeff
        };
        Ok(Self {
            coeff: norm_coeff,
            scale: norm_scale as i32,
        })
    }

    pub fn precision(&self) -> i64 {
        decimal_digits(&self.coeff) as i64
    }

    pub fn scale(&self) -> i64 {
        i64::from(self.scale)
    }

    /// Plain decimal representation without scientific notation (`BigDecimal.toPlainString`).
    pub fn to_plain_string(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }
        let neg = self.coeff < BigInt::ZERO;
        let digits = self.coeff.magnitude().to_str_radix(10);
        let body = if self.scale == 0 {
            digits
        } else if self.scale < 0 {
            let zeros = "0".repeat((-self.scale) as usize);
            format!("{digits}{zeros}")
        } else {
            let s = self.scale as usize;
            if s >= digits.len() {
                let zeros = "0".repeat(s - digits.len());
                format!("0.{zeros}{digits}")
            } else {
                let split = digits.len() - s;
                format!("{}.{}", &digits[..split], &digits[split..])
            }
        };
        if neg {
            format!("-{body}")
        } else {
            body
        }
    }

    /// Matches `Numeric.toUnscaledString(x)` (`BIGNUMERIC_TO_TEXT` and `ArithmeticError`).
    pub fn to_unscaled_string(&self) -> String {
        let s = self.to_plain_string();
        if s.contains('.') {
            s
        } else {
            format!("{s}.0")
        }
    }

    pub fn from_numeric(coeff: i128, scale: u8) -> Result<Self, EvalError> {
        Self::from_scaled(BigInt::from(coeff), i64::from(scale))
    }

    pub fn to_numeric(&self, target_scale: u8) -> Result<i128, EvalError> {
        if self.is_zero() {
            return Ok(0);
        }
        let target = i64::from(target_scale);
        let src = i64::from(self.scale);
        if src > target {
            return Err(EvalError::Arithmetic("BIGNUMERIC_TO_NUMERIC".to_string()));
        }
        let diff = (target - src) as u32;
        if self.precision() + i64::from(diff) > 39 {
            return Err(EvalError::Arithmetic("BIGNUMERIC_TO_NUMERIC".to_string()));
        }
        let scaled = &self.coeff * pow10(diff);
        let coeff = i128::try_from(&scaled)
            .map_err(|_| EvalError::Arithmetic("BIGNUMERIC_TO_NUMERIC".to_string()))?;
        if coeff.unsigned_abs() < NUMERIC_BOUND {
            Ok(coeff)
        } else {
            Err(EvalError::Arithmetic("BIGNUMERIC_TO_NUMERIC".to_string()))
        }
    }

    pub fn add(&self, other: &Self) -> Result<Self, EvalError> {
        if self.is_zero() {
            return Ok(other.clone());
        }
        if other.is_zero() {
            return Ok(self.clone());
        }
        let target_scale = self.scale.max(other.scale);
        let a = if self.scale < target_scale {
            &self.coeff * pow10((target_scale - self.scale) as u32)
        } else {
            self.coeff.clone()
        };
        let b = if other.scale < target_scale {
            &other.coeff * pow10((target_scale - other.scale) as u32)
        } else {
            other.coeff.clone()
        };
        Self::from_scaled(a + b, i64::from(target_scale))
    }

    pub fn sub(&self, other: &Self) -> Result<Self, EvalError> {
        if other.is_zero() {
            return Ok(self.clone());
        }
        let neg_other = Self {
            coeff: -&other.coeff,
            scale: other.scale,
        };
        self.add(&neg_other)
    }

    pub fn mul(&self, other: &Self) -> Result<Self, EvalError> {
        if self.is_zero() || other.is_zero() {
            return Ok(Self::zero());
        }
        Self::from_scaled(
            &self.coeff * &other.coeff,
            i64::from(self.scale) + i64::from(other.scale),
        )
    }

    pub fn shift_right(&self, shifting: i64) -> Result<Self, EvalError> {
        if self.is_zero() {
            return Ok(Self::zero());
        }
        if shifting.unsigned_abs() > MAX_PRECISION as u64 {
            return Err(EvalError::Arithmetic("SHIFT_RIGHT_BIGNUMERIC".to_string()));
        }
        let new_scale = i64::from(self.scale) + shifting;
        if new_scale > i64::from(MAX_SCALE) || (self.precision() - new_scale) > i64::from(MAX_SCALE)
        {
            return Err(EvalError::Arithmetic("SHIFT_RIGHT_BIGNUMERIC".to_string()));
        }
        Ok(Self {
            coeff: self.coeff.clone(),
            scale: new_scale as i32,
        })
    }

    pub fn div(
        &self,
        other: &Self,
        unchecked_scale: i64,
        unchecked_rm: i64,
    ) -> Result<Self, EvalError> {
        if unchecked_scale.unsigned_abs() > MAX_SCALE as u64 {
            return Err(EvalError::Arithmetic("DIV_BIGNUMERIC".to_string()));
        }
        if !(0..=7).contains(&unchecked_rm) || other.is_zero() {
            return Err(EvalError::Arithmetic("DIV_BIGNUMERIC".to_string()));
        }
        if self.is_zero() {
            return Ok(Self::zero());
        }
        let target_scale = unchecked_scale as i32;
        let dx = self.precision();
        let dy = other.precision();
        // Order-of-magnitude bound to avoid huge intermediate powers of 10 on guaranteed overflow:
        // |x/y| >= 10^((dx - 1 - sx) - (dy - sy)). Any rounded result at target_scale >= -32768
        // exceeding 10^32768 cannot satisfy precision - scale <= 32768.
        let min_int_digits = (dx - 1 - i64::from(self.scale)) - (dy - i64::from(other.scale));
        if min_int_digits > i64::from(MAX_SCALE) + 2 {
            return Err(EvalError::Arithmetic("DIV_BIGNUMERIC".to_string()));
        }

        let exp = i64::from(target_scale) + i64::from(other.scale) - i64::from(self.scale);
        let positive = (self.coeff > BigInt::ZERO) == (other.coeff > BigInt::ZERO);

        // Short-circuit when |x / y| * 10^target_scale is strictly in (0, 0.1).
        if exp < -(dx + 2) {
            let q = match unchecked_rm {
                0 => {
                    if positive {
                        BigInt::from(1)
                    } else {
                        BigInt::from(-1)
                    }
                }
                2 => {
                    if positive {
                        BigInt::from(1)
                    } else {
                        BigInt::ZERO
                    }
                }
                3 => {
                    if positive {
                        BigInt::ZERO
                    } else {
                        BigInt::from(-1)
                    }
                }
                7 => return Err(EvalError::Arithmetic("DIV_BIGNUMERIC".to_string())),
                _ => BigInt::ZERO,
            };
            return Self::from_scaled(q, i64::from(target_scale));
        }

        let (raw_num, raw_den) = if exp >= 0 {
            (&self.coeff * pow10(exp as u32), other.coeff.clone())
        } else {
            (self.coeff.clone(), &other.coeff * pow10((-exp) as u32))
        };
        let (num, den) = if raw_den < BigInt::ZERO {
            (-raw_num, -raw_den)
        } else {
            (raw_num, raw_den)
        };
        let q = &num / &den;
        let r = &num % &den;
        let rounded = if r == BigInt::ZERO {
            q
        } else {
            use std::cmp::Ordering;
            let step = if num > BigInt::ZERO {
                BigInt::from(1)
            } else {
                BigInt::from(-1)
            };
            let cmp_half = (r.magnitude() * 2u8).cmp(den.magnitude());
            match unchecked_rm {
                0 => q + step, // UP
                1 => q,        // DOWN
                2 => {
                    // CEILING
                    if num > BigInt::ZERO {
                        q + 1
                    } else {
                        q
                    }
                }
                3 => {
                    // FLOOR
                    if num < BigInt::ZERO {
                        q - 1
                    } else {
                        q
                    }
                }
                4 => {
                    // HALF_UP
                    if cmp_half != Ordering::Less {
                        q + step
                    } else {
                        q
                    }
                }
                5 => {
                    // HALF_DOWN
                    if cmp_half == Ordering::Greater {
                        q + step
                    } else {
                        q
                    }
                }
                6 => {
                    // HALF_EVEN
                    let odd = (q.magnitude() % 2u8) != num_bigint::BigUint::ZERO;
                    if cmp_half == Ordering::Greater || (cmp_half == Ordering::Equal && odd) {
                        q + step
                    } else {
                        q
                    }
                }
                7 => return Err(EvalError::Arithmetic("DIV_BIGNUMERIC".to_string())),
                _ => return Err(EvalError::Arithmetic("DIV_BIGNUMERIC".to_string())),
            }
        };
        Self::from_scaled(rounded, i64::from(target_scale))
    }

    pub fn cmp_value(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match (self.coeff.sign(), other.coeff.sign()) {
            (num_bigint::Sign::Minus, num_bigint::Sign::NoSign | num_bigint::Sign::Plus) => {
                Ordering::Less
            }
            (num_bigint::Sign::NoSign, num_bigint::Sign::Plus) => Ordering::Less,
            (num_bigint::Sign::NoSign, num_bigint::Sign::NoSign) => Ordering::Equal,
            (num_bigint::Sign::NoSign | num_bigint::Sign::Plus, num_bigint::Sign::Minus) => {
                Ordering::Greater
            }
            (num_bigint::Sign::Plus, num_bigint::Sign::NoSign) => Ordering::Greater,
            (sign @ (num_bigint::Sign::Plus | num_bigint::Sign::Minus), _) => {
                let mag_a = self.precision() - i64::from(self.scale);
                let mag_b = other.precision() - i64::from(other.scale);
                let mag_ord = mag_a.cmp(&mag_b);
                if mag_ord != Ordering::Equal {
                    return if sign == num_bigint::Sign::Minus {
                        mag_ord.reverse()
                    } else {
                        mag_ord
                    };
                }
                let target_scale = self.scale.max(other.scale);
                let a = if self.scale < target_scale {
                    &self.coeff * pow10((target_scale - self.scale) as u32)
                } else {
                    self.coeff.clone()
                };
                let b = if other.scale < target_scale {
                    &other.coeff * pow10((target_scale - other.scale) as u32)
                } else {
                    other.coeff.clone()
                };
                a.cmp(&b)
            }
        }
    }
}
