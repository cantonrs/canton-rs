//! Exact fixed-point 10-decimal (`Numeric 10`) arithmetic for Token Standard V2 balances (`S-DX-008`).
//!
//! Uses `i128` scaled by `10^10` (`SCALE`) so every sum, subtraction, conservation check, and
//! sub-cent transfer avoids IEEE-754 floating-point rounding drift (`f32`/`f64` are forbidden).

use std::fmt;

/// Fixed scale matching Daml `Numeric 10` (`10^-10` atomic precision).
pub const SCALE: i128 = 10_000_000_000;
const FRAC_DIGITS: usize = 10;

/// Exact base-10 fixed-point decimal with 10 fractional digits (`Numeric 10`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct DamlDecimal(i128);

impl DamlDecimal {
    pub const ZERO: Self = Self(0);

    /// Returns raw integer scaled by `10^10`.
    #[cfg(test)]
    pub const fn scaled(self) -> i128 {
        self.0
    }

    /// Parses an exact base-10 decimal string with up to 10 fractional digits (no scientific notation).
    pub fn parse(raw: &str) -> Result<Self, String> {
        let s = raw.trim();
        if s.is_empty() {
            return Err("empty decimal amount".to_string());
        }
        let (negative, unsigned) = if let Some(rest) = s.strip_prefix('-') {
            (true, rest)
        } else if let Some(rest) = s.strip_prefix('+') {
            (false, rest)
        } else {
            (false, s)
        };
        if unsigned.is_empty() {
            return Err(format!("invalid decimal amount '{raw}'"));
        }

        let (int_part, frac_part) = match unsigned.split_once('.') {
            Some((i, f)) => {
                if f.contains('.') {
                    return Err(format!("invalid decimal amount '{raw}': multiple dots"));
                }
                (i, f)
            }
            None => (unsigned, ""),
        };

        if int_part.is_empty() && frac_part.is_empty() {
            return Err(format!("invalid decimal amount '{raw}'"));
        }
        if !int_part.bytes().all(|b| b.is_ascii_digit())
            || !frac_part.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(format!("invalid decimal amount '{raw}'"));
        }
        if frac_part.len() > FRAC_DIGITS {
            return Err(format!(
                "decimal amount '{raw}' exceeds {FRAC_DIGITS} fractional digits"
            ));
        }

        let whole: i128 = if int_part.is_empty() {
            0
        } else {
            int_part
                .parse::<i128>()
                .map_err(|_| format!("decimal integer part overflow in '{raw}'"))?
        };
        let frac_raw: i128 = if frac_part.is_empty() {
            0
        } else {
            let mut padded = String::from(frac_part);
            while padded.len() < FRAC_DIGITS {
                padded.push('0');
            }
            padded
                .parse::<i128>()
                .map_err(|_| format!("decimal fraction overflow in '{raw}'"))?
        };

        let magnitude = whole
            .checked_mul(SCALE)
            .and_then(|w| w.checked_add(frac_raw))
            .ok_or_else(|| format!("decimal overflow in '{raw}'"))?;
        let signed = if negative {
            magnitude
                .checked_neg()
                .ok_or_else(|| format!("decimal negation overflow in '{raw}'"))?
        } else {
            magnitude
        };
        Ok(Self(signed))
    }

    /// Checked addition (`self + rhs`).
    pub fn checked_add(self, rhs: Self) -> Result<Self, String> {
        self.0
            .checked_add(rhs.0)
            .map(Self)
            .ok_or_else(|| "decimal addition overflow".to_string())
    }

    /// Checked subtraction (`self - rhs`).
    #[cfg(test)]
    pub fn checked_sub(self, rhs: Self) -> Result<Self, String> {
        self.0
            .checked_sub(rhs.0)
            .map(Self)
            .ok_or_else(|| "decimal subtraction overflow".to_string())
    }

    pub const fn is_positive(self) -> bool {
        self.0 > 0
    }

    /// Formats with all 10 fractional digits (`Numeric 10` wire representation).
    pub fn to_fixed10(self) -> String {
        let sign = if self.0 < 0 { "-" } else { "" };
        let abs = self.0.unsigned_abs();
        let scale = SCALE as u128;
        let whole = abs / scale;
        let frac = abs % scale;
        format!("{sign}{whole}.{frac:010}")
    }
}

impl fmt::Display for DamlDecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sign = if self.0 < 0 { "-" } else { "" };
        let abs = self.0.unsigned_abs();
        let scale = SCALE as u128;
        let whole = abs / scale;
        let frac = abs % scale;
        let raw_frac = format!("{frac:010}");
        let trimmed = raw_frac.trim_end_matches('0');
        let shown_frac = if trimmed.is_empty() { "0" } else { trimmed };
        write!(f, "{sign}{whole}.{shown_frac}")
    }
}

/// Exact `(available, locked)` holding summary for one `(party, admin, instrument)` bucket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BalanceBucket {
    pub avail: DamlDecimal,
    pub locked: DamlDecimal,
}

impl BalanceBucket {
    pub fn total(self) -> Result<DamlDecimal, String> {
        self.avail.checked_add(self.locked)
    }
}

#[cfg(test)]
mod tests {
    use super::{DamlDecimal, SCALE};

    #[test]
    fn subcent_100_transfers_remain_exact() {
        let step = DamlDecimal::parse("0.0000000001").expect("parse 10^-10");
        assert_eq!(step.scaled(), 1);
        let initial = DamlDecimal::parse("1000000.0").expect("parse 1000000.0");
        let mut sender = initial;
        let mut receiver = DamlDecimal::ZERO;
        for _ in 0..100 {
            sender = sender.checked_sub(step).expect("sub");
            receiver = receiver.checked_add(step).expect("add");
        }
        assert_eq!(receiver.to_string(), "0.00000001");
        assert_eq!(sender.to_string(), "999999.99999999");
        assert_eq!(sender.checked_add(receiver).expect("sum"), initial);
    }

    #[test]
    fn parse_and_format_variants() {
        assert_eq!(
            DamlDecimal::parse("100").expect("100").scaled(),
            100 * SCALE
        );
        assert_eq!(DamlDecimal::parse("100").expect("100").to_string(), "100.0");
        assert_eq!(
            DamlDecimal::parse("0.0000000001")
                .expect("10^-10")
                .to_fixed10(),
            "0.0000000001"
        );
        assert!(DamlDecimal::parse("0.12345678901").is_err());
        assert!(DamlDecimal::parse("1e-10").is_err());
        assert!(DamlDecimal::parse("").is_err());
    }
}
