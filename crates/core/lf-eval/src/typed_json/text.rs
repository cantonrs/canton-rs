//! Text forms of numerics, dates and timestamps, and their parsing.

use super::LfType;

pub(super) fn rescale_exact(coeff: i128, from_scale: u8, to_scale: u8) -> Option<i128> {
    if from_scale == to_scale {
        return Some(coeff);
    }
    if from_scale < to_scale {
        let factor = 10i128.checked_pow(u32::from(to_scale - from_scale))?;
        coeff.checked_mul(factor)
    } else {
        let factor = 10i128.checked_pow(u32::from(from_scale - to_scale))?;
        (coeff % factor == 0).then(|| coeff / factor)
    }
}

/// A numeric without trailing zeros but with at least one decimal digit (`Numeric.toString`): `0.0`, `16.67`.
pub(super) fn numeric_trimmed(coeff: i128, scale: u8) -> String {
    let plain = numeric_plain(coeff, scale);
    match plain.split_once('.') {
        None => format!("{plain}.0"),
        Some((int, frac)) => {
            let frac = frac.trim_end_matches('0');
            format!("{int}.{}", if frac.is_empty() { "0" } else { frac })
        }
    }
}

/// A numeric as a plain decimal at its scale (`Numeric.toString`): `100.0000000000`, `-0.5000000000`.
pub(super) fn numeric_plain(coeff: i128, scale: u8) -> String {
    let sign = if coeff < 0 { "-" } else { "" };
    let digits = coeff.unsigned_abs().to_string();
    let scale = usize::from(scale);
    if scale == 0 {
        return format!("{sign}{digits}");
    }
    let padded = format!("{digits:0>width$}", width = scale + 1);
    let (int, frac) = padded.split_at(padded.len() - scale);
    format!("{sign}{int}.{frac}")
}

/// The civil date of a day count since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `YYYY-MM-DD` of a day count since the epoch.
pub fn format_date(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DDTHH:MM:SS[.fff[fff]]Z` of microseconds since the epoch as Java's `Instant.toString` writes it: no fraction at a whole second,
/// otherwise three digits (milliseconds) or six.
pub fn format_timestamp(micros: i64) -> String {
    let seconds = micros.div_euclid(1_000_000);
    let fraction = micros.rem_euclid(1_000_000);
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let base = format!(
        "{}T{:02}:{:02}:{:02}",
        format_date(days),
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    );
    match fraction {
        0 => format!("{base}Z"),
        f if f % 1000 == 0 => format!("{base}.{:03}Z", f / 1000),
        f => format!("{base}.{f:06}Z"),
    }
}

/// Like [`format_timestamp`] with the fraction's trailing zeros dropped (`...:21.53937Z`): how a scan prints a contract's `created_at`.
pub fn format_timestamp_trimmed(micros: i64) -> String {
    let plain = format_timestamp_micros(micros);
    let base = plain.trim_end_matches('Z');
    let base = base.trim_end_matches('0');
    format!("{}Z", base.trim_end_matches('.'))
}

/// Like [`format_timestamp`] with the six digits of microseconds always (the scan's `formatRecordTime`).
pub fn format_timestamp_micros(micros: i64) -> String {
    let plain = format_timestamp(micros);
    let base = plain.trim_end_matches('Z');
    match base.split_once('.') {
        Some((head, f)) => format!("{head}.{f:0<6}Z"),
        None => format!("{base}.000000Z"),
    }
}

/// A numeric as Java's `BigDecimal.toString` writes it: plain while the adjusted exponent is at least -6, scientific (`0E-10`, `1.000E-7`)
/// below that.
pub fn format_numeric(coeff: i128, scale: u8) -> String {
    let sign = if coeff < 0 { "-" } else { "" };
    let digits = coeff.unsigned_abs().to_string();
    let scale = i64::from(scale);
    if scale == 0 {
        return format!("{sign}{digits}");
    }
    let adjusted = digits.len() as i64 - 1 - scale;
    if adjusted >= -6 {
        let padded = format!("{digits:0>width$}", width = scale as usize + 1);
        let (whole, frac) = padded.split_at(padded.len() - scale as usize);
        return format!("{sign}{whole}.{frac}");
    }
    let mantissa = if digits.len() > 1 {
        format!("{}.{}", &digits[..1], &digits[1..])
    } else {
        digits
    };
    format!(
        "{sign}{mantissa}E{}{}",
        if adjusted < 0 { "-" } else { "+" },
        adjusted.abs()
    )
}

/// `ty` with the type variables `params` replaced by `args`.
pub(super) fn substitute(ty: &LfType, params: &[String], args: &[LfType]) -> LfType {
    let sub = |t: &LfType| Box::new(substitute(t, params, args));
    match ty {
        LfType::Var(v) => params
            .iter()
            .position(|p| p == v)
            .map_or_else(|| ty.clone(), |i| args[i].clone()),
        LfType::List(t) => LfType::List(sub(t)),
        LfType::Optional(t) => LfType::Optional(sub(t)),
        LfType::TextMap(t) => LfType::TextMap(sub(t)),
        LfType::GenMap(k, v) => LfType::GenMap(sub(k), sub(v)),
        LfType::Numeric(None) => ty.clone(),
        LfType::Con {
            package_id,
            module,
            name,
            args: inner,
        } => LfType::Con {
            package_id: package_id.clone(),
            module: module.clone(),
            name: name.clone(),
            args: inner.iter().map(|t| substitute(t, params, args)).collect(),
        },
        other => other.clone(),
    }
}

/// A decimal as text (plain, or as Java's `BigDecimal.toString` writes it with an exponent) at exactly `scale` decimal places.
pub fn numeric(text: &str, scale: u8) -> Option<(i128, u8)> {
    let (mantissa, exponent) = match text.split_once(['E', 'e']) {
        Some((m, e)) => (m, e.parse::<i32>().ok()?),
        None => (text, 0),
    };
    let negative = mantissa.starts_with('-');
    let digits = mantissa.trim_start_matches(['+', '-']);
    let (whole, frac) = digits.split_once('.').unwrap_or((digits, ""));
    if whole.is_empty() && frac.is_empty()
        || !whole
            .chars()
            .chain(frac.chars())
            .all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let mut coeff: i128 = format!("{whole}{frac}").parse().ok()?;
    // the value is coeff * 10^(exponent - frac.len()); wanted: coeff' * 10^(-scale)
    let shift = exponent - frac.len() as i32 + i32::from(scale);
    if shift >= 0 {
        coeff = coeff.checked_mul(10i128.checked_pow(shift as u32)?)?;
    } else {
        let by = 10i128.checked_pow((-shift) as u32)?;
        if coeff % by != 0 {
            return None;
        }
        coeff /= by;
    }
    Some((if negative { -coeff } else { coeff }, scale))
}

/// Days since 1970-01-01 of a civil date (the proleptic Gregorian calendar).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYY-MM-DD` as days since the epoch.
pub fn date_days(text: &str) -> Option<i64> {
    let mut parts = text.split('-');
    let (y, m, d) = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    (parts.next().is_none() && (1..=12).contains(&m) && (1..=31).contains(&d))
        .then(|| days_from_civil(y, m, d))
}

/// `YYYY-MM-DDTHH:MM:SS[.ffffff]Z` as microseconds since the epoch.
pub fn timestamp_micros(text: &str) -> Option<i64> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    let mut hms = clock.split(':');
    let (h, m, s): (i64, i64, i64) = (
        hms.next()?.parse().ok()?,
        hms.next()?.parse().ok()?,
        hms.next()?.parse().ok()?,
    );
    if fraction.len() > 6 || !fraction.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let micros: i64 = format!("{fraction:0<6}").parse().ok()?;
    Some(((date_days(date)? * 24 + h) * 60 + m) * 60 * 1_000_000 + s * 1_000_000 + micros)
}
