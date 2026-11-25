//! S-TX-001: `TIMESTAMP_TO_TEXT` and `DATE_TO_TEXT`.
//!
//! The expected strings are what the JVM 3.7.2 printed for `show` on a `Time` and a `Date` (Java `Instant` style:
//! no fraction when the microseconds are zero, three digits when they are a whole number of milliseconds,
//! otherwise six). Timestamps are Int64 microseconds since the Unix epoch and dates Int64 days, as everywhere in
//! this evaluator.

/// (year, month, day) of a day number counted from 1970-01-01 (proleptic Gregorian; Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

pub(crate) fn date_to_text(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

pub(crate) fn timestamp_to_text(micros: i64) -> String {
    let secs = micros.div_euclid(1_000_000);
    let frac = micros.rem_euclid(1_000_000);
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    let of_day = secs.rem_euclid(86_400);
    let fraction = if frac == 0 {
        String::new()
    } else if frac % 1000 == 0 {
        format!(".{:03}", frac / 1000)
    } else {
        format!(".{frac:06}")
    };
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}{fraction}Z",
        of_day / 3600,
        (of_day / 60) % 60,
        of_day % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_print_like_the_jvm() {
        assert_eq!(timestamp_to_text(0), "1970-01-01T00:00:00Z");
        assert_eq!(timestamp_to_text(1), "1970-01-01T00:00:00.000001Z");
        assert_eq!(timestamp_to_text(1500), "1970-01-01T00:00:00.001500Z");
        assert_eq!(timestamp_to_text(123_456), "1970-01-01T00:00:00.123456Z");
        assert_eq!(timestamp_to_text(1000), "1970-01-01T00:00:00.001Z");
        assert_eq!(timestamp_to_text(-1), "1969-12-31T23:59:59.999999Z");
        assert_eq!(
            timestamp_to_text(1_709_251_199_000_000),
            "2024-02-29T23:59:59Z"
        );
        assert_eq!(
            timestamp_to_text(-62_135_596_800_000_000),
            "0001-01-01T00:00:00Z"
        );
        assert_eq!(
            timestamp_to_text(253_402_300_799_000_000),
            "9999-12-31T23:59:59Z"
        );
    }

    #[test]
    fn dates_print_like_the_jvm() {
        assert_eq!(date_to_text(0), "1970-01-01");
        assert_eq!(date_to_text(11_016), "2000-02-29");
        assert_eq!(date_to_text(-719_162), "0001-01-01");
        assert_eq!(date_to_text(2_932_896), "9999-12-31");
        assert_eq!(date_to_text(-1), "1969-12-31");
    }
}
