//! The UTC time stamp the web pages and the CLI both show.

const MS_PER_DAY: i64 = 86_400_000;
const MS_PER_MINUTE: i64 = 60_000;

fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Formats milliseconds since the Unix epoch as `YYYY-MM-DD HH:MM UTC`, truncated to the minute.
///
/// A value past `i64::MAX` is clamped.
#[must_use]
pub fn utc_stamp(ms: u64) -> String {
    let ms = i64::try_from(ms).unwrap_or(i64::MAX);
    let (year, month, day) = civil(ms.div_euclid(MS_PER_DAY));
    let minutes = ms.rem_euclid(MS_PER_DAY) / MS_PER_MINUTE;
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        minutes / 60,
        minutes % 60
    )
}

#[cfg(test)]
mod tests {
    use super::utc_stamp;

    #[test]
    fn the_stamp_is_utc_and_truncated_to_the_minute() {
        assert_eq!(utc_stamp(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc_stamp(86_399_999), "1970-01-01 23:59 UTC");
        assert_eq!(utc_stamp(951_782_400_000), "2000-02-29 00:00 UTC");
        assert_eq!(utc_stamp(1_794_000_000_000), "2026-11-06 21:20 UTC");
    }
}
