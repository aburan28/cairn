//! Timestamps, in `std` alone.
//!
//! These strings land inside records whose digests must match the Python
//! reference byte for byte, so the format is consensus-critical: `+00:00`, not
//! `Z`, and seconds precision. It lives in the library rather than in a binary
//! because more than one binary needs it -- `proofwork` and `proofwork-mcp` --
//! and a second copy of a date formatter is a second chance to disagree about
//! what time it is.

use std::time::{SystemTime, UNIX_EPOCH};

/// Now, as `2026-07-28T17:12:33+00:00`.
///
/// The reference implementation's `node.now()` --
/// `datetime.now(timezone.utc).isoformat(timespec="seconds")` -- spelled with
/// nothing but `std`, because this crate has no date library and will not grow
/// one for a single format string.
///
/// This value is **advisory**. Ordering in this system comes from the hash
/// chain, never from the clock: an operator who lies about the time produces a
/// log whose entries are still in exactly the order they were appended, which is
/// why a wrong clock is a cosmetic problem here rather than a consensus one.
pub fn timestamp() -> String {
    let seconds = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        // A clock set before 1970. Absurd, and still not a reason to panic.
        Err(before) => i64::try_from(before.duration().as_secs())
            .map(|seconds| -seconds)
            .unwrap_or(i64::MIN),
    };
    format_iso8601_utc(seconds)
}

/// Seconds since the Unix epoch, rendered as a UTC ISO-8601 instant.
///
/// Clamped to years 1..=9999 first. Every arithmetic step below is then bounded
/// by construction, which matters because this crate builds release with
/// `overflow-checks = true`: an unclamped input would abort rather than wrap.
pub fn format_iso8601_utc(unix_seconds: i64) -> String {
    // 0001-01-01T00:00:00Z.
    const MIN_SECONDS: i64 = -62_135_596_800;
    // 9999-12-31T23:59:59Z.
    const MAX_SECONDS: i64 = 253_402_300_799;
    const SECONDS_PER_DAY: i64 = 86_400;

    let unix_seconds = unix_seconds.clamp(MIN_SECONDS, MAX_SECONDS);
    // Euclidean, not truncating: a negative instant must floor to the day that
    // contains it, otherwise every pre-1970 time lands one day late.
    let days = unix_seconds.div_euclid(SECONDS_PER_DAY);
    let second_of_day = unix_seconds.rem_euclid(SECONDS_PER_DAY);

    let (year, month, day) = civil_from_days(days);
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;

    // `+00:00`, not `Z`: that is what Python's `isoformat` emits for a
    // timezone-aware UTC datetime, and these strings land in records whose
    // digests must match across implementations.
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+00:00")
}

/// Days since the Unix epoch to a proleptic Gregorian `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days`, with Euclidean division in place of his
/// sign correction. The algorithm shifts the year to start in March so that the
/// leap day lands at the end of it, which is what removes every special case for
/// February.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    // Re-base to 0000-03-01. Bounded by the clamp in the caller.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097); // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153; // [0, 11], March = 0
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instants_render_the_way_python_isoformat_does() {
        // `datetime.fromtimestamp(x, timezone.utc).isoformat(timespec="seconds")`
        assert_eq!(format_iso8601_utc(0), "1970-01-01T00:00:00+00:00");
        assert_eq!(format_iso8601_utc(1), "1970-01-01T00:00:01+00:00");
        assert_eq!(
            format_iso8601_utc(1_774_699_200),
            "2026-03-28T12:00:00+00:00"
        );
        assert_eq!(
            format_iso8601_utc(1_785_196_800),
            "2026-07-28T00:00:00+00:00"
        );
    }

    #[test]
    fn leap_days_and_century_rules_are_respected() {
        // 2000 is a leap year (divisible by 400), so 29 February exists.
        assert_eq!(format_iso8601_utc(951_782_400), "2000-02-29T00:00:00+00:00");
        // 1900 was not (divisible by 100 but not 400): these two days are
        // adjacent, with no 29 February between them.
        assert_eq!(
            format_iso8601_utc(-2_203_977_600),
            "1900-02-28T00:00:00+00:00"
        );
        assert_eq!(
            format_iso8601_utc(-2_203_977_600 + 86_400),
            "1900-03-01T00:00:00+00:00"
        );
    }

    #[test]
    fn instants_before_the_epoch_floor_to_the_right_day() {
        // Truncating division would put this on 1970-01-01, a day late: the
        // reason `div_euclid` is used rather than `/`.
        assert_eq!(format_iso8601_utc(-1), "1969-12-31T23:59:59+00:00");
        assert_eq!(format_iso8601_utc(-86_400), "1969-12-31T00:00:00+00:00");
    }

    #[test]
    fn absurd_instants_clamp_instead_of_overflowing() {
        // Release builds enable overflow checks, so an unclamped i64::MIN here
        // would abort rather than wrap.
        assert_eq!(format_iso8601_utc(i64::MIN), "0001-01-01T00:00:00+00:00");
        assert_eq!(format_iso8601_utc(i64::MAX), "9999-12-31T23:59:59+00:00");
    }

    #[test]
    fn the_clock_produces_a_well_formed_instant() {
        let stamp = timestamp();
        assert_eq!(stamp.chars().count(), "1970-01-01T00:00:00+00:00".len());
        assert!(stamp.ends_with("+00:00"), "got {stamp:?}");
        assert!(stamp.contains('T'), "got {stamp:?}");
    }
}
