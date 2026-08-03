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

/// Seconds since the Unix epoch.
///
/// Same advisory status as [`timestamp`], and one caller with a real need for
/// the number rather than the string: [`crate::dht::ProviderStore`] expires
/// records against it. Expiry is the one place in this crate where a clock
/// changes behaviour, and it is safe there for the reason the DHT is safe
/// generally -- being wrong costs a stale hint, never a wrong verdict.
pub fn unix_seconds() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs(),
        // A clock set before 1970. Every provider record then looks expired,
        // which degrades to "no DHT" rather than to a wrong answer.
        Err(_) => 0,
    }
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

/// The inverse of [`format_iso8601_utc`]: an RFC-3339 instant to seconds since
/// the Unix epoch, or `None` if the string is not one.
///
/// Epoch-batched commit–reveal decides whether a reveal is allowed by comparing
/// the epoch of the commitment against the epoch of the claim, and both are
/// read back out of records that are already in the log. So this is not a
/// convenience: without it there is no way to re-derive that decision during an
/// audit, and a rule an auditor cannot recheck is not a rule.
///
/// Strict on purpose. Every offset is accepted (`Z`, `+00:00`, `-05:30`) because
/// the schema promises RFC-3339 rather than this crate's own output, but a
/// month of `13`, a day of `31` in April, or a `60` in the minutes field is
/// rejected rather than normalised. Normalising would let two spellings of one
/// instant carry two different digests while meaning the same thing.
pub fn parse_rfc3339(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    // YYYY-MM-DDTHH:MM:SS is the shortest acceptable prefix.
    if bytes.len() < 19 {
        return None;
    }
    let digits = |from: usize, len: usize| -> Option<i64> {
        let slice = text.get(from..from + len)?;
        if slice.len() != len || !slice.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        slice.parse::<i64>().ok()
    };
    let at = |i: usize| -> Option<char> { bytes.get(i).map(|b| *b as char) };

    let year = digits(0, 4)?;
    if at(4)? != '-' {
        return None;
    }
    let month = digits(5, 2)?;
    if at(7)? != '-' {
        return None;
    }
    let day = digits(8, 2)?;
    // RFC-3339 permits a lowercase `t` and a space as the date/time separator.
    if !matches!(at(10)?, 'T' | 't' | ' ') {
        return None;
    }
    let hour = digits(11, 2)?;
    if at(13)? != ':' {
        return None;
    }
    let minute = digits(14, 2)?;
    if at(16)? != ':' {
        return None;
    }
    let second = digits(17, 2)?;

    let mut i = 19;
    // Fractional seconds are parsed and discarded: sub-second precision never
    // appears in a record this crate writes, and truncating toward the epoch
    // start keeps an instant inside the epoch it was actually in.
    if at(i) == Some('.') {
        i += 1;
        let start = i;
        while matches!(at(i), Some(c) if c.is_ascii_digit()) {
            i += 1;
        }
        if i == start {
            return None;
        }
    }

    let offset_minutes = match at(i) {
        Some('Z' | 'z') => {
            i += 1;
            0
        }
        Some(sign @ ('+' | '-')) => {
            let oh = digits(i + 1, 2)?;
            if at(i + 3)? != ':' {
                return None;
            }
            let om = digits(i + 4, 2)?;
            i += 6;
            if oh > 23 || om > 59 {
                return None;
            }
            let magnitude = oh * 60 + om;
            if sign == '-' {
                -magnitude
            } else {
                magnitude
            }
        }
        // A naive timestamp has no instant. Guessing UTC would make two nodes
        // in different zones settle differently for the same log.
        _ => return None,
    };
    if i != bytes.len() {
        return None;
    }

    if !(1..=9999).contains(&year) || !(1..=12).contains(&month) || day < 1 {
        return None;
    }
    if day > days_in_month(year, month) {
        return None;
    }
    // A leap second (`:60`) is refused, not normalised. The Python reference
    // (`datetime.fromisoformat`) refuses it, and both implementations walk the
    // whole log deciding which entries move the settlement anchor -- one
    // spelling accepted here and refused there is a different anchor, a
    // different beacon order, and different payouts for the same log.
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let days = days_from_civil(year, month, day);
    Some((days * 86_400 + hour * 3_600 + minute * 60 + second) - offset_minutes * 60)
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// The inverse of [`civil_from_days`], same Hinnant algorithm run backwards.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400; // [0, 399]
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1; // [0, 365]
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
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
    fn parsing_inverts_formatting_over_the_whole_supported_range() {
        // Every instant this crate can write must read back as itself; the
        // epoch comparison in commit-reveal is only sound if that holds.
        for seconds in [
            0,
            1,
            -1,
            -86_400,
            951_782_400,
            1_774_699_200,
            1_785_196_800,
            -2_203_977_600,
            253_402_300_799,
            -62_135_596_800,
        ] {
            assert_eq!(
                parse_rfc3339(&format_iso8601_utc(seconds)),
                Some(seconds),
                "round trip failed for {seconds}"
            );
        }
        // And a long sweep, one step per ~11 days, to catch a month-table slip
        // that a handful of picked instants would miss.
        let mut seconds = -62_135_596_800;
        while seconds < 253_402_300_799 - 1_000_000 {
            assert_eq!(parse_rfc3339(&format_iso8601_utc(seconds)), Some(seconds));
            seconds += 999_983;
        }
    }

    #[test]
    fn offsets_are_honoured_rather_than_ignored() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00+00:00"), Some(0));
        assert_eq!(parse_rfc3339("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(parse_rfc3339("1969-12-31T19:00:00-05:00"), Some(0));
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00.250Z"), Some(0));
    }

    #[test]
    fn impossible_and_ambiguous_instants_are_refused() {
        for bad in [
            "",
            "1970-01-01",
            // No offset: a naive timestamp names no instant.
            "1970-01-01T00:00:00",
            "1970-13-01T00:00:00Z",
            "1970-00-01T00:00:00Z",
            "1970-04-31T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "1970-01-01T24:00:00Z",
            "1970-01-01T00:60:00Z",
            // A leap second: the Python reference refuses it, so accepting it
            // here would move the settlement anchor for a log containing one.
            "1970-01-01T00:00:60Z",
            "1970-01-01T00:00:00+24:00",
            "1970-01-01T00:00:00+0000",
            "1970-01-01T00:00:00Z ",
            "1970-01-01T00:00:00.Z",
            "197a-01-01T00:00:00Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "accepted {bad:?}");
        }
        // 2000 is a leap year, so the same day in 1900 being refused above is
        // the century rule and not a blanket refusal of 29 February.
        assert!(parse_rfc3339("2000-02-29T00:00:00Z").is_some());
    }

    #[test]
    fn the_clock_produces_a_well_formed_instant() {
        let stamp = timestamp();
        assert_eq!(stamp.chars().count(), "1970-01-01T00:00:00+00:00".len());
        assert!(stamp.ends_with("+00:00"), "got {stamp:?}");
        assert!(stamp.contains('T'), "got {stamp:?}");
    }
}
