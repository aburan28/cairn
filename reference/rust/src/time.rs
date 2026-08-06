//! Timestamps, in `std` alone.
//!
//! Consensus-critical in one specific way: both implementations walk the log
//! deciding which entries move the settlement anchor, so a timestamp one
//! parses and the other refuses is a different anchor, a different beacon
//! order, and different payouts for the same log. The grammar is therefore
//! spelled out rather than delegated: `T`/`t`/space separator, optional
//! `.digits` fraction (truncated), `Z`/`z` or `±HH:MM` offset, nothing before
//! or after, and no leap second.

use std::time::{SystemTime, UNIX_EPOCH};

/// Now, as `2026-07-28T17:12:33+00:00`. `+00:00`, not `Z`: that is what the
/// records already in the world carry.
pub fn timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_iso8601_utc(seconds)
}

pub fn format_iso8601_utc(unix_seconds: i64) -> String {
    const MIN: i64 = -62_135_596_800;
    const MAX: i64 = 253_402_300_799;
    let unix_seconds = unix_seconds.clamp(MIN, MAX);
    let days = unix_seconds.div_euclid(86_400);
    let rest = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rest / 3600, (rest % 3600) / 60, rest % 60);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+00:00")
}

pub fn parse_rfc3339(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let digits = |from: usize, len: usize| -> Option<i64> {
        let slice = text.get(from..from + len)?;
        slice.bytes().all(|b| b.is_ascii_digit()).then_some(())?;
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
        // A naive timestamp names no instant. Guessing UTC would make two
        // nodes in different zones settle differently for the same log.
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
    // A leap second is refused, not normalised: the two implementations must
    // agree, and one accepting `:60` moves the anchor.
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
            - offset_minutes * 60,
    )
}

/// Seconds since the epoch for a record's timestamp, or a refusal. Pre-1970 is
/// refused with the unparsable: it keys a beacon, and there is no sensible
/// epoch number for a record this network could not have produced.
pub fn unix_seconds(ts: &str) -> Option<u64> {
    parse_rfc3339(ts).and_then(|seconds| u64::try_from(seconds).ok())
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

/// Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}
