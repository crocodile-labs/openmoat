//! Time helpers: UTC formatting for output and parsing of `--since` windows.
//! No external crates; the kernel's time needs are small and must stay cheap.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};

const SECS_PER_DAY: i64 = 86_400;
const MS_PER_HOUR: i64 = 3_600_000;
const MS_PER_DAY: i64 = 24 * MS_PER_HOUR;

#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// `HH:MM:SS` in UTC.
#[must_use]
pub fn clock(ts_ms: i64) -> String {
    let secs = ts_ms.div_euclid(1000).rem_euclid(SECS_PER_DAY);
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// `YYYY-MM-DD HH:MM:SS UTC`.
#[must_use]
pub fn timestamp(ts_ms: i64) -> String {
    format!(
        "{} {} UTC",
        date(ts_ms.div_euclid(1000).div_euclid(SECS_PER_DAY)),
        clock(ts_ms)
    )
}

/// The start of the UTC day `days` days before `ts_ms`, in RFC 3339
/// (`2026-10-11T00:00:00Z`), the form npm and uv read.
#[must_use]
pub fn day_start_before(ts_ms: i64, days: u16) -> String {
    let day = ts_ms.div_euclid(MS_PER_DAY) - i64::from(days);
    format!("{}T00:00:00Z", date(day))
}

/// A span as `24h`, `2h 5m` or `45m`, rounded down to the minute.
#[must_use]
pub fn duration(ms: i64) -> String {
    let minutes = ms.max(0) / 60_000;
    match (minutes / 60, minutes % 60) {
        (0, m) => format!("{m}m"),
        (h, 0) => format!("{h}h"),
        (h, m) => format!("{h}h {m}m"),
    }
}

/// Parse a window start: `all`, `today`, `yesterday`, `<n>h`, `<n>d`, `<n>w`,
/// or a UTC date `YYYY-MM-DD`. Returns milliseconds since the epoch.
pub fn parse_since(text: &str, now_ms: i64) -> Result<i64> {
    let text = text.trim().to_ascii_lowercase();
    let today_start = now_ms.div_euclid(MS_PER_DAY) * MS_PER_DAY;
    match text.as_str() {
        "all" => return Ok(0),
        "today" => return Ok(today_start),
        "yesterday" => return Ok(today_start - MS_PER_DAY),
        _ => {}
    }
    if let Some((n, unit)) = text
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map(|(i, _)| text.split_at(i))
        && let Ok(n) = n.parse::<i64>()
    {
        let unit_ms = match unit {
            "h" => MS_PER_HOUR,
            "d" => MS_PER_DAY,
            "w" => 7 * MS_PER_DAY,
            _ => 0,
        };
        if unit_ms > 0 && n > 0 {
            return Ok(now_ms - n.saturating_mul(unit_ms));
        }
    }
    if let Some(days) = parse_date(&text) {
        return Ok(days * MS_PER_DAY);
    }
    bail!(
        "cannot parse `{text}` as a time window; use all, today, yesterday, 12h, 7d, 2w or YYYY-MM-DD"
    )
}

/// Civil date for a day count since 1970-01-01 (Howard Hinnant's algorithm).
fn date(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// `YYYY-MM-DD` → days since 1970-01-01.
fn parse_date(text: &str) -> Option<i64> {
    let mut parts = text.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OCT_3_2026: i64 = 1_790_985_600_000;

    #[test]
    fn formats_utc() {
        assert_eq!(timestamp(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(timestamp(OCT_3_2026), "2026-10-03 00:00:00 UTC");
        assert_eq!(clock(90_061_000), "01:01:01");
        let afternoon = OCT_3_2026 + 15 * MS_PER_HOUR;
        assert_eq!(day_start_before(afternoon, 7), "2026-09-26T00:00:00Z");
        assert_eq!(day_start_before(afternoon, 0), "2026-10-03T00:00:00Z");
    }

    #[test]
    fn formats_durations() {
        assert_eq!(duration(MS_PER_DAY), "24h");
        assert_eq!(duration(2 * MS_PER_HOUR + 5 * 60_000 + 59_999), "2h 5m");
        assert_eq!(duration(59_999), "0m");
        assert_eq!(duration(-1), "0m");
    }

    #[test]
    fn parses_windows() {
        let now = OCT_3_2026 + 5 * MS_PER_HOUR;
        assert_eq!(parse_since("all", now).unwrap(), 0);
        assert_eq!(parse_since("today", now).unwrap(), OCT_3_2026);
        assert_eq!(
            parse_since("yesterday", now).unwrap(),
            OCT_3_2026 - MS_PER_DAY
        );
        assert_eq!(parse_since("12h", now).unwrap(), now - 12 * MS_PER_HOUR);
        assert_eq!(parse_since("7d", now).unwrap(), now - 7 * MS_PER_DAY);
        assert_eq!(parse_since("2W", now).unwrap(), now - 14 * MS_PER_DAY);
        assert_eq!(parse_since("2026-10-03", now).unwrap(), OCT_3_2026);
        assert_eq!(parse_since("1970-01-02", now).unwrap(), MS_PER_DAY);
        for bad in ["", "soon", "0h", "3x", "2026-13-01", "2026-10-03T00:00"] {
            assert!(parse_since(bad, now).is_err(), "{bad}");
        }
    }

    #[test]
    fn date_round_trips() {
        for days in [0, 1, 59, 60, 365, 20_000, 20_729] {
            assert_eq!(parse_date(&date(days)), Some(days));
        }
    }
}
