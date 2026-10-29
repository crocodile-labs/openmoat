//! Calendar days for certificate validity, from the system clock, without a
//! date library of this crate's own: rcgen takes a year, month and day.

use std::time::{SystemTime, UNIX_EPOCH};

use super::TlsError;

/// A day, as days since 1970-01-01 (UTC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Day(pub(super) i64);

/// Latest year a certificate date is written for; well inside what rcgen's
/// date type holds.
const LAST_YEAR: i64 = 9000;

impl Day {
    /// The day `time` falls on; `None` before 1970.
    pub(crate) fn of(time: SystemTime) -> Option<Self> {
        let secs = time.duration_since(UNIX_EPOCH).ok()?.as_secs();
        i64::try_from(secs / 86_400).ok().map(Self)
    }

    /// Today, by the system clock.
    pub(crate) fn today() -> Result<Self, TlsError> {
        Self::of(SystemTime::now()).ok_or(TlsError::Clock)
    }

    /// `n` days later (earlier when negative).
    pub(crate) fn add(self, n: i64) -> Result<Self, TlsError> {
        self.0.checked_add(n).map(Self).ok_or(TlsError::Clock)
    }

    /// `(year, month, day)` of the proleptic Gregorian calendar (Howard
    /// Hinnant's `civil_from_days`).
    pub(crate) fn civil(self) -> (i64, u8, u8) {
        let z = self.0 + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        // `day` is 1 to 31 and `month` 1 to 12 by construction.
        (
            year,
            u8::try_from(month).unwrap_or(1),
            u8::try_from(day).unwrap_or(1),
        )
    }

    /// `(year, month, day)` as rcgen takes them, for a year it can write.
    pub(crate) fn ymd(self) -> Result<(i32, u8, u8), TlsError> {
        let (year, month, day) = self.civil();
        if !(1970..=LAST_YEAR).contains(&year) {
            return Err(TlsError::Clock);
        }
        let year = i32::try_from(year).map_err(|_| TlsError::Clock)?;
        Ok((year, month, day))
    }
}
