//! Time-based one-time codes as RFC 6238 defines them over RFC 4226's HOTP,
//! with the parameters every authenticator app takes by default: HMAC-SHA-1,
//! 30-second steps, six digits.
//!
//! SHA-1 here is HOTP's MAC, not a hash anything is identified by: RFC 4226
//! §A.4 shows its use in HMAC is not weakened by SHA-1's collisions, and the
//! apps people have expect it. `ring` names the algorithm
//! `HMAC_SHA1_FOR_LEGACY_USE_ONLY` for that reason.

use ring::hmac;

/// Seconds per step (RFC 6238's `X`).
pub const STEP_SECS: u64 = 30;

/// Digits of a code.
pub const DIGITS: u32 = 6;

/// The steps either side of the current one a code is still taken from: a
/// phone clock 30 seconds off, or a code typed as it changed.
pub const SKEW: u64 = 1;

/// RFC 4226's HOTP value of `counter`, `digits` long.
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let mac = tag.as_ref();
    // Dynamic truncation (RFC 4226 §5.3): the low four bits of the last byte
    // say where the four bytes start; SHA-1's 20 bytes always hold them.
    let offset = usize::from(mac.last().copied().unwrap_or_default() & 0x0f);
    let word = mac
        .get(offset..offset + 4)
        .and_then(|w| <[u8; 4]>::try_from(w).ok())
        .unwrap_or_default();
    (u32::from_be_bytes(word) & 0x7fff_ffff) % 10u32.pow(digits)
}

/// The step `unix_secs` falls in (RFC 6238's `T`, with `T0` = 0).
pub fn step(unix_secs: u64) -> u64 {
    unix_secs / STEP_SECS
}

/// The six-digit code of `step`, zero-padded as the apps show it.
pub fn code(secret: &[u8], step: u64) -> String {
    format!(
        "{:0width$}",
        hotp(secret, step, DIGITS),
        width = DIGITS as usize
    )
}

/// Why a typed code is not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Nothing was typed (end of input, no terminal).
    Missing,
    /// Not six digits.
    Malformed,
    /// No code of the steps around now.
    Wrong,
    /// The code of a step already used, or of one before it.
    Replayed,
}

impl Refusal {
    /// The words the error and the audit row use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "no code was typed",
            Self::Malformed => "the code is not six digits",
            Self::Wrong => "the code is wrong",
            Self::Replayed => "the code was already used",
        }
    }
}

/// The step whose code `typed` is, among the steps within [`SKEW`] of
/// `now_secs`, when it is later than `last_step`: each code is taken once,
/// and never after a later one.
pub fn check(secret: &[u8], typed: &str, now_secs: u64, last_step: u64) -> Result<u64, Refusal> {
    let typed = typed.trim();
    if typed.is_empty() {
        return Err(Refusal::Missing);
    }
    if typed.len() != DIGITS as usize || !typed.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refusal::Malformed);
    }
    let now = step(now_secs);
    let mut matched = None;
    // Every step is compared, whichever matches, so the time taken does not
    // say which one did.
    for candidate in now.saturating_sub(SKEW)..=now.saturating_add(SKEW) {
        if same(code(secret, candidate).as_bytes(), typed.as_bytes()) && matched.is_none() {
            matched = Some(candidate);
        }
    }
    match matched {
        None => Err(Refusal::Wrong),
        Some(step) if step <= last_step => Err(Refusal::Replayed),
        Some(step) => Ok(step),
    }
}

/// Whether `a` and `b` are equal, in time that depends only on their length.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
