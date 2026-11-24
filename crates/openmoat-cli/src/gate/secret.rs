//! The gate's shared secret: its file, its text form (RFC 4648 base32, what
//! authenticator apps take) and the `otpauth://` URI that carries it.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use zeroize::Zeroizing;

/// The file's first line.
const HEADER: &str = "openmoat-gate-totp-v1";

/// Bytes of a new secret: 160 bits, RFC 4226 §4's recommended length.
pub const LEN: usize = 20;

/// RFC 4648's base32 alphabet.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A new random secret.
pub fn generate() -> Result<Zeroizing<Vec<u8>>> {
    let mut raw = Zeroizing::new(vec![0u8; LEN]);
    getrandom::fill(raw.as_mut_slice())
        .map_err(|e| anyhow::Error::msg(e.to_string()))
        .context("reading random bytes for the gate's secret")?;
    Ok(raw)
}

/// The file's text for `secret`.
pub fn encode_file(secret: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(format!("{HEADER}\n{}\n", base32(secret).as_str()))
}

/// The secret in the file at `path`, refused when others may read or replace
/// the file (`key_file::read`) or when it does not parse. The error names the
/// file, never its contents.
pub fn read(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let text = crate::key_file::read(path)?;
    parse(&text).with_context(|| {
        format!(
            "reading {}: the gate's secret file is not valid; run `openmoat doctor`",
            path.display()
        )
    })
}

pub(super) fn parse(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        bail!("the first line is not `{HEADER}`");
    }
    let Some(encoded) = lines.next() else {
        bail!("there is no secret line");
    };
    let secret = unbase32(encoded.trim()).context("the secret is not base32")?;
    if secret.len() < 16 {
        bail!("the secret is shorter than 128 bits");
    }
    Ok(secret)
}

/// RFC 4648 base32 of `bytes`, without padding (authenticator apps take it
/// either way, and the URI form leaves it out).
pub fn base32(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len().div_ceil(5) * 8));
    for chunk in bytes.chunks(5) {
        let mut block = [0u8; 5];
        for (slot, byte) in block.iter_mut().zip(chunk) {
            *slot = *byte;
        }
        let bits = block.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        // Each 8-bit byte gives 8/5 characters, rounded up.
        let chars = (chunk.len() * 8).div_ceil(5);
        for i in 0..chars {
            let index = (bits >> (35 - 5 * i)) & 0x1f;
            out.push(char::from(
                ALPHABET[usize::try_from(index).unwrap_or_default()],
            ));
        }
    }
    out
}

/// The bytes of base32 `text`, in either case, with or without padding and
/// with spaces (as some apps show the secret in groups); `None` when a
/// character is outside the alphabet.
pub fn unbase32(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8));
    let mut bits: u64 = 0;
    let mut count = 0u32;
    for c in text.bytes().filter(|b| !matches!(b, b' ' | b'=')) {
        let upper = c.to_ascii_uppercase();
        let value = ALPHABET.iter().position(|a| *a == upper)?;
        bits = (bits << 5) | u64::try_from(value).ok()?;
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// The `otpauth://` URI an authenticator app reads (the Key URI Format every
/// app follows): issuer OpenMoat, SHA-1, six digits, 30 seconds.
pub fn uri(secret: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "otpauth://totp/OpenMoat:policy-changes?secret={}&issuer=OpenMoat&algorithm=SHA1\
         &digits={}&period={}",
        base32(secret).as_str(),
        super::totp::DIGITS,
        super::totp::STEP_SECS
    ))
}

/// `secret`'s base32 in groups of four, easier to type into an app by hand.
pub fn grouped(secret: &[u8]) -> Zeroizing<String> {
    let plain = base32(secret);
    let mut out = Zeroizing::new(String::with_capacity(plain.len() + plain.len() / 4));
    for (i, c) in plain.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}
