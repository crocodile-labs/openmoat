//! Hex and base64 (RFC 4648 §4, standard alphabet, padded) for checkpoints.
//!
//! Signed notes carry their root hash, key and signatures in base64. Both
//! codecs are a few lines; a crate for them would be the only new one the
//! checkpoints need. Decoding is strict: a character outside the alphabet,
//! missing padding or set bits in the padding are refused, so one value has
//! one spelling.

use std::fmt::Write as _;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `bytes` as lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// The bytes lowercase hex `text` spells, exactly `N` of them.
pub(crate) fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(digits.as_chunks::<2>().0) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        *byte = (high << 4) | low;
    }
    Some(out)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// `bytes` in base64.
pub(crate) fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> shift) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The bytes base64 `text` spells; `None` unless it is canonical base64.
pub(crate) fn unbase64(text: &str) -> Option<Vec<u8>> {
    let chars = text.as_bytes();
    if !chars.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(chars.len() / 4 * 3);
    let quads = chars.len() / 4;
    for (q, quad) in chars.as_chunks::<4>().0.iter().enumerate() {
        let last = q + 1 == quads;
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &quad[..4 - pad] {
            n = (n << 6) | u32::from(sextet(c)?);
        }
        n <<= 6 * u32::try_from(pad).ok()?;
        let [_, b0, b1, b2] = n.to_be_bytes();
        let bytes = [b0, b1, b2];
        let keep = 3 - pad;
        // Bits the padding drops must be zero: one value, one spelling.
        if bytes[keep..].iter().any(|&b| b != 0) {
            return None;
        }
        out.extend_from_slice(&bytes[..keep]);
    }
    Some(out)
}

fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
