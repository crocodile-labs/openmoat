//! The texts a value sent out stands for once its encodings are undone
//! (ADR-123): URL encoding, once or several times, zero-width characters
//! between letters, base64 and base64url, and hex with or without a `-` or
//! `:` between bytes, nested up to [`MAX_DEPTH`] layers deep. Only what decodes
//! to readable text is kept, so an image, a hash or a random id adds nothing
//! for [`crate::token`] and [`super::credentials`] to read.

/// Layers of encoding undone, one inside the other.
const MAX_DEPTH: usize = 4;
/// Shortest base64 or hex run decoded: an AWS key id (20 characters) is 28
/// in base64 and 40 in hex, a short word 16.
const MIN_RUN: usize = 16;
/// Most texts one value yields; past it the rest are not read.
const MAX_TEXTS: usize = 64;
/// Longest value read: a longer one is not decoded.
const MAX_INPUT: usize = 16 * 1024;
/// Characters that render as nothing and split a token for a reader of text.
const INVISIBLE: [char; 6] = [
    '\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{feff}', '\u{ad}',
];

/// Every text `value` stands for after undoing one or more encodings, not
/// `value` itself; empty when it holds none.
#[must_use]
pub(crate) fn decoded(value: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if value.len() > MAX_INPUT {
        return out;
    }
    let mut layer = vec![value.to_owned()];
    for _ in 0..MAX_DEPTH {
        let mut next = Vec::new();
        for text in &layer {
            for found in one_layer(text) {
                if found != value && !out.contains(&found) && out.len() < MAX_TEXTS {
                    out.push(found.clone());
                    next.push(found);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        layer = next;
    }
    out
}

/// The texts one encoding undone gives: `text` without invisible
/// characters, URL-decoded, and each long base64 or hex run decoded.
fn one_layer(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let visible: String = text.chars().filter(|c| !INVISIBLE.contains(c)).collect();
    if visible != text {
        out.push(visible);
    }
    if let Some(plain) = percent(text) {
        out.push(plain);
    }
    for run in runs(text, |b| {
        b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_')
    }) {
        // A path's `/` may split base64url values as well as be base64's own.
        let pieces = run
            .split('/')
            .filter(|p| p.len() >= MIN_RUN && p.len() < run.len());
        for piece in std::iter::once(run).chain(pieces) {
            out.extend(base64(piece).and_then(readable));
        }
    }
    for run in runs(text, |b| b.is_ascii_hexdigit() || matches!(b, b'-' | b':')) {
        out.extend(hex(run).and_then(readable));
    }
    out
}

/// `text` with every `%XX` decoded, when it has one and the result is UTF-8.
fn percent(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        let escape = bytes
            .get(i + 1..i + 3)
            .filter(|h| bytes[i] == b'%' && h.iter().all(u8::is_ascii_hexdigit));
        if let Some(h) = escape {
            out.push(hex_value(h[0]) << 4 | hex_value(h[1]));
            changed = true;
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    changed.then(|| String::from_utf8(out).ok()).flatten()
}

/// The stretches of `text` made of bytes `part` accepts, [`MIN_RUN`] long
/// or more, each with the `=` padding after it.
fn runs(text: &str, part: impl Fn(u8) -> bool) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start = None;
    for i in 0..=bytes.len() {
        let inside = bytes.get(i).is_some_and(|b| part(*b));
        match (start, inside) {
            (None, true) => start = Some(i),
            (Some(from), false) => {
                let end = i + bytes[i..].iter().take_while(|b| **b == b'=').count().min(2);
                if i - from >= MIN_RUN {
                    out.push(&text[from..end]);
                }
                start = None;
            }
            _ => {}
        }
    }
    out
}

/// The bytes of base64 or base64url `run` (padding optional); `None` for a
/// length no encoder writes or a mix of the two alphabets.
fn base64(run: &str) -> Option<Vec<u8>> {
    let body = run.trim_end_matches('=');
    let standard = body.contains(['+', '/']);
    if body.len() % 4 == 1 || (standard && body.contains(['-', '_'])) {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 2);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in body.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            _ => 63,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// The bytes of hex `run`: pairs of digits, with one `-` or `:` between
/// every pair or none at all.
fn hex(run: &str) -> Option<Vec<u8>> {
    let trimmed = run.trim_matches(['-', ':']);
    let delimited = trimmed.contains(['-', ':']);
    let digits: Vec<u8> = if delimited {
        let mut digits = Vec::new();
        for pair in trimmed.split(['-', ':']) {
            if pair.len() != 2 {
                return None;
            }
            digits.extend_from_slice(pair.as_bytes());
        }
        digits
    } else {
        trimmed.as_bytes().to_vec()
    };
    if digits.len() % 2 == 1 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    Some(
        digits
            .chunks(2)
            .map(|p| hex_value(p[0]) << 4 | hex_value(p[1]))
            .collect(),
    )
}

/// The value of a hex digit; only ever called with one.
fn hex_value(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        b'A'..=b'F' => digit - b'A' + 10,
        _ => 0,
    }
}

/// `bytes` as text, when they are UTF-8 with no control character but white
/// space: what a person or a token reader can read.
fn readable(bytes: Vec<u8>) -> Option<String> {
    let text = String::from_utf8(bytes).ok()?;
    let printable = !text.trim().is_empty()
        && text
            .chars()
            .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'));
    printable.then_some(text)
}

#[cfg(test)]
mod tests;
