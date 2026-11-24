//! Base64 text a PowerShell line decodes and runs: `-EncodedCommand`, whose
//! value is base64 of UTF-16LE text, and the quoted literals a
//! `[Convert]::FromBase64String(…)` line names, UTF-16LE or UTF-8.

/// Longest decoded text read: a longer one stays unread.
const MAX_DECODED: usize = 64 * 1024;

/// The bytes of standard base64 (`+/`, padding optional); `None` for any
/// other character or a length no encoder writes.
fn decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim().trim_end_matches('=');
    if text.len() % 4 == 1 || text.len() / 4 * 3 > MAX_DECODED {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 2);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for b in text.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
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

/// Text that is printable or white space, nothing else.
fn readable(text: &str) -> bool {
    !text.trim().is_empty()
        && text
            .chars()
            .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
}

/// The text `-EncodedCommand`'s value stands for: base64 of UTF-16LE.
pub(super) fn utf16le_base64(value: &str) -> Option<String> {
    let bytes = decode(value)?;
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes(*p))
        .collect();
    String::from_utf16(&units).ok().filter(|t| readable(t))
}

/// The text of every quoted base64 literal of 16 characters or more in a line
/// that calls `FromBase64String`, read as UTF-16LE or UTF-8.
pub(super) fn base64_literals(line: &str) -> Vec<String> {
    if !line.to_ascii_lowercase().contains("frombase64string") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for quote in ['\'', '"'] {
        for (i, piece) in line.split(quote).enumerate() {
            if i % 2 == 0 || piece.len() < 16 {
                continue;
            }
            let text = utf16le_base64(piece).or_else(|| {
                decode(piece)
                    .and_then(|b| String::from_utf8(b).ok())
                    .filter(|t| readable(t))
            });
            if let Some(text) = text
                && !out.contains(&text)
            {
                out.push(text);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{base64_literals, decode, utf16le_base64};

    #[test]
    fn decodes_what_powershell_encodes() {
        assert_eq!(decode("Y2F0").as_deref(), Some(&b"cat"[..]));
        assert_eq!(decode("Y2E=").as_deref(), Some(&b"ca"[..]));
        // `[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('echo hi'))`
        assert_eq!(
            utf16le_base64("ZQBjAGgAbwAgAGgAaQA=").as_deref(),
            Some("echo hi")
        );
        assert_eq!(utf16le_base64("not base64!"), None);
        assert_eq!(utf16le_base64("Y2F0"), None);
    }

    #[test]
    fn reads_the_literals_a_decoding_line_names() {
        let line = "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('UmVtb3ZlLUl0ZW0gfg==')))";
        assert_eq!(base64_literals(line), vec!["Remove-Item ~".to_owned()]);
        assert_eq!(
            base64_literals("echo 'UmVtb3ZlLUl0ZW0gfg=='"),
            Vec::<String>::new()
        );
    }
}
