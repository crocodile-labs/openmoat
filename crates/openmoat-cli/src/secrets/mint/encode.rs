//! The encodings minting requests need: base64 (standard and URL-safe, for
//! JWTs and PEM), lowercase hex (`SigV4`), RFC 3986 percent-encoding (form
//! bodies) and the expiry times providers answer with.

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64_with(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        let sextets = [18, 12, 6, 0].map(|shift| alphabet[((n >> shift) & 0x3f) as usize]);
        let used = chunk.len() + 1;
        for (i, c) in sextets.iter().enumerate() {
            if i < used {
                out.push(char::from(*c));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// Standard base64 with padding (RFC 4648 §4).
pub fn base64(bytes: &[u8]) -> String {
    base64_with(bytes, STANDARD, true)
}

/// URL-safe base64 without padding (RFC 4648 §5), as JWTs use it.
pub fn base64url(bytes: &[u8]) -> String {
    base64_with(bytes, URL_SAFE, false)
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// `text` with every byte but RFC 3986's unreserved ones as `%XX`
/// (uppercase), the form both `SigV4` and OAuth form bodies need.
pub fn percent(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// A form body (`application/x-www-form-urlencoded`) of `pairs`, in order.
pub fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", percent(k), percent(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Milliseconds since the epoch of an RFC 3339 UTC time as providers write
/// it: `2026-11-23T10:15:00Z`, with or without fractional seconds, `Z` or
/// `+00:00`. `None` for any other offset or text.
pub fn expiry_ms(text: &str) -> Option<i64> {
    let text = text.trim();
    let text = text
        .strip_suffix("+00:00")
        .map_or_else(|| text.to_owned(), |t| format!("{t}Z"));
    let (whole, _) = text.strip_suffix('Z')?.split_once('.').map_or_else(
        || (text.trim_end_matches('Z').to_owned(), ""),
        |(w, f)| (w.to_owned(), f),
    );
    crate::time::parse_rfc3339(&format!("{whole}Z"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_forms_match_rfc_4648() {
        // RFC 4648's test vectors: the prefixes of `foobar`.
        for (len, std, url) in [
            (0, "", ""),
            (1, "Zg==", "Zg"),
            (2, "Zm8=", "Zm8"),
            (3, "Zm9v", "Zm9v"),
            (4, "Zm9vYg==", "Zm9vYg"),
            (5, "Zm9vYmE=", "Zm9vYmE"),
            (6, "Zm9vYmFy", "Zm9vYmFy"),
        ] {
            let raw = &"foobar"[..len];
            assert_eq!(base64(raw.as_bytes()), std, "{raw}");
            assert_eq!(base64url(raw.as_bytes()), url, "{raw}");
        }
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
        assert_eq!(base64(&[0xfb, 0xff]), "+/8=");
    }

    #[test]
    fn percent_and_form_encoding() {
        assert_eq!(percent("a b/c:d~e"), "a%20b%2Fc%3Ad~e");
        assert_eq!(
            form(&[("Action", "AssumeRole"), ("P", "{\"a\":1}")]),
            "Action=AssumeRole&P=%7B%22a%22%3A1%7D"
        );
        assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
    }

    #[test]
    fn expiry_times_in_each_providers_form() {
        let at = crate::time::parse_rfc3339("2026-11-23T10:15:00Z").unwrap();
        for text in [
            "2026-11-23T10:15:00Z",
            "2026-11-23T10:15:00.123456789Z",
            "2026-11-23T10:15:00+00:00",
            " 2026-11-23T10:15:00Z\n",
        ] {
            assert_eq!(expiry_ms(text), Some(at), "{text}");
        }
        for bad in ["2026-11-23T10:15:00+05:00", "tomorrow", ""] {
            assert_eq!(expiry_ms(bad), None, "{bad}");
        }
    }
}
