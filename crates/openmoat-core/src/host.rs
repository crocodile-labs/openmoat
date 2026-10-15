//! Host names in URLs and shell words: one parser for every action kind.
//!
//! A host is reported lowercase, without userinfo, port, trailing dot or IPv6
//! brackets (`http://User@[::1]:8080/` → `::1`). Net rules match that form.
//!
//! Two entry points differ only in how much evidence they need:
//! - [`of_url`]: the caller knows the text is a URL (`WebFetch`, MCP `url`
//!   arguments), so any non-empty host counts, including `localhost`,
//!   numeric forms such as `2130706433` and IPv6 literals.
//! - [`of_word`]: a shell word that may or may not be a host. With a scheme
//!   it is a URL and gets the same treatment; without one it must look like a
//!   dotted name with a known top-level domain, or an IPv4 address, so that
//!   `fix.bug` and `main.rs` stay words.

use crate::shell::tables::{FILE_EXTENSIONS, KNOWN_TLDS};

/// Host of a URL, with or without its scheme.
#[must_use]
pub fn of_url(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    authority_host(rest)
}

/// The local path a `file:` URL names (`file:///p`, `file://localhost/p`,
/// `FILE:/p`), percent-decoded, also as the value of `--opt=URL`. Programs that
/// fetch URLs (`curl`, `wget`, `git`) read that file.
#[must_use]
pub fn file_url_path(token: &str) -> Option<String> {
    let url = match token.split_once('=') {
        Some((option, value)) if option.starts_with('-') => value,
        _ => token,
    };
    let scheme = url.get(..5)?;
    if !scheme.eq_ignore_ascii_case("file:") {
        return None;
    }
    let rest = &url[5..];
    let path = match rest.strip_prefix("//") {
        Some(authority_and_path) => &authority_and_path[authority_and_path.find('/')?..],
        None => rest,
    };
    let path = path.split(['?', '#']).next().unwrap_or(path);
    (path.starts_with('/') || path.starts_with('~')).then(|| percent_decode(path))
}

/// `%2e` → `.`; a `%` not followed by two hex digits stays as it is.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if bytes[i] == b'%'
            && let (Some(hi), Some(lo)) = (
                bytes.get(i + 1).copied().and_then(hex),
                bytes.get(i + 2).copied().and_then(hex),
            )
        {
            // two hex digits: always a byte
            out.extend(u8::try_from(hi * 16 + lo).ok());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Host named by one shell word, if the word is evidently a network address.
#[must_use]
pub fn of_word(token: &str) -> Option<String> {
    match token.split_once("://") {
        Some((scheme, rest)) => {
            let valid = !scheme.is_empty()
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
            if valid { authority_host(rest) } else { None }
        }
        None if token.starts_with(['-', '.', '=']) => None,
        None => authority_host(token).filter(|h| looks_like_bare_host(h)),
    }
}

/// Host named by an argument of `program`: [`of_word`], after taking off the address
/// type `socat` puts in front of a host (`TCP:evil.com:443`, `OPENSSL:evil.com:443`).
#[must_use]
pub fn of_argument(program: &str, token: &str) -> Option<String> {
    let address = match token.split_once(':') {
        Some((kind, rest))
            if program == "socat"
                && !kind.is_empty()
                && kind.len() <= 16
                && kind.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') =>
        {
            rest
        }
        _ => token,
    };
    of_word(address)
}

/// `[userinfo@]host[:port]` up to the first `/`, `?` or `#`. `_` is kept: DNS
/// itself allows it and resolvers look such names up (`a_b.evil.com`), so a
/// rule must still see the host.
fn authority_host(rest: &str) -> Option<String> {
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    let host = if let Some(bracketed) = host_port.strip_prefix('[') {
        bracketed.split(']').next()?
    } else {
        host_port.split(':').next()?
    };
    let host = host.trim_end_matches('.');
    let valid = !host.is_empty()
        && !host.starts_with('.')
        && !host.contains("..")
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':' | '%'));
    valid.then(|| host.to_ascii_lowercase())
}

/// Without a scheme only dotted names under a known TLD and IPv4 literals count.
/// A registrable name (the last two labels) never holds `_`, so `my_pkg.io`
/// stays a word, but a subdomain may: `a_b.evil.com` is a host.
fn looks_like_bare_host(host: &str) -> bool {
    if host.contains(':') || !host.contains('.') {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.iter().rev().take(2).any(|l| l.contains('_')) {
        return false;
    }
    if labels.len() == 4 && labels.iter().all(|o| o.parse::<u8>().is_ok()) {
        return true;
    }
    let tld = labels.last().copied().unwrap_or_default();
    (2..=24).contains(&tld.len())
        && tld.chars().all(|c| c.is_ascii_alphabetic())
        && KNOWN_TLDS.contains(&tld)
        && !FILE_EXTENSIONS.contains(&tld)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_report_every_host_form() {
        for (url, host) in [
            ("https://Api.GitHub.com/x?y#z", "api.github.com"),
            ("http://user:pw@evil.com:8443/", "evil.com"),
            ("http://localhost:8080/x", "localhost"),
            ("http://intranet/x", "intranet"),
            ("http://[::1]:8080/x", "::1"),
            ("http://[FE80::1%25en0]/", "fe80::1%25en0"),
            ("http://2130706433/", "2130706433"),
            ("http://0x7f000001/", "0x7f000001"),
            ("http://127.1/", "127.1"),
            ("example.com/path", "example.com"),
            ("http://evil.com./", "evil.com"),
            ("http://my_host.com/", "my_host.com"),
        ] {
            assert_eq!(of_url(url).as_deref(), Some(host), "{url}");
            assert_eq!(of_word(url).as_deref(), Some(host), "{url}");
        }
        for url in ["https://", "http:///x", "http://..evil/", "http://a b/"] {
            assert_eq!(of_url(url), None, "{url}");
        }
    }

    #[test]
    fn bare_words_need_a_known_tld_or_ipv4() {
        for (word, host) in [
            ("prod.example.com", "prod.example.com"),
            ("deploy@prod.example.com", "prod.example.com"),
            ("10.0.0.5", "10.0.0.5"),
            ("evil.com:443", "evil.com"),
            ("a_b.evil.com", "a_b.evil.com"),
            ("x_y.co.uk", "x_y.co.uk"),
        ] {
            assert_eq!(of_word(word).as_deref(), Some(host), "{word}");
        }
        for word in [
            "localhost",
            "fix.bug",
            "main.rs",
            "sys.version",
            "a.b.c",
            "-v",
            ".env",
            "=x",
            "::1",
            "my_host.com",
            "my_pkg.io",
            "test_main.rs",
            "app.my_mod.dev",
            "1.2.3",
        ] {
            assert_eq!(of_word(word), None, "{word}");
        }
    }
}
