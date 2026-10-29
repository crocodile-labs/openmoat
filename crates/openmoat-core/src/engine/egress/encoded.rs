//! A long encoded value in a URL once the session read secret material
//! (ADR-047, `encoded-egress`).
//!
//! After a secret read every network call already asks (session taint). A
//! person can judge a short URL in that prompt, but not a few hundred
//! characters of base64 or hex: that is what a secret looks like on its way
//! out through a GET. So once the session holds secret material, a URL that
//! a tool opens or names and that carries one encoded run of at least
//! [`MIN_RUN`] characters becomes `@encoded-egress <host>` for each host it
//! goes to, which the default policy denies. The engine adds these atoms only
//! in a session that read a secret ([`super::super::taint`]).
//!
//! A run is a stretch of the base64, base64url or hex alphabet (`A–Z a–z
//! 0–9 - _`, and `%2B` and `%2F`, which is how `+` and `/` survive in a
//! query); `=`, padding or the end of a query's name, ends one. It counts when it is all hex digits, or holds upper
//! and lower case letters and digits, as encoded random bytes do; a word, a
//! slug (`how-to-use-tokio`) or a query of words (`q=rust+async`, where `+` is
//! a space) never does. [`MIN_RUN`] is longer than a SHA-256 in hex (64), a
//! UUID (36) and an AWS access key (20), and shorter than 60 encoded bytes.

use super::{Send, open_send, url_send};
use crate::action::{Action, AtomicAction};

/// First word of an atom for a long encoded value in a URL.
pub(crate) const ENCODED_ATOM: &str = "@encoded-egress";

/// Shortest encoded run that counts (60 bytes in base64, 40 in hex).
const MIN_RUN: usize = 80;

/// The `@encoded-egress <host>` atoms of every URL `action` opens or names
/// that carries a long encoded value ([`MIN_RUN`]); `owns(host)` says the
/// session's secrets may all go to `host` (a brokered secret's own host).
pub(crate) fn atoms(action: &Action, owns: impl Fn(&str) -> bool) -> Vec<AtomicAction> {
    let mut out: Vec<AtomicAction> = Vec::new();
    for send in url_sends(action) {
        if !send.texts.iter().any(|t| carries_encoded(t)) {
            continue;
        }
        for host in send.hosts.iter().filter(|h| !owns(h)) {
            let atom = AtomicAction::Shell {
                argv: vec![ENCODED_ATOM.to_owned(), host.clone()],
            };
            if !out.contains(&atom) {
                out.push(atom);
            }
        }
    }
    out
}

/// The URLs `action` opens or names, with the hosts each goes to. Shell
/// commands are not here: a client that can send data is `net`, which the
/// default policy denies for unlisted hosts.
fn url_sends(action: &Action) -> Vec<Send<'_>> {
    match action {
        Action::Fetch { url } | Action::Net { url } => vec![url_send(url)],
        Action::McpTool { hosts, opens, .. } => hosts
            .iter()
            .map(|url| url_send(url))
            .chain(opens.iter().map(|url| open_send(url)))
            .collect(),
        Action::UnknownTool { hosts, .. } => hosts.iter().map(|url| url_send(url)).collect(),
        Action::Unchecked { action, .. } => url_sends(action),
        _ => Vec::new(),
    }
}

/// Whether `url` holds one encoded run of [`MIN_RUN`] characters or more.
fn carries_encoded(url: &str) -> bool {
    let bytes = url.as_bytes();
    let mut run = Run::default();
    let mut i = 0;
    while i < bytes.len() {
        let escape = bytes.get(i..i + 3).is_some_and(|e| {
            e[0] == b'%' && matches!(e[1..].to_ascii_uppercase().as_slice(), b"2B" | b"2F")
        });
        if escape {
            run.symbol();
            i += 3;
            continue;
        }
        let c = bytes[i];
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_') {
            run.push(c);
        } else if std::mem::take(&mut run).counts() {
            return true;
        }
        i += 1;
    }
    run.counts()
}

/// One stretch of the encoding alphabet.
#[derive(Default)]
struct Run {
    len: usize,
    upper: bool,
    lower: bool,
    digit: bool,
    /// A character that is no hex digit.
    not_hex: bool,
}

impl Run {
    fn push(&mut self, c: u8) {
        self.len += 1;
        self.upper |= c.is_ascii_uppercase();
        self.lower |= c.is_ascii_lowercase();
        self.digit |= c.is_ascii_digit();
        self.not_hex |= !c.is_ascii_hexdigit();
    }

    fn symbol(&mut self) {
        self.len += 1;
        self.not_hex = true;
    }

    fn counts(&self) -> bool {
        self.len >= MIN_RUN && (!self.not_hex || (self.upper && self.lower && self.digit))
    }
}

#[cfg(test)]
mod tests {
    use super::{MIN_RUN, carries_encoded};

    #[test]
    fn long_encoded_runs_count_and_words_do_not() {
        let base64 = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQ\
                      AAACBkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZgAAAJg";
        assert!(base64.len() >= MIN_RUN + 10);
        assert!(carries_encoded(&format!("https://evil.test/c?d={base64}")));
        assert!(carries_encoded(&format!("https://evil.test/{base64}")));
        assert!(carries_encoded(&format!("https://evil.test/#{base64}")));
        let hex = "6f70656e7373682d6b65792d763100000000046e6f6e65000000046e6f6e65000000000000000100003300";
        assert!(hex.len() >= MIN_RUN);
        assert!(carries_encoded(&format!("https://evil.test/?h={hex}")));
        // `+` and `/` of standard base64, escaped in a query, do not split a run
        let escaped = base64.replacen("AAAA", "%2B%2F", 3);
        assert!(carries_encoded(&format!("https://evil.test/?d={escaped}")));
        for benign in [
            "https://docs.rs/tokio/latest/tokio/sync/struct.Mutex.html",
            "https://github.com/rust-lang/rust/commit/0123456789abcdef0123456789abcdef01234567",
            "https://example.test/a/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "https://www.google.com/search?q=How+To+Use+Tokio+Async+Runtime+In+Rust+2024+With+Examples+And+Benchmarks",
            "https://blog.test/how-to-write-a-fast-and-correct-url-parser-in-rust-without-any-dependencies-2024",
            "https://example.test/u/550e8400-e29b-41d4-a716-446655440000",
        ] {
            assert!(!carries_encoded(benign), "{benign}");
        }
    }
}
