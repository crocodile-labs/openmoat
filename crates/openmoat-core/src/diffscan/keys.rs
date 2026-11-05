//! Secrets by their shape: a private key, and a real-looking value in a
//! `.env` file. Known token formats with a vendor prefix are the push
//! check's scanner (`diff-secret`), which the CLI runs on every added line.
//! No value is ever put in a reason.

use super::files::{File, Kind};
use super::{Change, ENV_SECRET, Hit, Level, PRIVATE_KEY};

/// Words in a variable name that say its value is a secret.
const SECRET_WORDS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "AUTH_KEY",
    "CREDENTIAL",
];

/// Values that stand in for a secret rather than being one.
const PLACEHOLDERS: &[&str] = &[
    "xxx",
    "changeme",
    "change_me",
    "change-me",
    "your",
    "example",
    "placeholder",
    "dummy",
    "fake",
    "todo",
    "replace",
    "redacted",
    "<",
    "${",
    "$(",
    "***",
    "...",
    "none",
    "null",
    "test",
];

/// Words that mark a key as made for a test.
const FAKE_MARKERS: &[&str] = &[
    "fake",
    "dummy",
    "not a real",
    "test key",
    "test-only",
    "example key",
    "do not use",
];

/// The shortest `.env` value that looks like a real secret.
const MIN_SECRET_LEN: usize = 12;

pub(super) fn scan(file: &File, change: &Change<'_>, hits: &mut Vec<Hit>) {
    for run in change.runs() {
        let marked = run.iter().any(|(_, t)| {
            let lower = t.to_ascii_lowercase();
            FAKE_MARKERS.iter().any(|m| lower.contains(m))
        });
        for (line, text) in run {
            if let Some(kind) = private_key(text) {
                let (level, reason) = if file.test || file.is(Kind::Doc) || marked {
                    (
                        Level::Review,
                        format!(
                            "adds {kind} in a test fixture, an example or marked as fake: check \
                             it was never used for anything real"
                        ),
                    )
                } else {
                    (
                        Level::Deny,
                        format!(
                            "adds {kind}: everyone who can read the repository holds it; revoke \
                             it and remove it from the history"
                        ),
                    )
                };
                hits.push(Hit::new(PRIVATE_KEY, level, *line, reason));
            }
            if file.is(Kind::Dotenv)
                && let Some(name) = env_secret(text)
            {
                hits.push(Hit::new(
                    ENV_SECRET,
                    Level::Review,
                    *line,
                    format!(
                        "sets `{name}` to a value that looks real, in an env file the \
                         repository publishes; use a placeholder and keep the value elsewhere"
                    ),
                ));
            }
        }
    }
}

/// What kind of private key `text` starts: a PEM `BEGIN … PRIVATE KEY` header
/// (RSA, EC, DSA, `OpenSSH`, PKCS#8, encrypted, PGP) or a `PuTTY` key file.
fn private_key(text: &str) -> Option<&'static str> {
    if text.contains("PuTTY-User-Key-File-") {
        return Some("a PuTTY private key");
    }
    let (_, rest) = text.split_once("-----BEGIN ")?;
    let label = rest.split("-----").next()?;
    if label.ends_with("PRIVATE KEY") || label == "PGP PRIVATE KEY BLOCK" {
        Some("a private key")
    } else {
        None
    }
}

/// The name of `NAME=value` (or `export NAME=value`) when the name says the
/// value is a secret and the value looks like one.
fn env_secret(text: &str) -> Option<&str> {
    let t = text.trim();
    let t = t.strip_prefix("export ").unwrap_or(t);
    let (name, value) = t.split_once('=')?;
    let name = name.trim();
    let upper = name.to_ascii_uppercase();
    if name.is_empty() || name.contains(' ') || !SECRET_WORDS.iter().any(|w| upper.contains(w)) {
        return None;
    }
    let value = value.split(" #").next().unwrap_or(value).trim();
    let value = value.trim_matches(['"', '\'']);
    let lower = value.to_ascii_lowercase();
    let repeated = value.chars().all(|c| value.starts_with(c));
    let placeholder = repeated || PLACEHOLDERS.iter().any(|p| lower.contains(p));
    (value.len() >= MIN_SECRET_LEN && !placeholder).then_some(name)
}
