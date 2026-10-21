//! Replacements that look at what a pattern matched before masking it, so a
//! credential-looking word that holds no credential keeps its value. Each one
//! masks unless the match is plainly harmless: when in doubt, redact.

use regex::Captures;

use super::REPLACEMENT;

/// Last parts of a name that make its value something about a credential (how
/// many, where it is kept, what kind), not the credential itself:
/// `token_count`, `--token-file`, `password_file`, `private_key_path`.
const NOT_SECRET_PARTS: &[&str] = &[
    "count", "file", "path", "dir", "name", "id", "len", "length", "size", "type", "url",
];

/// Programs whose `-u`/`--user` is `user:password` for an HTTP server.
const HTTP_CLIENTS: &[&str] = &["curl", "wget", "http", "https", "xh", "xhs", "curlie"];

/// Commands that run the next word as the program (`sudo curl …`).
const RUNNERS: &[&str] = &["sudo", "env", "command", "exec", "time", "nohup"];

/// Words that follow `Bearer` or `Basic` in prose about the schemes, never a
/// credential (`bearer authentication`, `Basic credentials`).
const PROSE: &[&str] = &[
    "according",
    "authentication",
    "authorisation",
    "authorization",
    "credential",
    "credentials",
    "endpoint",
    "endpoints",
    "followed",
    "middleware",
    "password",
    "passwords",
    "protocol",
    "provided",
    "required",
    "requires",
    "response",
    "security",
    "specified",
    "standard",
    "strategy",
];

/// The text of group `name`, empty when it did not take part in the match.
fn group<'h>(caps: &Captures<'h>, name: &str) -> &'h str {
    caps.name(name).map_or("", |m| m.as_str())
}

fn whole<'h>(caps: &Captures<'h>) -> &'h str {
    caps.get(0).map_or("", |m| m.as_str())
}

/// Whether the last `_`- or `-`-separated part of `name` is one of
/// [`NOT_SECRET_PARTS`].
fn names_no_secret(name: &str) -> bool {
    let name = name.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    let last = name.rsplit(['_', '-']).next().unwrap_or(name);
    name != last && NOT_SECRET_PARTS.contains(&last.to_ascii_lowercase().as_str())
}

/// `key=value` and `key: value`: the value is masked, the key and quotes kept.
pub(super) fn named_value(caps: &Captures<'_>, _: &str) -> String {
    let key = group(caps, "key");
    if names_no_secret(key.trim_end_matches(|c: char| c.is_whitespace() || c == '=' || c == ':')) {
        return whole(caps).to_owned();
    }
    format!(
        "{key}{}{}{REPLACEMENT}{}",
        group(caps, "q"),
        group(caps, "scheme"),
        group(caps, "e"),
    )
}

/// `"key": "value"`: the quoted value is masked, the key and quotes kept.
pub(super) fn quoted_value(caps: &Captures<'_>, _: &str) -> String {
    let key = group(caps, "key");
    let name = key.trim_end_matches(|c: char| c.is_whitespace() || c == ':');
    if names_no_secret(name) {
        return whole(caps).to_owned();
    }
    let quote = group(caps, "v").chars().next().unwrap_or('"');
    format!("{key}{quote}{REPLACEMENT}{quote}")
}

/// The program of the command that the text before a match ends in, by its
/// file name, lowercased and without `.exe`.
fn program_before(before: &str) -> String {
    let segment = before
        .rsplit([';', '|', '&', '\n', '('])
        .next()
        .unwrap_or(before);
    let word = segment
        .split_whitespace()
        .find(|w| !w.contains('=') && !RUNNERS.contains(w))
        .unwrap_or_default();
    let name = word.rsplit(['/', '\\']).next().unwrap_or(word);
    let name = name.to_ascii_lowercase();
    name.strip_suffix(".exe").map(str::to_owned).unwrap_or(name)
}

/// `-u user:password` and `--user=user:password`. Outside an HTTP client, a
/// drive path (`python -u C:\x`) or `uid:gid` (`docker run -u 1000:1000`) is
/// kept; everything else with a `:` is taken for a password.
pub(super) fn user_password(caps: &Captures<'_>, text: &str) -> String {
    let user = group(caps, "user");
    let pass = group(caps, "pass");
    let start = caps.get(0).map_or(0, |m| m.start());
    let http = HTTP_CLIENTS.contains(&program_before(&text[..start]).as_str());
    let drive = user.len() == 1
        && user.chars().all(|c| c.is_ascii_alphabetic())
        && pass.starts_with(['\\', '/']);
    let ids = [user, pass]
        .iter()
        .all(|p| p.chars().all(|c| c.is_ascii_digit()));
    if !http && (drive || ids) {
        return whole(caps).to_owned();
    }
    format!("{}{user}:{REPLACEMENT}", group(caps, "pre"))
}

/// Whether the word after a scheme name is prose rather than a credential.
fn prose(caps: &Captures<'_>) -> bool {
    let value = group(caps, "v");
    value.chars().all(|c| c.is_ascii_alphabetic())
        && PROSE.contains(&value.to_ascii_lowercase().as_str())
}

/// `Bearer <token>`, unless the word after `bearer` is prose.
pub(super) fn bearer(caps: &Captures<'_>, _: &str) -> String {
    if prose(caps) {
        whole(caps).to_owned()
    } else {
        format!("Bearer {REPLACEMENT}")
    }
}

/// `Basic <credentials>`, unless the word after `basic` is prose.
pub(super) fn basic(caps: &Captures<'_>, _: &str) -> String {
    if prose(caps) {
        whole(caps).to_owned()
    } else {
        format!("Basic {REPLACEMENT}")
    }
}
