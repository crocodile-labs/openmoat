//! Best-effort removal of credential material before anything is persisted.
//!
//! The audit log records *what was attempted*, never the secret itself. Two
//! passes run over every text: the exact values of the secrets OpenMoat knows
//! ([`KnownSecrets`]) are masked first, then the patterns, which cover the token
//! formats that routinely appear in shell commands. Policy still blocks the
//! dangerous cases regardless of what is logged here.

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::{Captures, Regex, RegexBuilder};
use serde_json::Value;

use crate::StoreError;

mod judge;

const REPLACEMENT: &str = "[redacted]";

/// What replaces a pattern's match.
#[derive(Clone, Copy)]
enum Mask {
    /// A replacement string, in which `${name}` stands for a group.
    Text(&'static str),
    /// A function of the match and of the whole text it was found in.
    With(fn(&Captures<'_>, &str) -> String),
}

/// The credential words a name may hold as one `_`- or `-`-separated part.
macro_rules! credential_word {
    () => {
        r"(?:api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|token|passw(?:or)?d|authorization|private[_-]?key)"
    };
}

/// Credential patterns that run before [`TOKEN_SHAPES`], and what replaces each match.
const NAMED: &[(&str, Mask)] = &[
    // A named credential whose value is quoted, as the shell reads it: the
    // whole quoted value is masked, spaces included (`DB_PASSWORD="a b c"`).
    // The unquoted form below stops at the first space.
    (
        concat!(
            r"(?i)\b(?P<key>(?:[a-z0-9]+[_-])*",
            credential_word!(),
            r#"(?:[_-][a-z0-9]+)*\s*[=:]\s*)(?P<q>\x22)(?P<scheme>(?:bearer|basic)\s+)?(?:\\.|[^\x22\\])+(?P<e>\x22)"#
        ),
        Mask::With(judge::named_value),
    ),
    (
        concat!(
            r"(?i)\b(?P<key>(?:[a-z0-9]+[_-])*",
            credential_word!(),
            r"(?:[_-][a-z0-9]+)*\s*[=:]\s*)(?P<q>')(?P<scheme>(?:bearer|basic)\s+)?[^']+(?P<e>')"
        ),
        Mask::With(judge::named_value),
    ),
    // The same for a flag with its quoted value as the next argument.
    (
        r"(?i)(\s--?(?:[a-z0-9]+[_-])*(?:api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|token|passw(?:or)?d|private[_-]?key)\s+)\x22(?:\\.|[^\x22\\])+\x22",
        Mask::Text("${1}\"[redacted]\""),
    ),
    (
        r"(?i)(\s--?(?:[a-z0-9]+[_-])*(?:api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|token|passw(?:or)?d|private[_-]?key)\s+)'[^']+'",
        Mask::Text("${1}'[redacted]'"),
    ),
    // `-u "user:pass word"`: the quoted password, spaces included.
    (
        r"(?P<pre>(?:^|\s)(?:-u|--user)(?:\s+|=)(?P<q>['\x22]))(?P<user>[^\s:'\x22]+):(?P<pass>[^'\x22]+)['\x22]",
        Mask::With(judge::quoted_user_password),
    ),
    // Named credentials in key=value or key: value form; keep the key. The
    // credential word may be one `_`- or `-`-separated part of a longer name
    // (`AWS_SECRET_ACCESS_KEY`, `GH_TOKEN`, `access_token`), but not the start
    // of a longer word (`tokenizer`, `secretary`, `max_tokens`). A name whose
    // last part says the value is about the credential, not the credential
    // (`token_count`, `--token-file`, `private_key_path`), keeps its value.
    (
        concat!(
            r"(?i)\b(?P<key>(?:[a-z0-9]+[_-])*",
            credential_word!(),
            r"(?:[_-][a-z0-9]+)*\s*[=:]\s*)(?P<q>['\x22]?)(?P<scheme>(?:bearer|basic)\s+)?[^\s'\x22&;]+(?P<e>['\x22]?)"
        ),
        Mask::With(judge::named_value),
    ),
    // The same names as a quoted key with a quoted value, as JSON and Python
    // literals write them (`{"token": "abc"}`, `{'password': 'a b'}`).
    (
        concat!(
            r"(?i)(?P<key>['\x22](?:[a-z0-9]+[_-])*",
            credential_word!(),
            r#"(?:[_-][a-z0-9]+)*['\x22]\s*:\s*)(?P<v>\x22(?:\\.|[^\x22\\])+\x22|'(?:\\.|[^'\\])+')"#
        ),
        Mask::With(judge::quoted_value),
    ),
    // The same names as a flag with its value as the next argument
    // (`--token abc`, `--db-password abc`). The name must end in the
    // credential word, so `--password-stdin` and `--with-token < file` keep
    // what follows, and a value cannot start with `-` (the next flag).
    (
        r"(?i)(\s--?(?:[a-z0-9]+[_-])*(?:api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|token|passw(?:or)?d|private[_-]?key)\s+)(['\x22]?)[^\s'\x22&;|<>-][^\s'\x22&;|<>]*(['\x22]?)",
        Mask::Text("${1}${2}[redacted]${3}"),
    ),
    // `user:password` given to `-u` or `--user` (curl and others); a value
    // without `:` (`git push -u origin`) has no password to mask, and one
    // outside an HTTP client that is a drive path or `uid:gid` keeps it.
    (
        r"(?P<pre>(?:^|\s)(?:-u|--user)(?:\s+|=)['\x22]?)(?P<user>[^\s:'\x22]+):(?P<pass>[^\s'\x22]+)",
        Mask::With(judge::user_password),
    ),
    (
        r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9._~+/=-]{8,})",
        Mask::With(judge::bearer),
    ),
    (
        r"(?i)\bbasic\s+(?P<v>[A-Za-z0-9+/=]{8,})",
        Mask::With(judge::basic),
    ),
];

/// Well-known token formats with a vendor prefix, by name. Rarely anything
/// else, so `moat guard` also refuses a push that adds one ([`token_shape`]).
pub const TOKEN_SHAPES: &[(&str, &str)] = &[
    (
        "a GitHub token",
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b",
    ),
    ("a GitHub token", r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    (
        "an OpenAI or Anthropic key",
        r"\bsk-(?:[a-z]+-)?[A-Za-z0-9]{16,}\b",
    ),
    // Anthropic (`sk-ant-api03-…`) and OpenAI project, service-account and
    // admin keys, whose body also holds `-` and `_`.
    (
        "an OpenAI or Anthropic key",
        r"\bsk-(?:ant|proj|svcacct|admin)-[A-Za-z0-9_-]{16,}\b",
    ),
    ("an AWS access key id", r"\bAKIA[0-9A-Z]{16}\b"),
    ("a Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    ("a Google API key", r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    ("an npm token", r"\bnpm_[A-Za-z0-9]{30,}\b"),
    ("a GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
];

/// Credential patterns that run after [`TOKEN_SHAPES`]. A JSON web token is
/// masked but not in [`TOKEN_SHAPES`]: sample ones are common in test data.
const TAIL: &[(&str, Mask)] = &[
    (
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        Mask::Text(REPLACEMENT),
    ),
    // Credentials embedded in URLs.
    (r"(://[^/\s:@]+:)[^@/\s]+@", Mask::Text("${1}[redacted]@")),
];

/// Every pattern in the order it runs, with what replaces its match.
fn rules() -> impl Iterator<Item = (&'static str, Mask)> {
    let shapes = TOKEN_SHAPES
        .iter()
        .map(|(_, p)| (*p, Mask::Text(REPLACEMENT)));
    NAMED
        .iter()
        .copied()
        .chain(shapes)
        .chain(TAIL.iter().copied())
}

/// [`rules`] compiled; `None` when one does not compile, which a test rules
/// out. Every text is then redacted whole rather than masked by fewer patterns.
static PATTERNS: LazyLock<Option<Vec<(Regex, Mask)>>> = LazyLock::new(|| {
    rules()
        .map(|(pattern, replacement)| Regex::new(pattern).map(|re| (re, replacement)))
        .collect::<Result<_, _>>()
        .ok()
});

/// [`TOKEN_SHAPES`] compiled, with their names; `None` as for [`PATTERNS`].
static SHAPES: LazyLock<Option<Vec<(Regex, &'static str)>>> = LazyLock::new(|| {
    TOKEN_SHAPES
        .iter()
        .map(|(name, pattern)| Regex::new(pattern).map(|re| (re, *name)))
        .collect::<Result<_, _>>()
        .ok()
});

/// What kind of token `text` holds, if it holds one of [`TOKEN_SHAPES`]. If
/// the shapes could not be compiled, every text counts as holding one.
#[must_use]
pub fn token_shape(text: &str) -> Option<&'static str> {
    let Some(shapes) = SHAPES.as_deref() else {
        return Some("a token (the patterns could not be compiled)");
    };
    shapes
        .iter()
        .find(|(re, _)| re.is_match(text))
        .map(|(_, name)| *name)
}

/// Values shorter than this many bytes are not masked by exact match: a short
/// value (`admin`, `8080`) also occurs in ordinary text, and masking it there
/// would destroy the record. The patterns still apply to such values.
pub const MIN_SECRET_LEN: usize = 8;

/// The exact values of the secrets OpenMoat knows (the policy's brokered
/// secrets), replaced by `[redacted]` wherever they occur in any letter case,
/// whatever their format. One automaton matches them all, so masking is linear
/// in the text.
/// [`KnownSecrets::default`] knows none. `Debug` prints no value.
#[derive(Default)]
pub struct KnownSecrets(Option<Regex>);

impl std::fmt::Debug for KnownSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KnownSecrets")
    }
}

impl KnownSecrets {
    /// Mask `values`, except those shorter than [`MIN_SECRET_LEN`]. Fails only
    /// when the values are too large to match together; the error names none.
    pub fn new<'a>(values: impl IntoIterator<Item = &'a str>) -> Result<Self, StoreError> {
        let mut values: Vec<&str> = values
            .into_iter()
            .filter(|v| v.len() >= MIN_SECRET_LEN)
            .collect();
        if values.is_empty() {
            return Ok(Self(None));
        }
        // At each position the first alternative that matches wins, so a value
        // that is a prefix of another must come after it.
        values.sort_unstable_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
        values.dedup();
        let alternation = values
            .iter()
            .map(|v| regex::escape(v))
            .collect::<Vec<_>>()
            .join("|");
        // Any case: the proxy records a host lowercased, so a value sent as part
        // of a host name would otherwise slip through.
        // Not passed on: a regex error quotes its pattern, that is the values.
        RegexBuilder::new(&alternation)
            .case_insensitive(true)
            .size_limit(64 << 20)
            .build()
            .map(|re| Self(Some(re)))
            .map_err(|_| StoreError::Secrets)
    }

    /// Whether one of the known values occurs in `text`, in any letter case.
    #[must_use]
    pub fn occurs_in(&self, text: &str) -> bool {
        self.0.as_ref().is_some_and(|re| re.is_match(text))
    }

    /// [`redact`] after masking the known values. Idempotent.
    #[must_use]
    pub fn redact(&self, text: &str) -> String {
        let masked = match &self.0 {
            Some(re) => re.replace_all(text, REPLACEMENT),
            None => Cow::Borrowed(text),
        };
        mask_patterns(PATTERNS.as_deref(), masked.into_owned())
    }

    /// [`redact_value`] after masking the known values.
    #[must_use]
    pub fn redact_value(&self, value: Value) -> Value {
        match value {
            Value::String(text) => Value::String(self.redact(&text)),
            Value::Array(items) => {
                Value::Array(items.into_iter().map(|v| self.redact_value(v)).collect())
            }
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .map(|(key, item)| (key, self.redact_value(item)))
                    .collect(),
            ),
            other => other,
        }
    }
}

/// Run `patterns` over `text`; with none, nothing of `text` is kept.
fn mask_patterns(patterns: Option<&[(Regex, Mask)]>, text: String) -> String {
    let Some(patterns) = patterns else {
        return REPLACEMENT.to_owned();
    };
    patterns.iter().fold(text, |acc, (re, mask)| match mask {
        Mask::Text(replacement) => re.replace_all(&acc, *replacement).into_owned(),
        Mask::With(replace) => re
            .replace_all(&acc, |caps: &Captures<'_>| replace(caps, &acc))
            .into_owned(),
    })
}

/// Replace credential-looking substrings. Idempotent.
#[must_use]
pub fn redact(text: &str) -> String {
    KnownSecrets::default().redact(text)
}

/// Redact every string leaf of a JSON document. Used on the structured action
/// before it is serialised, so patterns see the raw text rather than
/// JSON-escaped quotes and the result is re-encoded as valid JSON.
#[must_use]
pub fn redact_value(value: Value) -> Value {
    KnownSecrets::default().redact_value(value)
}

#[cfg(test)]
mod tests;
