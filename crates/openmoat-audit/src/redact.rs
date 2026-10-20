//! Best-effort removal of credential material before anything is persisted.
//!
//! The audit log records *what was attempted*, never the secret itself. Two
//! passes run over every text: the exact values of the secrets OpenMoat knows
//! ([`KnownSecrets`]) are masked first, then the patterns, which cover the token
//! formats that routinely appear in shell commands. Policy still blocks the
//! dangerous cases regardless of what is logged here.

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::{Regex, RegexBuilder};
use serde_json::Value;

use crate::StoreError;

const REPLACEMENT: &str = "[redacted]";

/// Credential patterns that run before [`TOKEN_SHAPES`], and what replaces each match.
const NAMED: &[(&str, &str)] = &[
    // Named credentials in key=value or key: value form; keep the key. The
    // credential word may be one `_`- or `-`-separated part of a longer name
    // (`AWS_SECRET_ACCESS_KEY`, `GH_TOKEN`, `access_token`), but not the start
    // of a longer word (`tokenizer`, `secretary`, `max_tokens`).
    (
        r"(?i)\b((?:[a-z0-9]+[_-])*(?:api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|token|passw(?:or)?d|authorization|private[_-]?key)(?:[_-][a-z0-9]+)*\s*[=:]\s*)(['\x22]?)((?:bearer|basic)\s+)?[^\s'\x22&;]+(['\x22]?)",
        "${1}${2}${3}[redacted]${4}",
    ),
    // The same names as a flag with its value as the next argument
    // (`--token abc`, `--db-password abc`). The name must end in the
    // credential word, so `--password-stdin` and `--with-token < file` keep
    // what follows, and a value cannot start with `-` (the next flag).
    (
        r"(?i)(\s--?(?:[a-z0-9]+[_-])*(?:api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|token|passw(?:or)?d|private[_-]?key)\s+)(['\x22]?)[^\s'\x22&;|<>-][^\s'\x22&;|<>]*(['\x22]?)",
        "${1}${2}[redacted]${3}",
    ),
    // `user:password` given to `-u` or `--user` (curl and others); a value
    // without `:` (`git push -u origin`) has no password to mask.
    (
        r"((?:^|\s)(?:-u|--user)(?:\s+|=)['\x22]?[^\s:'\x22]+:)[^\s'\x22]+",
        "${1}[redacted]",
    ),
    (
        r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}",
        "Bearer [redacted]",
    ),
    (r"(?i)\bbasic\s+[A-Za-z0-9+/=]{8,}", "Basic [redacted]"),
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
const TAIL: &[(&str, &str)] = &[
    (
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        REPLACEMENT,
    ),
    // Credentials embedded in URLs.
    (r"(://[^/\s:@]+:)[^@/\s]+@", "${1}[redacted]@"),
];

/// Every pattern in the order it runs, with what replaces its match.
fn rules() -> impl Iterator<Item = (&'static str, &'static str)> {
    let shapes = TOKEN_SHAPES.iter().map(|(_, p)| (*p, REPLACEMENT));
    NAMED
        .iter()
        .copied()
        .chain(shapes)
        .chain(TAIL.iter().copied())
}

/// [`rules`] compiled; `None` when one does not compile, which a test rules
/// out. Every text is then redacted whole rather than masked by fewer patterns.
static PATTERNS: LazyLock<Option<Vec<(Regex, &'static str)>>> = LazyLock::new(|| {
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
fn mask_patterns(patterns: Option<&[(Regex, &str)]>, text: String) -> String {
    let Some(patterns) = patterns else {
        return REPLACEMENT.to_owned();
    };
    patterns.iter().fold(text, |acc, (re, replacement)| {
        re.replace_all(&acc, *replacement).into_owned()
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
mod tests {
    use super::{
        KnownSecrets, PATTERNS, SHAPES, TOKEN_SHAPES, mask_patterns, redact, redact_value, rules,
        token_shape,
    };
    use serde_json::json;

    #[test]
    fn every_pattern_compiles() {
        assert!(
            PATTERNS
                .as_ref()
                .is_some_and(|p| p.len() == rules().count())
        );
        assert!(
            SHAPES
                .as_ref()
                .is_some_and(|p| p.len() == TOKEN_SHAPES.len())
        );
    }

    #[test]
    fn token_shapes_are_named_and_ordinary_text_has_none() {
        assert_eq!(
            token_shape("+ key = \"AKIAIOSFODNN7EXAMPLE\""),
            Some("an AWS access key id")
        );
        assert_eq!(
            token_shape("x=ghp_abcdefghijklmnopqrstuvwxyz0123"),
            Some("a GitHub token")
        );
        for key in [
            "sk-ant-api03-FAKE_fake-0000FAKEfake0000-FAKEfake",
            "sk-proj-FAKE_fake-0000FAKEfake0000",
        ] {
            assert_eq!(
                token_shape(&format!("k={key}")),
                Some("an OpenAI or Anthropic key")
            );
            assert_eq!(redact(&format!("k={key}")), "k=[redacted]");
        }
        for text in [
            "fn main() {}",
            "token: ${{ secrets.X }}",
            "sk-short",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijkl",
        ] {
            assert_eq!(token_shape(text), None, "{text}");
        }
        let known = KnownSecrets::new([FAKE]).unwrap();
        assert!(known.occurs_in(&format!("+v={}", FAKE.to_ascii_uppercase())));
        assert!(!known.occurs_in("+v=other"));
        assert!(!KnownSecrets::default().occurs_in(FAKE));
    }

    #[test]
    fn without_patterns_nothing_is_kept() {
        let text = "export TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123".to_owned();
        assert_eq!(mask_patterns(None, text), "[redacted]");
    }

    #[test]
    fn redacts_string_leaves_of_a_document() {
        let doc = json!({"shell": {"command": "curl -H \"X-Api-Key: abc123def456\" https://x", "n": 1, "list": ["token=ghp_abcdefghijklmnopqrstuvwxyz0123"]}});
        let out = redact_value(doc);
        let text = out.to_string();
        assert!(!text.contains("abc123def456"), "{text}");
        assert!(!text.contains("ghp_abc"), "{text}");
        assert!(text.contains("X-Api-Key: [redacted]"), "{text}");
        assert_eq!(out["shell"]["n"], 1);
    }

    #[test]
    fn named_credentials_keep_their_key() {
        assert_eq!(
            redact("curl -H 'X-Api-Key: abc123def'"),
            "curl -H 'X-Api-Key: [redacted]'"
        );
        assert_eq!(
            redact("export TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123"),
            "export TOKEN=[redacted]"
        );
        assert_eq!(
            redact("password=hunter2 user=bob"),
            "password=[redacted] user=bob"
        );
    }

    #[test]
    fn credential_words_inside_longer_names() {
        for (text, want) in [
            (
                "AWS_SECRET_ACCESS_KEY=wJalrFAKEfakeKEY aws s3 ls",
                "AWS_SECRET_ACCESS_KEY=[redacted] aws s3 ls",
            ),
            (
                "GH_TOKEN=abc123 gh pr list",
                "GH_TOKEN=[redacted] gh pr list",
            ),
            ("export NPM_TOKEN='abc123'", "export NPM_TOKEN='[redacted]'"),
            (
                "DATABASE_PASSWORD=hunter2 ./run",
                "DATABASE_PASSWORD=[redacted] ./run",
            ),
            ("MY_TOKEN: abc123", "MY_TOKEN: [redacted]"),
            (
                "curl 'https://x.test/?access_token=abc123&n=1'",
                "curl 'https://x.test/?access_token=[redacted]&n=1'",
            ),
            ("tool --token=abc123", "tool --token=[redacted]"),
            ("tool --token abc123 -v", "tool --token [redacted] -v"),
            (
                "psql --db-password \"abc123\"",
                "psql --db-password \"[redacted]\"",
            ),
            (
                "curl -u alice:s3cret https://x.test",
                "curl -u alice:[redacted] https://x.test",
            ),
            (
                "curl --user=alice:s3cret x.test",
                "curl --user=alice:[redacted] x.test",
            ),
            (
                "curl --user 'alice:s3cret' x.test",
                "curl --user 'alice:[redacted]' x.test",
            ),
        ] {
            assert_eq!(redact(text), want, "{text}");
            assert_eq!(redact(want), want, "{want}");
        }
    }

    #[test]
    fn words_that_only_start_with_a_credential_word_are_kept() {
        for text in [
            "tokenizer=bpe max_tokens=100",
            "the secretary: Jane",
            "passwords are hashed",
            "gh auth login --with-token < token.txt",
            "docker login --password-stdin registry.example",
            "tool --token --verbose",
            "git push -u origin main",
            "sort -u names.txt",
        ] {
            assert_eq!(redact(text), text);
        }
    }

    #[test]
    fn well_known_token_shapes() {
        assert_eq!(redact("AKIAIOSFODNN7EXAMPLE"), "[redacted]");
        assert_eq!(
            redact("Authorization: Bearer abc.def-ghi_jkl"),
            "Authorization: Bearer [redacted]"
        );
        assert!(redact("sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX").contains("[redacted]"));
        assert_eq!(
            redact("https://user:s3cret@host.example/x"),
            "https://user:[redacted]@host.example/x"
        );
    }

    #[test]
    fn ordinary_commands_are_untouched() {
        for cmd in [
            "git status --short",
            "cargo test -p openmoat-core",
            "echo token",
            "cat ~/.ssh/id_rsa",
        ] {
            assert_eq!(redact(cmd), cmd);
        }
    }

    /// Generated for the test; no real secret is used.
    const FAKE: &str = "q7Zp-fake-9xK2mW4v";

    #[test]
    fn known_values_are_masked_whatever_their_format() {
        let known = KnownSecrets::new([FAKE, "q7Zp-fake-9xK2mW4v-longer", "short"]).unwrap();
        let text = format!("curl https://x.test/?k={FAKE}&n=1 /tmp/{FAKE}-longer/f short");
        assert_eq!(
            known.redact(&text),
            "curl https://x.test/?k=[redacted]&n=1 /tmp/[redacted]/f short"
        );
        let host = format!("http://{}.x.test:80", FAKE.to_ascii_lowercase());
        assert_eq!(known.redact(&host), "http://[redacted].x.test:80");
        let doc = known.redact_value(json!({"mcp": {"args": [FAKE]}}));
        assert_eq!(doc["mcp"]["args"][0], "[redacted]");
        assert_eq!(format!("{known:?}"), "KnownSecrets");
        assert_eq!(KnownSecrets::default().redact(FAKE), FAKE);
    }

    #[test]
    fn idempotent() {
        let once = redact("GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123");
        assert_eq!(redact(&once), once);
    }
}
