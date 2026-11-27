//! Building a redaction pattern only for a text it may match.
//!
//! Building every pattern's regex took about 12 ms, most of a hook call's
//! first redaction, while most texts a call records (a session id, a path,
//! `git status`) can match none of them. Each pattern names texts one of
//! which every match holds ([`super::Rule::needs`], proved from the pattern by
//! `tests/needles.rs`); a text that holds none of them in any letter case
//! keeps what it is without the regex being built, and the regex is built the
//! first time a text does.
//!
//! The check reads ASCII only. A text with another character goes to the
//! regex: case folding equates `ſ` with `s` and the Kelvin sign with `k`,
//! which a comparison of ASCII letters would not see.

use std::sync::OnceLock;

use regex::Regex;

use super::Rule;

/// A text as the needles are compared with it: lowercased, or `None` when it
/// holds a character that is not ASCII.
pub(super) struct Folded(Option<String>);

impl Folded {
    pub(super) fn of(text: &str) -> Self {
        Self(text.is_ascii().then(|| text.to_ascii_lowercase()))
    }
}

/// A rule and its regex, built on first need.
pub(super) struct Lazy {
    pub(super) rule: Rule,
    regex: OnceLock<Option<Regex>>,
}

impl Lazy {
    pub(super) fn new(rule: Rule) -> Self {
        Self {
            rule,
            regex: OnceLock::new(),
        }
    }

    /// False only where the regex could not match `text` either: an ASCII
    /// text that holds none of the needles.
    pub(super) fn may_match(&self, text: &Folded) -> bool {
        match &text.0 {
            Some(lower) if !self.rule.needs.is_empty() => {
                self.rule.needs.iter().any(|needle| lower.contains(needle))
            }
            _ => true,
        }
    }

    /// The regex, built the first time; `None` when it does not compile.
    pub(super) fn regex(&self) -> Option<&Regex> {
        self.regex
            .get_or_init(|| Regex::new(self.rule.pattern).ok())
            .as_ref()
    }
}
