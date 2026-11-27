//! A glob kept as its text, built and compiled to a matcher on first use.

use std::sync::{Arc, OnceLock};

use globset::{Glob, GlobBuilder, GlobMatcher};

use super::tail::Tail;
use super::word::cannot_fail;
use crate::policy::PolicyError;

/// Building a glob (globset's parse and its regex text) was most of compiling
/// a policy, and a hook call needs only a few of the globs a policy names
/// (ADR-132). So a glob whose text cannot fail to parse ([`cannot_fail`]) is
/// built the first time a candidate reaches its regex, or the never-widen
/// proof asks for it; every other glob is built when the policy is compiled,
/// so a bad pattern is still reported (and still fails `moat guard` closed)
/// before any decision. Compiling the regex behind the matcher cannot fail
/// (`Glob::compile_matcher` is infallible) and also waits for first use.
///
/// Before either, two checks read from the glob's own text refuse most
/// candidates: one that cannot begin as the glob's literal start does
/// (`/Users/me/.ssh/id_rsa` against `/Users/me/.hermes/{…}`), and one that
/// cannot end as the glob's literal end does (`/p/src/lib.rs` against
/// `**/.env`, `git` against `{gh,*/gh}`, [`Tail`]).
#[derive(Debug, Clone)]
pub(super) struct LazyGlob {
    text: String,
    options: Options,
    /// The ASCII text the glob starts with, up to its first `*`, `?`, `[`,
    /// `{` or `\`, which every match begins with.
    prefix: String,
    /// The text every match ends with or holds.
    tail: Tail,
    /// The glob; `None` once a build on first use failed.
    glob: OnceLock<Option<Glob>>,
    matcher: OnceLock<Option<GlobMatcher>>,
    /// For a glob built on first use: the mark of the compile it belongs to,
    /// set if its build fails.
    unbuilt: Option<Arc<Unbuilt>>,
}

/// How globset is asked to build a glob.
#[derive(Debug, Clone, Copy)]
pub(super) struct Options {
    pub(super) literal_separator: bool,
    pub(super) case_insensitive: bool,
    /// `None` keeps globset's default for the platform: an escape on Unix, a
    /// separator on Windows.
    pub(super) backslash_escape: Option<bool>,
}

impl Options {
    fn build(self, text: &str) -> Result<Glob, globset::Error> {
        let mut builder = GlobBuilder::new(text);
        builder
            .literal_separator(self.literal_separator)
            .case_insensitive(self.case_insensitive);
        if let Some(escape) = self.backslash_escape {
            builder.backslash_escape(escape);
        }
        builder.build()
    }
}

/// When a compile builds its globs ([`super::Built`]).
#[derive(Debug, Clone, Default)]
pub(crate) enum Defer {
    /// Every glob is built at once.
    #[default]
    Never,
    /// A glob whose text cannot fail to parse waits for its first use; a
    /// failure of its build anyway sets the mark.
    Safe(Arc<Unbuilt>),
    /// Every glob waits for its first use: only for tests of the mark,
    /// which no text the safe mode defers can reach.
    Every(Arc<Unbuilt>),
}

/// Set once, by the first glob of a compile whose build on first use failed:
/// that glob answered "no match" whatever list it is in, so every decision of
/// the compile is replaced by the deny a compile error gives
/// (`engine/unbuilt.rs`). globset's parser fails only on `[`, `{`, `}` or
/// `\`, which keep a glob from being deferred, so only a globset that parses
/// differently could set it.
#[derive(Debug, Default)]
pub(crate) struct Unbuilt(OnceLock<String>);

impl Unbuilt {
    /// Why the first glob that failed did not build, as a compile error says it.
    pub(crate) fn reason(&self) -> Option<&str> {
        self.0.get().map(String::as_str)
    }
}

/// The ASCII text `glob` starts with, up to its first `*`, `?`, `[`, `{` or `\`
/// or its first non-ASCII character: every match begins with it.
pub(super) fn literal_start(glob: &str) -> &str {
    let end = glob
        .find(|c: char| !c.is_ascii() || matches!(c, '*' | '?' | '[' | '{' | '\\'))
        .unwrap_or(glob.len());
    &glob[..end]
}

impl LazyGlob {
    /// The glob for `text`: built now, failing as globset does, or on first
    /// use where `defer` lets it wait.
    pub(super) fn build(
        text: &str,
        options: Options,
        defer: &Defer,
    ) -> Result<Self, globset::Error> {
        let mark = match defer {
            Defer::Safe(mark) if cannot_fail(text) => mark,
            Defer::Every(mark) => mark,
            Defer::Never | Defer::Safe(_) => {
                let glob = options.build(text)?;
                return Ok(Self::of(text, options, OnceLock::from(Some(glob)), None));
            }
        };
        Ok(Self::of(
            text,
            options,
            OnceLock::new(),
            Some(Arc::clone(mark)),
        ))
    }

    fn of(
        text: &str,
        options: Options,
        glob: OnceLock<Option<Glob>>,
        unbuilt: Option<Arc<Unbuilt>>,
    ) -> Self {
        Self {
            text: text.to_owned(),
            options,
            prefix: literal_start(text).to_owned(),
            tail: Tail::of(text),
            glob,
            matcher: OnceLock::new(),
            unbuilt,
        }
    }

    /// Whether the glob was built (or its build tried) yet.
    #[cfg(test)]
    pub(super) fn is_built(&self) -> bool {
        self.glob.get().is_some()
    }

    /// The glob, built on the first call when it was deferred. A build that
    /// fails sets the compile's mark and leaves `None`.
    fn glob(&self) -> Option<&Glob> {
        self.glob
            .get_or_init(|| match self.options.build(&self.text) {
                Ok(glob) => Some(glob),
                Err(error) => {
                    if let Some(mark) = &self.unbuilt {
                        let error = PolicyError::BadGlob {
                            pattern: self.text.clone(),
                            error,
                        };
                        // Only the first failure is kept; later ones say the same.
                        mark.0.get_or_init(|| error.to_string());
                    }
                    None
                }
            })
            .as_ref()
    }

    /// The regular expression globset matches candidates with: what the
    /// never-widen proof (`widen/proof.rs`) reads the glob as. Empty for a
    /// glob that did not build, which the proof cannot read and so reports
    /// as not proven.
    pub(super) fn regex(&self) -> &str {
        self.glob().map_or("", Glob::regex)
    }

    pub(super) fn is_match(&self, candidate: &str) -> bool {
        self.may_match(candidate)
            && self
                .tail
                .may_match(candidate, self.options.case_insensitive)
            && self.regex_match(candidate)
    }

    /// The regex's own answer, without the prefix and tail checks; "no match"
    /// for a glob that did not build.
    pub(super) fn regex_match(&self, candidate: &str) -> bool {
        self.matcher
            .get_or_init(|| self.glob().map(Glob::compile_matcher))
            .as_ref()
            .is_some_and(|matcher| matcher.is_match(candidate))
    }

    /// False only where the regex could not match either: an ASCII character
    /// of the candidate that differs from the prefix's at its place (ignoring
    /// ASCII case when the glob does), or a candidate shorter than the prefix.
    /// A non-ASCII character, which case folding may equate with an ASCII one
    /// (`K` KELVIN SIGN with `k`), or a `\`, which a path matcher may read as a
    /// separator, leaves it to the regex.
    fn may_match(&self, candidate: &str) -> bool {
        let case_insensitive = self.options.case_insensitive;
        let mut chars = candidate.chars();
        for want in self.prefix.chars() {
            let Some(c) = chars.next() else {
                return false;
            };
            if !c.is_ascii() || c == '\\' {
                return true;
            }
            if c != want && !(case_insensitive && c.eq_ignore_ascii_case(&want)) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests;
