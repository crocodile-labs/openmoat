//! Whether a policy's patterns compile, without compiling them: what the
//! policy lint asks of every pattern ([`crate::RuleGroup::check_patterns`]).
//!
//! The lint used to build every glob, and building one (globset's parse and
//! its regex text) was most of the cost of loading the policy in each hook
//! process; the engine builds them again for its context. Here a glob is built
//! only when it may fail to parse ([`super::word::cannot_fail`]) and the
//! policy has not already shown the same text to parse. The answer, and the
//! error for the first pattern that does not compile, are what compiling gives.

use std::collections::HashSet;

use super::word::{WordGlob, cannot_fail};
use super::{GlobPattern, ShellPattern, split_negation};
use crate::policy::PolicyError;

/// The texts one lint found to parse: globs and shell words that may fail but
/// did not, so a text the policy repeats (`{moat,openmoat}` opens 19 shell
/// patterns of the default policy) is built once. Only successes are kept,
/// so the first error is reported where it always was.
#[derive(Debug, Default)]
pub(crate) struct Checked {
    globs: HashSet<String>,
    words: HashSet<String>,
}

impl GlobPattern {
    /// [`Self::compile`]'s answer without the pattern. Whether a glob parses
    /// does not depend on case folding, so this holds for either.
    pub(crate) fn check(raw: &str, checked: &mut Checked) -> Result<(), PolicyError> {
        let (_, body) = split_negation(raw);
        if body.is_empty() {
            return Err(PolicyError::EmptyPattern);
        }
        if cannot_fail(body) || checked.globs.contains(raw) {
            return Ok(());
        }
        Self::compile(raw, false)?;
        checked.globs.insert(raw.to_owned());
        Ok(())
    }
}

impl ShellPattern {
    /// [`Self::compile`]'s answer without the pattern, word by word in the
    /// same order.
    pub(crate) fn check(raw: &str, checked: &mut Checked) -> Result<(), PolicyError> {
        let (_, words, _) = Self::words(raw)?;
        for word in words {
            if word == "*" || cannot_fail(&word) || checked.words.contains(&word) {
                continue;
            }
            WordGlob::new(&word).map_err(|e| PolicyError::BadGlob {
                pattern: raw.to_owned(),
                error: e,
            })?;
            checked.words.insert(word);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Checked;
    use crate::pattern::{GlobPattern, ShellPattern};

    /// The check reports exactly what compiling reports, valid or not, the
    /// first time and when the same text comes again.
    #[test]
    fn check_answers_as_compile_does() {
        let globs = [
            "/a/**",
            "!/a/**",
            "",
            "!",
            "**/.env",
            "/a/{b,c}",
            "/a/{b",
            "/a/b}",
            "[z-a]",
            "a\\",
            "/x/[ab]/**",
            "/x/{a/**",
            "*.pem",
            "é/*",
        ];
        let mut checked = Checked::default();
        for g in globs.iter().chain(&globs) {
            assert_eq!(
                format!("{:?}", GlobPattern::check(g, &mut checked)),
                format!("{:?}", GlobPattern::compile(g, false).map(drop)),
                "{g}"
            );
        }
        let shells = [
            "git push --force*",
            "!find * -exec*",
            "",
            "$",
            "env $",
            "{gh,*/gh} auth token*",
            "{gh,*/gh} auth status",
            "x {a",
            "x [z-a] {b",
            "cat <<EOF",
            "echo 'unclosed",
            "x a\\\\b",
            "* | sh",
        ];
        let mut checked = Checked::default();
        for s in shells.iter().chain(&shells) {
            assert_eq!(
                format!("{:?}", ShellPattern::check(s, &mut checked)),
                format!("{:?}", ShellPattern::compile(s).map(drop)),
                "{s}"
            );
        }
    }
}
