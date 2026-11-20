//! `openmoat run`'s environment settings: whether it passes on the whole
//! environment it is started from or only an allowlist (`sandbox.env`,
//! ADR-105), and the form of a name a person may add to that allowlist
//! (ADR-077): a name, never a value or a pattern, so nothing can be written
//! that lets every variable through.

use serde::{Deserialize, Serialize};

/// `sandbox.env` (ADR-105): what `openmoat run` passes on of the environment
/// it is started from. Absent, the default, which is [`RunEnv::DEFAULT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunEnv {
    /// Every inherited variable, a brokered secret's excepted.
    Inherited,
    /// Only the allowlist: a base every program needs, the agent's own names
    /// from its spec, `sandbox.env_allow` and `--env`.
    Scrubbed,
}

impl RunEnv {
    /// What `openmoat run` does when no policy says and no flag asks.
    pub const DEFAULT: Self = Self::Inherited;
}

/// Why `name` cannot be added to the allowlist; `None` when it can. A name is
/// a letter or `_`, then letters, digits and `_`.
#[must_use]
pub fn env_name_problem(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        return Some("must not be empty");
    }
    if name.contains('=') {
        return Some("must be a name, not `NAME=value`");
    }
    if name.contains(['*', '?', '[', ']']) {
        return Some("must be a plain name, not a pattern");
    }
    let mut chars = name.chars();
    let starts_well = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    if starts_well && chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        None
    } else {
        Some("must be letters, digits and `_`, not starting with a digit")
    }
}

#[cfg(test)]
mod tests {
    use super::env_name_problem;

    #[test]
    fn plain_names_are_accepted() {
        for name in ["PATH", "_", "MY_VAR_2", "lower"] {
            assert_eq!(env_name_problem(name), None, "{name}");
        }
    }

    #[test]
    fn values_patterns_and_junk_are_refused() {
        for name in [
            "", "A=b", "*", "AWS_*", "A?", "[A]", "1A", "A-B", "A B", "A.B",
        ] {
            assert!(env_name_problem(name).is_some(), "{name}");
        }
    }
}
