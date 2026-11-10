//! The form of an environment variable name a person may add to
//! `openmoat run`'s allowlist (ADR-077): a name, never a value or a pattern,
//! so nothing can be written that lets every variable through.

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
