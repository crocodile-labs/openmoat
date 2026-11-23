//! A tool call's arguments as `when:` conditions read them (ADR-113): each
//! string value with the path of keys that leads to it. The core does no JSON;
//! the caller flattens what the host sent (the CLI's `arguments.rs`), and the
//! engine adds what the action itself names (a host tool's path, URL or
//! command). Bounded: past [`MAX_VALUES`] values the rest are left out and the
//! arguments are marked cut, which makes a negated condition hold.

/// The most values kept of one call's arguments.
pub const MAX_VALUES: usize = 1024;

/// The most bytes of one value kept; a longer value is cut there.
pub const MAX_VALUE_BYTES: usize = 64 * 1024;

/// One call's argument values, each under its key path (`to`, `message.to`),
/// keys in snake case.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Arguments {
    values: Vec<(String, String)>,
    cut: bool,
}

impl Arguments {
    /// No arguments.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `value` under the keys `path` (outermost first; an array's items
    /// take the key that holds the array). Past [`MAX_VALUES`] the value is
    /// left out and the arguments are marked cut.
    pub fn push(&mut self, path: &[&str], value: &str) {
        if self.values.len() >= MAX_VALUES {
            self.cut = true;
            return;
        }
        let key: Vec<String> = path.iter().map(|k| snake(k)).collect();
        let mut end = value.len().min(MAX_VALUE_BYTES);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        self.values.push((key.join("."), value[..end].to_owned()));
    }

    /// Mark the arguments as not read in full (nested too deep, not parsed).
    pub fn mark_cut(&mut self) {
        self.cut = true;
    }

    /// Whether some values were left out.
    #[must_use]
    pub fn is_cut(&self) -> bool {
        self.cut
    }

    /// Whether there are no values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The values under any of `names`, each with its key: a name matches a
    /// key that is it or ends in `.<name>`; `*` matches every key.
    pub(crate) fn values_of<'a>(
        &'a self,
        names: &'a [String],
    ) -> impl Iterator<Item = (&'a str, &'a str)> + 'a {
        self.values
            .iter()
            .filter(move |(key, _)| {
                names.iter().any(|name| {
                    name == "*"
                        || key == name
                        || key
                            .strip_suffix(name.as_str())
                            .is_some_and(|head| head.ends_with('.'))
                })
            })
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    /// Every value of `other` added to these.
    pub(crate) fn extend(&mut self, other: &Self) {
        for (key, value) in &other.values {
            if self.values.len() >= MAX_VALUES {
                self.cut = true;
                return;
            }
            self.values.push((key.clone(), value.clone()));
        }
        self.cut |= other.cut;
    }
}

/// `key` in snake case: `sourcePath`, `source-path` and `SOURCE_PATH` are all
/// `source_path`, as the MCP argument scanner spells keys.
#[must_use]
pub fn snake(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    let mut previous_lower = false;
    for c in key.chars() {
        if c == '-' {
            out.push('_');
            previous_lower = false;
        } else if c.is_ascii_uppercase() {
            if previous_lower {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
            previous_lower = false;
        } else {
            out.push(c);
            previous_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Arguments, MAX_VALUES, snake};

    #[test]
    fn keys_are_snake_case_paths_and_names_match_their_end() {
        let mut args = Arguments::new();
        args.push(&["To"], "a@example.com");
        args.push(&["message", "ccList"], "b@example.com");
        args.push(&["subject"], "hi");
        let names = |n: &[&str]| n.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let to_names = names(&["to"]);
        let to: Vec<_> = args.values_of(&to_names).collect();
        assert_eq!(to, [("to", "a@example.com")]);
        let cc_names = names(&["cc_list"]);
        let cc: Vec<_> = args.values_of(&cc_names).collect();
        assert_eq!(cc, [("message.cc_list", "b@example.com")]);
        assert_eq!(args.values_of(&names(&["*"])).count(), 3);
        assert_eq!(args.values_of(&names(&["list"])).count(), 0);
        assert_eq!(snake("sourcePath"), "source_path");
        assert_eq!(snake("SOURCE-PATH"), "source_path");
    }

    #[test]
    fn past_the_limit_values_are_cut() {
        let mut args = Arguments::new();
        for n in 0..=MAX_VALUES {
            args.push(&["v"], &n.to_string());
        }
        assert!(args.is_cut());
        assert_eq!(args.values_of(&["v".to_owned()]).count(), MAX_VALUES);
    }
}
