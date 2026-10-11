//! Classifying IR patterns for hosts that have no project of their own.

use super::PROJECT;

/// Where an IR pattern points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spot<'a> {
    /// The project itself (`""`) or a path below it (`.git/**`).
    Project(&'a str),
    /// An absolute path or glob.
    Absolute(&'a str),
    /// A relative glob such as `**/.env`, which matches at any depth; the
    /// leading `**/` is removed.
    Anywhere(&'a str),
}

pub fn spot(pattern: &str) -> Spot<'_> {
    if pattern == PROJECT {
        return Spot::Project("");
    }
    if let Some(rest) = pattern
        .strip_prefix(PROJECT)
        .and_then(|r| r.strip_prefix('/'))
    {
        return Spot::Project(rest);
    }
    let bytes = pattern.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if pattern.starts_with('/') || drive {
        Spot::Absolute(pattern)
    } else {
        Spot::Anywhere(pattern.trim_start_matches("**/"))
    }
}

/// The project-relative write exclusion for a `.git` at any depth below the
/// project (a `gitdir:` file or a planted directory in a subdirectory), which
/// git follows like the root's own `.git`.
pub const ANY_GIT: &str = "**/.git/**";

pub fn has_glob(pattern: &str) -> bool {
    pattern.contains(['*', '?', '[', ']', '{', '}'])
}

/// `dir` for `dir/**` or `dir` when it names one literal location.
pub fn literal_tree(pattern: &str) -> Option<&str> {
    let base = pattern.strip_suffix("/**").unwrap_or(pattern);
    (!base.is_empty() && !has_glob(base)).then_some(base)
}

/// Whether `entry` lies below the directory `node`. A root (`/`, `C:/`) already
/// ends in its separator, so `/` has every absolute path below it, not `//…`.
pub fn is_below(entry: &str, node: &str) -> bool {
    let prefix = if node.ends_with('/') {
        node.to_owned()
    } else {
        format!("{node}/")
    };
    entry.len() > prefix.len() && entry.starts_with(&prefix)
}

/// A rule's positive patterns and its exclusions (without the `!`).
pub fn split(patterns: &[String]) -> (Vec<&str>, Vec<&str>) {
    let (excluded, positive): (Vec<&str>, Vec<&str>) = patterns
        .iter()
        .map(String::as_str)
        .partition(|p| p.starts_with('!'));
    let excluded = excluded.into_iter().map(|p| &p[1..]).collect();
    (positive, excluded)
}

/// A host pattern a domain list takes as written: `name` or `*.name`, whose
/// last label has a letter, so it never matches an IP address.
pub fn domain(pattern: &str) -> bool {
    let name = pattern.strip_prefix("*.").unwrap_or(pattern);
    let label = |l: &str| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    name.split('.').all(label)
        && name
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.chars().any(|c| c.is_ascii_alphabetic()))
}

/// Append `value` unless it is already there, keeping first-seen order.
pub fn push_unique(list: &mut Vec<String>, value: String) {
    if !list.contains(&value) {
        list.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spots_and_shapes() {
        assert_eq!(spot("/__moat_project__"), Spot::Project(""));
        assert_eq!(spot("/__moat_project__/.git/**"), Spot::Project(".git/**"));
        assert_eq!(
            spot("/__moat_project__x"),
            Spot::Absolute("/__moat_project__x")
        );
        assert_eq!(spot("C:/x"), Spot::Absolute("C:/x"));
        assert_eq!(spot("**/.env"), Spot::Anywhere(".env"));
        assert_eq!(literal_tree("/h/.ssh/**"), Some("/h/.ssh"));
        assert_eq!(literal_tree("/h/**/.env"), None);
        assert_eq!(split(&["a".into(), "!b".into()]), (vec!["a"], vec!["b"]));
        assert!(is_below("/h/.ssh", "/h") && is_below("/h", "/") && is_below("C:/x", "C:/"));
        assert!(!is_below("/hx", "/h") && !is_below("/h", "/h") && !is_below("/", "/"));
        for ok in ["github.com", "*.crates.io", "localhost"] {
            assert!(domain(ok), "{ok}");
        }
        for bad in [
            "169.254.*",
            "fe80:*",
            "100.100.100.200",
            "*",
            "a*.b.com",
            "::1",
        ] {
            assert!(!domain(bad), "{bad}");
        }
    }
}
