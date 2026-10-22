//! Where a search tool's glob pattern reaches when its `..` segments climb out
//! of the directory it is searched from.

use openmoat_core::Action;

/// Where a glob `pattern` with `..` reaches: for a relative pattern, where it
/// climbs out of the directory it is searched from, relative to that
/// directory (`../../x`); for an absolute one, the directory it lands in.
/// `None` when it has no `..` or stays below its search directory. Glob
/// libraries walk a `..` after a wildcard too (`*/../..`): a segment with a
/// wildcard matches one directory that the `..` undoes, and `**` may match
/// none, so the highest directory the pattern can reach is taken, up to its
/// first wildcard left over (the whole path when none is).
fn glob_climb(pattern: &str) -> Option<String> {
    const WILD: &str = "*";
    let root = if pattern.starts_with(['/', '\\']) {
        "/"
    } else if pattern == "~" || pattern.starts_with("~/") || pattern.starts_with("~\\") {
        "~/"
    } else if pattern.as_bytes().get(1) == Some(&b':')
        && pattern.as_bytes()[0].is_ascii_alphabetic()
    {
        &pattern[..2]
    } else {
        ""
    };
    if !pattern.contains("..") {
        return None;
    }
    let mut stack: Vec<&str> = Vec::new();
    let rest = pattern[root.len().min(pattern.len())..].trim_start_matches(['/', '\\']);
    for seg in rest.split(['/', '\\']) {
        // A segment that may expand to `..` (`{..,x}`) climbs as `..` does.
        let seg = if seg.contains("..") { ".." } else { seg };
        match seg {
            "" | "." | "**" => {}
            ".." => match stack.last() {
                Some(&last) if last != ".." => {
                    stack.pop();
                }
                // `..` at a filesystem root is the root; at `~` it is above it.
                _ if root == "/" || root.ends_with(':') => {}
                _ => stack.push(".."),
            },
            s if s.contains(['*', '?', '[', '{']) => stack.push(WILD),
            s => stack.push(s),
        }
    }
    let end = stack.iter().position(|s| *s == WILD).unwrap_or(stack.len());
    let reached = stack[..end].join("/");
    match root {
        "" => reached.starts_with("..").then_some(reached),
        "~/" => Some(format!("~/{reached}")),
        drive if drive.ends_with(':') => Some(format!("{drive}/{reached}")),
        _ => Some(format!("/{reached}")),
    }
}

/// Whether how far `pattern` reaches cannot be worked out by [`glob_climb`]:
/// a brace group (`{a,b}`) holding a separator, a `..` or another brace group,
/// or a bracket expression (`[…]`) holding a separator. Glob libraries expand
/// braces before they walk (Gemini CLI's npm `glob` does), so such a group may
/// name a path that climbs further than its segment shows (`{x/../..,y}`).
pub(crate) fn reach_unknown(pattern: &str) -> bool {
    let mut braces = 0_usize;
    let mut bracket = false;
    let mut previous = '\0';
    for c in pattern.chars() {
        match c {
            '/' | '\\' if braces > 0 || bracket => return true,
            '.' if braces > 0 && previous == '.' => return true,
            '{' if braces > 0 => return true,
            '{' if !bracket => braces += 1,
            '}' if !bracket => braces = braces.saturating_sub(1),
            '[' if braces == 0 => bracket = true,
            ']' => bracket = false,
            _ => {}
        }
        previous = c;
    }
    false
}

/// `action`, asking at least when one of `patterns` reaches where OpenMoat
/// cannot work out ([`reach_unknown`]): what it reads is then not all checked.
pub(crate) fn bounded<'a>(action: Action, patterns: impl IntoIterator<Item = &'a str>) -> Action {
    let mut patterns = patterns.into_iter();
    match patterns.find(|p| reach_unknown(p)) {
        Some(pattern) => Action::unchecked(
            action,
            format!(
                "the glob pattern `{pattern}` holds a brace or bracket group that may reach \
                 further than OpenMoat can work out"
            ),
        ),
        None => action,
    }
}

/// `dir` joined with the relative `rel`.
pub(crate) fn below(dir: &str, rel: &str) -> String {
    format!("{}/{rel}", dir.trim_end_matches(['/', '\\']))
}

/// [`glob_climb`] for `pattern` searched from `root`, as a path to check.
pub(crate) fn glob_reach(root: &str, pattern: &str) -> Option<String> {
    let reach = glob_climb(pattern)?;
    Some(if reach.starts_with("..") {
        below(root, &reach)
    } else {
        reach
    })
}

#[cfg(test)]
mod tests {
    use super::{glob_climb, reach_unknown};

    /// A brace group with a separator, a `..` or a nested group, or a bracket
    /// expression with a separator, reaches where no segment shows.
    #[test]
    fn groups_that_may_climb_are_unknown() {
        for pattern in [
            "{x/../..,y}/.ssh/*",
            "{..,x}/.ssh/*",
            "src/{a,{b,c}}/*",
            "a[/]b/*",
            "{a\\..\\..,b}",
            "~/{.config/../.ssh,x}/*",
        ] {
            assert!(reach_unknown(pattern), "{pattern}");
        }
        for pattern in [
            "src/**/*.{rs,toml}",
            "../x/*.rs",
            "*.[ch]",
            "{a,b}/c/*",
            "{.github,.gitlab}/*",
            "docs/[!.]*",
        ] {
            assert!(!reach_unknown(pattern), "{pattern}");
        }
    }

    /// A `..` after a wildcard undoes the directory the wildcard matched, and
    /// `**` may match none, so the highest directory reachable is checked.
    #[test]
    fn glob_patterns_climb_through_wildcards() {
        for (pattern, reach) in [
            ("src/**/*.rs", None),
            ("../x/*.rs", Some("../x")),
            ("*/../../Users/me/.ssh/*", Some("../Users/me/.ssh")),
            ("**/../../.ssh/id_rsa", Some("../../.ssh/id_rsa")),
            ("{..,x}/.ssh/*", Some("../.ssh")),
            ("a*/../b/*", None),
            (
                "/p/*/../../Users/me/.ssh/id_rsa",
                Some("/Users/me/.ssh/id_rsa"),
            ),
            ("/../../etc/*", Some("/etc")),
            ("~/x/*/../../.ssh/*", Some("~/.ssh")),
            ("~/../other/*", Some("~/../other")),
            ("C:/p/*/../../x", Some("C:/x")),
            ("/p/src/*.rs", None),
        ] {
            assert_eq!(glob_climb(pattern).as_deref(), reach, "{pattern}");
        }
    }
}
