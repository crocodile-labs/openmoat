//! Where a search tool's glob pattern reaches when its `..` segments climb out
//! of the directory it is searched from.

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
    use super::glob_climb;

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
