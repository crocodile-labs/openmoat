//! Absolute IR patterns written where the filesystem resolves them.
//!
//! The kernel enforces paths as they resolve, and `openmoat run` resolves the
//! paths it grants (`--write ~/.claude` is the directory `~/.claude` links to).
//! A deny rule's path is written as the policy names it, so with `~/.claude` a
//! link, `~/.claude/settings.json` lies below no grant by its text, though it
//! is the same file as `<target>/settings.json`. Every backend that compares a
//! deny with a resolved grant compares this spelling.

use std::path::Path;

/// `pattern` (an absolute glob, `!` for an exclusion) with its literal
/// directory prefix written as the filesystem resolves it, when that differs:
/// `/tmp/x/**` → `/private/tmp/x/**` on macOS, `~/.claude/settings.json` →
/// `/data/claude/settings.json` where `~/.claude` links there. The deepest
/// existing directory of the prefix is resolved; the last component is not
/// followed, as a mount over it or a deny of it would not follow it either.
/// `None` when nothing changes.
pub fn real_spelling(pattern: &str) -> Option<String> {
    let (bang, body) = match pattern.strip_prefix('!') {
        Some(rest) => ("!", rest),
        None => ("", pattern),
    };
    if !body.starts_with('/') {
        return None;
    }
    let literal_end = body.find(['*', '?', '[', '{', '\\']).unwrap_or(body.len());
    let literal = &body[..literal_end];
    let dir_end = literal.rfind('/')?;
    let mut dir = Path::new(&literal[..dir_end.max(1)]);
    loop {
        if let Ok(real) = std::fs::canonicalize(dir) {
            let (dir, real) = (dir.to_str()?, real.to_str()?.to_owned());
            if real == dir {
                return None;
            }
            // `/` resolves to itself; any other root ends without a slash.
            let rest = &body[dir.len()..];
            let real = if rest.starts_with('/') {
                real.trim_end_matches('/').to_owned()
            } else {
                real
            };
            return Some(format!("{bang}{real}{rest}"));
        }
        dir = dir.parent()?;
    }
}

/// `path`, an absolute path without globs, as [`real_spelling`] resolves it,
/// or as written when nothing changes. Only the Linux backends compare paths
/// this way; Seatbelt takes both spellings.
#[cfg(any(target_os = "linux", all(test, unix)))]
pub fn real_path(path: &str) -> String {
    real_spelling(path).unwrap_or_else(|| path.to_owned())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_linked_directory_is_written_where_it_points() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let real = root.join("real-agent");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, root.join(".agent")).unwrap();
        let at = |rel: &str| format!("{}/{rel}", root.display());
        assert_eq!(
            real_spelling(&at(".agent/settings.json")),
            Some(at("real-agent/settings.json"))
        );
        // a file that does not exist yet, below the link
        assert_eq!(
            real_spelling(&at(".agent/new/deeper.json")),
            Some(at("real-agent/new/deeper.json"))
        );
        assert_eq!(
            real_spelling(&format!("!{}", at(".agent/**"))),
            Some(format!("!{}", at("real-agent/**")))
        );
        // the link itself is not followed
        assert_eq!(real_spelling(&at(".agent")), None);
        assert_eq!(real_path(&at(".agent")), at(".agent"));
        assert_eq!(real_spelling(&at("real-agent/settings.json")), None);
        assert_eq!(real_spelling("**/.agent/settings.json"), None);
        assert_eq!(real_spelling("/"), None);
    }
}
