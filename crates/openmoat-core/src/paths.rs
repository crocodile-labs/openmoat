//! Path normalisation without touching the filesystem (docs/POLICY.md §3.2).
//!
//! All paths are handled in a slash-separated canonical form on every platform:
//! `/Users/me/x` on Unix, `C:/Users/me/x` or `//server/share/x` on Windows.
//! Callers convert OS paths to this form (`\` → `/`) before passing them in.
//! Symlink resolution needs I/O and is done by the caller through
//! [`crate::realpath::PathResolver`]; the engine checks both paths.

/// Expand `~`, `$HOME`, `${project}` and make the path absolute against `cwd`,
/// then collapse `.` and `..` lexically. Without a project, `${project}` expands
/// to nothing, as an unset shell variable does.
///
/// A path that depends on a directory nobody knows here (`~-`, the shell's
/// previous directory) is taken literally, relative to `cwd`; shell words go
/// through [`resolve`] instead, which refuses it.
#[must_use]
pub fn normalise(raw: &str, home: &str, project: Option<&str>, cwd: &str) -> String {
    // `resolve` returns `None` for a shell-only form (`~-`) or a `~<otheruser>`
    // path OpenMoat cannot place; keep the raw-under-cwd fallback so a direct
    // host-side `fs.read` of `~alice/.ssh/id_rsa` still has an atom to check (the
    // guarded suffix is intact; a rule naming `~alice` matches as written, and
    // a shell token with it needs review through `unparseable` via `resolve`).
    resolve(raw, home, project, Some(cwd)).unwrap_or_else(|| collapse(&under(cwd, raw)))
}

/// `rel` below the directory `dir`. A root (`/`, `C:/`) already ends in its
/// separator: `/` and `x` are `/x`, not `//x`, which is a UNC path naming the
/// server `x`.
fn under(dir: &str, rel: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{rel}")
    } else {
        format!("{dir}/{rel}")
    }
}

/// `normalise` for a word a shell will expand, against a working directory
/// that may be unknown (`None`). `None` when the result depends on a directory
/// that is not known: a relative path and an unknown `cwd`, `~-`, or a `~name`
/// of another user (OpenMoat cannot know where other users' homes live, so a
/// cross-user path is unresolvable; a shell token with it needs review through
/// `unparseable`).
#[must_use]
pub fn resolve(raw: &str, home: &str, project: Option<&str>, cwd: Option<&str>) -> Option<String> {
    absolute(raw, home, project, cwd).map(|s| collapse(&s))
}

/// The absolute form of `raw` with its `..` segments kept, when it has one
/// (`c/../.ssh/id_rsa` in `/p` is `/p/c/../.ssh/id_rsa`). [`resolve`] collapses
/// `..` against the name before it, but the OS steps up from where that name
/// really points: through `ln -s ~/.config c`, `c/..` is the home directory, not
/// the project. The engine resolves this form with [`crate::realpath::physical`]
/// and checks where it lands as well as the collapsed path.
#[must_use]
pub fn traversal(
    raw: &str,
    home: &str,
    project: Option<&str>,
    cwd: Option<&str>,
) -> Option<String> {
    absolute(raw, home, project, cwd).filter(|s| has_dotdot(s))
}

/// Whether `path` has a `..` segment.
#[must_use]
pub fn has_dotdot(path: &str) -> bool {
    path.split('/').any(|seg| seg == "..")
}

/// [`resolve`] before `.` and `..` are collapsed.
fn absolute(raw: &str, home: &str, project: Option<&str>, cwd: Option<&str>) -> Option<String> {
    let unified = raw.replace('\\', "/");
    // The home and project are spliced in with the same `/` the rest of the
    // path gets, so `~/x` and the home's own spelling name one path.
    let slashed_home = home.replace('\\', "/");
    let expanded = match dir_stack_tilde(&unified) {
        Some(('+', rest)) => format!("{}{rest}", cwd?),
        Some(_) => return None,
        None => expand_home(&unified, home, &slashed_home)?,
    };
    let mut s = expanded
        .replace(
            "${project}",
            &project.unwrap_or_default().replace('\\', "/"),
        )
        .replace("${HOME}", &slashed_home)
        .replace("$HOME", &slashed_home);
    // `$PWD` is the working directory, when it is known
    if s.contains("$PWD") || s.contains("${PWD}") {
        let dir = cwd?;
        s = s.replace("${PWD}", dir).replace("$PWD", dir);
    }
    if is_absolute(&s) {
        Some(s)
    } else {
        Some(under(cwd?, &s))
    }
}

/// Whether `raw` still names a variable after the ones [`resolve`] expands
/// in a shell word (`HOME`, `PWD`), or holds the output of a command (`$( … )`,
/// backticks): the shell replaces it with a value the path itself does not
/// show, so the path is not known (`cat $d/id_rsa`, `cat $(cat list)`).
#[must_use]
pub fn has_unexpanded_variable(raw: &str) -> bool {
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_';
    if raw.contains("$(") || raw.contains('`') {
        return true;
    }
    raw.match_indices('$').any(|(pos, _)| {
        let rest = &raw[pos + 1..];
        let (body, braced) = match rest.strip_prefix('{') {
            Some(b) => (b, true),
            None => (rest, false),
        };
        let end = body.find(|c: char| !is_name(c)).unwrap_or(body.len());
        let name = &body[..end];
        if name.is_empty() || !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
            // `$1`, `$$`, `$?` and a lone `$` are positional or special: unknown
            // too, except a bare `$` that starts no expansion (`a$`, `$/`)
            return braced
                || body.starts_with(|c: char| c.is_ascii_digit() || "@*#?$!-".contains(c));
        }
        // `${project}` is the policy's syntax; in a shell word it is a variable
        let known = matches!(name, "HOME" | "PWD");
        !(known && (!braced || body[end..].starts_with('}')))
    })
}

/// `~+` (the working directory) and `~-` (the previous one), alone or before
/// `/`: the sign and the rest of the word.
fn dir_stack_tilde(raw: &str) -> Option<(char, &str)> {
    let rest = raw.strip_prefix('~')?;
    let sign = rest.chars().next().filter(|c| matches!(c, '+' | '-'))?;
    let rest = &rest[1..];
    (rest.is_empty() || rest.starts_with('/')).then_some((sign, rest))
}

/// Absolute in canonical form: `/…`, `X:/…`, or UNC `//…`.
#[must_use]
pub fn is_absolute(path: &str) -> bool {
    path.starts_with('/') || drive_prefix(path).is_some()
}

/// `C:` for `C:/x`, `C:x` or `c:\x`; `None` otherwise.
fn drive_prefix(path: &str) -> Option<&str> {
    let bytes = path.as_bytes();
    (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':').then(|| &path[..2])
}

/// Lexically collapse `//`, `/./` and `/../` segments while preserving the root
/// (`/`, `C:/` or `//server`).
#[must_use]
pub fn collapse(path: &str) -> String {
    let (root, rest) = split_root(path);
    let mut out: Vec<&str> = Vec::new();
    for seg in rest.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    format!("{root}{}", out.join("/"))
}

/// The root of a canonical path (`/`, `C:/` or `//server/`) and the rest.
pub(crate) fn split_root(path: &str) -> (String, &str) {
    if let Some(drive) = drive_prefix(path) {
        let rest = &path[2..];
        let root = format!("{}:/", drive[..1].to_ascii_uppercase());
        return (root, rest.trim_start_matches('/'));
    }
    if let Some(unc) = path.strip_prefix("//") {
        let (server, rest) = unc.split_once('/').unwrap_or((unc, ""));
        return (format!("//{server}/"), rest);
    }
    ("/".to_owned(), path.trim_start_matches('/'))
}

/// Expand `~` and `${project}` inside a *pattern* (not a path), leaving globs intact.
///
/// `None` when the pattern names `${project}` and there is no project: such a
/// pattern names no location, so it can match nothing (and exclude nothing).
///
/// The home and the project are spliced in as literal text ([`glob_literal`]):
/// a project at `/w/a*b` makes `${project}/**` name `/w/a*b` and what is in
/// it, not `/w/aXb`.
#[must_use]
pub fn expand_pattern(raw: &str, home: &str, project: Option<&str>) -> Option<String> {
    let (negated, body) = crate::pattern::split_negation(raw);
    // A pattern naming another user's home (`~alice/.ssh/**`) stays literal:
    // paths are normalised through `resolve`, which refuses `~<otheruser>`
    // (#400), so such a pattern names no reachable path. Keep the raw text so
    // the pattern is still a well-formed glob and the lint still sees it.
    let body = expand_home(body, home, &glob_literal(home)).unwrap_or_else(|| body.to_owned());
    let expanded = match project {
        Some(project) => body.replace("${project}", &glob_literal(project)),
        None if body.contains("${project}") => return None,
        None => body,
    };
    Some(if negated {
        format!("!{expanded}")
    } else {
        expanded
    })
}

/// Characters a policy glob reads as syntax: wildcards, classes and
/// alternations (`,` only inside `{…}`, but a directory may be spliced there).
const GLOB_SYNTAX: [char; 7] = ['*', '?', '[', ']', '{', '}', ','];

/// The directory `dir` (a home, project, moved or resolved directory) as glob
/// text that matches exactly the paths it names.
///
/// Each glob character becomes a one-character class (`*` → `[*]`, `[` → `[[]`,
/// `]` → `[]]`): globset reads a class the same whether `\` escapes (Unix) or
/// separates (Windows), so the text means one thing on every platform. A `\`
/// becomes `/`, as it does in every path the engine checks ([`normalise`]): a
/// Windows path written with `\` is the same path with `/`, and on Unix a
/// directory named `a\b` is checked as `a/b`, the spelling its paths have once
/// normalised. A directory without these characters is returned unchanged.
#[must_use]
pub fn glob_literal(dir: &str) -> String {
    let mut out = String::with_capacity(dir.len());
    for c in dir.chars() {
        match c {
            '\\' => out.push('/'),
            c if GLOB_SYNTAX.contains(&c) => {
                out.push('[');
                out.push(c);
                out.push(']');
            }
            c => out.push(c),
        }
    }
    out
}

/// Expand a leading `~` or `~name`, as a POSIX shell does — safely.
///
/// `~` is `home`. `~name` is `home` when `name` is the last component of
/// `home` (the current user). Any other `~name` is unresolvable: homes do not
/// always sit side by side (`/root`, `/srv/<name>`, networked homes), so a
/// guessed `/<parent-of-home>/<name>` can judge one path while the OS reads
/// another (#400). Return `None` for that case; the caller maps it to `review`
/// through `unparseable`. A leading `~` that is not followed by a valid login
/// name (`~a$b`) stays literal (`Some(raw)`). `spliced` is the text that
/// stands for `home`: the home itself in a path, [`glob_literal`] of it in a
/// pattern.
fn expand_home(raw: &str, home: &str, spliced: &str) -> Option<String> {
    let Some((name, tail)) = home_prefix(raw) else {
        return Some(raw.to_owned());
    };
    let (_parent, user) = home.rsplit_once('/').unwrap_or(("", home));
    if name.is_empty() || name == user {
        Some(format!("{spliced}{tail}"))
    } else {
        // Another user's home — unresolvable from inside the pure core.
        None
    }
}

/// Whether `raw` starts with `~name` of a user other than the one `home` belongs to.
pub(crate) fn other_user_home(raw: &str, home: &str) -> bool {
    let user = home.rsplit_once('/').map_or(home, |(_, user)| user);
    home_prefix(raw).is_some_and(|(name, _)| !name.is_empty() && name != user)
}

/// `~` or `~name` followed by nothing or `/…`: the name (empty for `~`) and
/// the rest of the word.
fn home_prefix(raw: &str) -> Option<(&str, &str)> {
    let rest = raw.strip_prefix('~')?;
    let (name, tail) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let login = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    (login && !name.starts_with('-')).then_some((name, tail))
}

/// Heuristic: does this shell token look like a filesystem path?
///
/// Besides the obvious prefixes, a token counts as a path when it traverses
/// (`src/../x`, `a/..`) or names a hidden entry (`.env`, `config/.env.local`,
/// `.ssh/id_rsa`): those are the relative forms that reach secrets, and a
/// bare `cat .env` must produce a file-read atom. Plain `a/b` tokens do not
/// qualify, so branch names, MIME types and `owner/repo` stay unclassified.
#[must_use]
pub fn looks_like_path(token: &str) -> bool {
    if token.contains("://") {
        return false;
    }
    token.starts_with('/')
        || home_prefix(token).is_some()
        || dir_stack_tilde(token).is_some()
        || token.starts_with("./")
        || token.starts_with("../")
        || token.starts_with(".\\")
        || token.starts_with("..\\")
        || token.starts_with("$HOME/")
        || token.starts_with("${HOME}/")
        || token.starts_with("${project}/")
        || drive_prefix(token)
            .is_some_and(|_| matches!(token.as_bytes().get(2), Some(b'/' | b'\\')))
        || token.starts_with("\\\\")
        || traverses(token)
        || names_hidden_entry(token)
}

fn traverses(token: &str) -> bool {
    token == ".."
        || token
            .split(['/', '\\'])
            .enumerate()
            .any(|(i, seg)| seg == ".." && (i > 0 || token.len() > 2))
}

/// A segment such as `.env` or `.ssh` (not `.`, `..`, or a number like `.5`).
fn names_hidden_entry(token: &str) -> bool {
    token.split(['/', '\\']).any(|seg| {
        seg.len() > 1
            && seg != ".."
            && seg.starts_with('.')
            && !seg[1..].chars().all(|c| c.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_unix_paths() {
        assert_eq!(
            normalise("~/.ssh/id_rsa", "/Users/me", Some("/p"), "/p"),
            "/Users/me/.ssh/id_rsa"
        );
        assert_eq!(
            normalise("src/../.env", "/Users/me", Some("/p"), "/p/app"),
            "/p/app/.env"
        );
        assert_eq!(normalise("${project}/x", "/h", Some("/p"), "/c"), "/p/x");
        assert_eq!(
            normalise("$HOME/.aws/credentials", "/h", Some("/p"), "/c"),
            "/h/.aws/credentials"
        );
        // from the root, a relative path is below `/`, not a `//server` path
        assert_eq!(
            normalise("Users/me/.ssh/id_rsa", "/Users/me", None, "/"),
            "/Users/me/.ssh/id_rsa"
        );
        assert_eq!(
            resolve("./etc/x", "/h", None, Some("/")).as_deref(),
            Some("/etc/x")
        );
        assert_eq!(normalise("x", "/h", None, "C:/"), "C:/x");
        assert_eq!(collapse("/a//b/./c/../d"), "/a/b/d");
        assert_eq!(collapse("/../x"), "/x");
    }

    #[test]
    fn project_patterns_match_nothing_without_a_project() {
        assert_eq!(
            expand_pattern("!${project}/.git/**", "/h", Some("/p")).as_deref(),
            Some("!/p/.git/**")
        );
        assert_eq!(expand_pattern("${project}/**", "/h", None), None);
        assert_eq!(
            expand_pattern("~/.ssh/**", "/h", None).as_deref(),
            Some("/h/.ssh/**")
        );
        assert_eq!(normalise("${project}/x", "/h", None, "/c"), "/x");
    }

    /// A spliced directory is literal under both readings of `\` globset has
    /// (escape on Unix, separator on Windows): its text holds no `\`.
    #[test]
    fn spliced_directories_are_literal_on_every_platform() {
        assert_eq!(glob_literal("/Users/me/src/app"), "/Users/me/src/app");
        assert_eq!(glob_literal("C:/Users/me"), "C:/Users/me");
        assert_eq!(glob_literal(r"C:\Users\me"), "C:/Users/me");
        assert_eq!(glob_literal("/a*b?[c]{d,e}"), "/a[*]b[?][[]c[]][{]d[,]e[}]");
        for (home, own, near) in [
            ("/Users/a*b", "/Users/a*b/.ssh/k", "/Users/aXb/.ssh/k"),
            ("/Users/a?b", "/Users/a?b/.ssh/k", "/Users/aXb/.ssh/k"),
            ("/Users/a[x]b", "/Users/a[x]b/.ssh/k", "/Users/axb/.ssh/k"),
            ("/Users/a[!x]b", "/Users/a[!x]b/.ssh/k", "/Users/ayb/.ssh/k"),
            ("/Users/a]b", "/Users/a]b/.ssh/k", "/Users/ab/.ssh/k"),
            (
                "/Users/a{x,y}b",
                "/Users/a{x,y}b/.ssh/k",
                "/Users/axb/.ssh/k",
            ),
            ("/Users/a}b", "/Users/a}b/.ssh/k", "/Users/ab/.ssh/k"),
            ("/Users/a b", "/Users/a b/.ssh/k", "/Users/ab/.ssh/k"),
            (r"/Users/a\b", "/Users/a/b/.ssh/k", "/Users/ab/.ssh/k"),
            ("C:/Users/a*b", "C:/Users/a*b/.ssh/k", "C:/Users/aXb/.ssh/k"),
        ] {
            let spelled = expand_pattern("~/.ssh/**", home, None).unwrap();
            for backslash_escape in [true, false] {
                let glob = globset::GlobBuilder::new(&spelled)
                    .literal_separator(true)
                    .backslash_escape(backslash_escape)
                    .build()
                    .unwrap()
                    .compile_matcher();
                assert!(glob.is_match(own), "{spelled} {own} {backslash_escape}");
                assert!(!glob.is_match(near), "{spelled} {near} {backslash_escape}");
            }
        }
        // in an alternation, a spliced `,` or `}` does not split or close it
        let spelled = expand_pattern("{${project}/a,${project}/b}", "/h", Some("/w/p,}q")).unwrap();
        let glob = globset::Glob::new(&spelled).unwrap().compile_matcher();
        assert!(glob.is_match("/w/p,}q/a") && glob.is_match("/w/p,}q/b"));
        assert!(!glob.is_match("/w/p") && !glob.is_match("q/a"));
    }

    #[test]
    fn tilde_names_a_home_directory() {
        let n = |raw: &str| normalise(raw, "/Users/me", Some("/p"), "/p/app");
        assert_eq!(n("~me/.ssh/id_rsa"), "/Users/me/.ssh/id_rsa");
        assert_eq!(n("~me"), "/Users/me");
        // `~<otheruser>` is unresolvable from the pure core (#400): the parent-of-
        // home heuristic assumed every home sits next to the current user's, which
        // is false on common layouts. `normalise` falls back to the literal word
        // under `cwd`; the shell path (`resolve`) returns `None` and the shell
        // token needs review through `unparseable`.
        assert_eq!(n("~alice/.ssh/id_rsa"), "/p/app/~alice/.ssh/id_rsa");
        assert_eq!(n("~+/x"), "/p/app/x");
        assert_eq!(n("~+"), "/p/app");
        assert_eq!(n("a/~me"), "/p/app/a/~me", "only a leading tilde expands");
        assert_eq!(n("~a$b/x"), "/p/app/~a$b/x", "not a login name");
        assert_eq!(
            normalise("~bob/x", "C:/Users/me", None, "C:/p"),
            "C:/p/~bob/x"
        );
        let r = |raw: &str| resolve(raw, "/Users/me", Some("/p"), Some("/p/app"));
        assert_eq!(
            r("~-/.ssh/id_rsa"),
            None,
            "the previous directory is unknown"
        );
        assert_eq!(r("~-"), None);
        assert_eq!(r("~-x/y").as_deref(), Some("/p/app/~-x/y"));
        assert_eq!(
            r("~alice/.ssh/id_rsa"),
            None,
            "another user's home is unresolvable (#400)"
        );
        assert_eq!(r("~alice"), None);
        assert_eq!(resolve("src", "/h", None, None), None);
        assert_eq!(
            resolve("/etc/hosts", "/h", None, None).as_deref(),
            Some("/etc/hosts")
        );
        assert_eq!(resolve("~+/x", "/h", None, None), None);
        for token in ["~me/.ssh/id_rsa", "~alice", "~+/x", "~-", "~"] {
            assert!(looks_like_path(token), "{token}");
        }
        for token in ["~a$b", "x~y"] {
            assert!(!looks_like_path(token), "{token}");
        }
    }

    #[test]
    fn normalises_windows_paths() {
        let home = "C:/Users/me";
        assert_eq!(
            normalise("~/.ssh/id_rsa", home, Some("C:/p"), "C:/p"),
            "C:/Users/me/.ssh/id_rsa"
        );
        assert_eq!(
            normalise(r"C:\p\src\main.rs", home, Some("C:/p"), "C:/p"),
            "C:/p/src/main.rs"
        );
        assert_eq!(
            normalise(r"src\lib.rs", home, Some("C:/p"), "C:/p"),
            "C:/p/src/lib.rs"
        );
        assert_eq!(normalise("c:/P/../q", home, Some("C:/p"), "C:/p"), "C:/q");
        assert_eq!(
            normalise(r"\\server\share\f.txt", home, Some("C:/p"), "C:/p"),
            "//server/share/f.txt"
        );
        assert!(is_absolute("D:/x") && is_absolute("//srv/s") && !is_absolute("x/y"));
    }

    #[test]
    fn path_heuristics() {
        for token in [
            "/etc/passwd",
            "~/.ssh",
            "./a",
            "../a",
            r"C:\x",
            "D:/y",
            r".\x",
            r"\\srv\s",
        ] {
            assert!(looks_like_path(token), "{token}");
        }
        for token in ["main.rs", "C:", "https://x", "-v", "ab/cd"] {
            assert!(!looks_like_path(token), "{token}");
        }
    }

    #[test]
    fn relative_forms_that_reach_secrets_are_paths() {
        for token in [
            ".env",
            ".env.production",
            "config/.env.local",
            ".ssh/id_rsa",
            "src/../../.ssh/id_rsa",
            "a/..",
            "..",
            r"src\..\.env",
        ] {
            assert!(looks_like_path(token), "{token}");
        }
        for token in [
            "origin/main",
            "application/json",
            "owner/repo",
            ".",
            ".5",
            "s/foo/bar/",
            "https://x/.env",
            "fix.bug",
        ] {
            assert!(!looks_like_path(token), "{token}");
        }
    }
}
