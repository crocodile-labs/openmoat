//! A glob parsed eagerly and compiled to a matcher on first use.

use std::sync::OnceLock;

use globset::{Glob, GlobMatcher};

use super::tail::Tail;

/// Parsing a glob is what can fail, so it happens when the policy is compiled
/// and a bad pattern is still reported (and still fails `moat guard` closed)
/// before any decision. Building the regex behind the matcher cannot fail
/// (`Glob::compile_matcher` is infallible) but is the expensive part: a hook
/// call consults only the patterns for the kinds its action touches, so the
/// rest are never built. Of those, a candidate that cannot begin as the
/// glob's literal start does (`/Users/me/.ssh/id_rsa` against
/// `/Users/me/.hermes/{…}`) is refused without building it, so a policy
/// with more patterns does not make each call build more regexes. So is one
/// that cannot end as the glob's literal end does (`/p/src/lib.rs` against
/// `**/.env`, `git` against `{gh,*/gh}`, [`Tail`]).
#[derive(Debug, Clone)]
pub(super) struct LazyGlob {
    glob: Glob,
    /// The ASCII text the glob starts with, up to its first `*`, `?`, `[`,
    /// `{` or `\`, which every match begins with.
    prefix: String,
    /// The text every match ends with or holds.
    tail: Tail,
    case_insensitive: bool,
    matcher: OnceLock<GlobMatcher>,
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
    pub(super) fn new(glob: Glob, case_insensitive: bool) -> Self {
        let prefix = literal_start(glob.glob()).to_owned();
        let tail = Tail::of(glob.glob());
        Self {
            glob,
            prefix,
            tail,
            case_insensitive,
            matcher: OnceLock::new(),
        }
    }

    /// The regular expression globset matches candidates with: what the
    /// never-widen proof (`widen/proof.rs`) reads the glob as.
    pub(super) fn regex(&self) -> &str {
        self.glob.regex()
    }

    pub(super) fn is_match(&self, candidate: &str) -> bool {
        self.may_match(candidate)
            && self.tail.may_match(candidate, self.case_insensitive)
            && self.regex_match(candidate)
    }

    /// The regex's own answer, without the prefix and tail checks.
    pub(super) fn regex_match(&self, candidate: &str) -> bool {
        self.matcher
            .get_or_init(|| self.glob.compile_matcher())
            .is_match(candidate)
    }

    /// False only where the regex could not match either: an ASCII character
    /// of the candidate that differs from the prefix's at its place (ignoring
    /// ASCII case when the glob does), or a candidate shorter than the prefix.
    /// A non-ASCII character, which case folding may equate with an ASCII one
    /// (`K` KELVIN SIGN with `k`), or a `\`, which a path matcher may read as a
    /// separator, leaves it to the regex.
    fn may_match(&self, candidate: &str) -> bool {
        let mut chars = candidate.chars();
        for want in self.prefix.chars() {
            let Some(c) = chars.next() else {
                return false;
            };
            if !c.is_ascii() || c == '\\' {
                return true;
            }
            if c != want && !(self.case_insensitive && c.eq_ignore_ascii_case(&want)) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use globset::GlobBuilder;

    use super::LazyGlob;

    fn glob(pattern: &str, case_insensitive: bool) -> LazyGlob {
        let built = GlobBuilder::new(pattern)
            .literal_separator(true)
            .case_insensitive(case_insensitive)
            .build()
            .unwrap();
        LazyGlob::new(built, case_insensitive)
    }

    /// The prefix and tail checks never change a verdict: for every pattern
    /// and candidate, in both case modes, the answer is the regex's own.
    #[test]
    fn the_prefix_check_agrees_with_the_regex() {
        let patterns = [
            "/Users/me/.ssh/**",
            "/Users/me/.ssh",
            "/Users/me/.hermes/{auth.json,mcp-tokens,mcp-tokens/**,profiles/*/auth.json}",
            "/Users/me/.local/share/opencode/{auth.json,opencode*.db*}",
            "/Users/me/.kube/**",
            "/Users/me/.aws/credentials",
            "**/.env",
            "**/.env.*",
            "*.pem",
            "/Users/me/projects/[a-c]*/x",
            "/Users/me/esc\\*aped",
            "C:/Users/me/.ssh/**",
            "/",
            "",
            // ends and holds the tail check reads
            "**/.git/hooks/**",
            "**/.git/hooks",
            "**/{.envrc,.env.*}",
            "**/{a,**/b}",
            "{gh,*/gh}",
            "**/*.{pem,key}",
            "**/sécret/key",
            "**/sécret",
            "**/[}]x",
            "**/a\\}",
            "**/a/**/b/**",
        ];
        let candidates = [
            "/Users/me/.ssh/id_rsa",
            "/users/ME/.SSH/id_rsa",
            "/Users/me/.ssh",
            "/Users/me/.ss",
            "/Users/me",
            "",
            "/",
            "/Users/me/.hermes/auth.json",
            "/Users/me/.hermes/profiles/work/auth.json",
            "/Users/me/.hermes/mcp-tokens",
            "/Users/me/.local/share/opencode/opencode.db-wal",
            // KELVIN SIGN and LONG S fold to ASCII letters under Unicode case folding.
            "/Users/me/.\u{212A}ube/config",
            "/U\u{17F}ers/me/.ssh/id_rsa",
            "/Users/mé/.ssh/id_rsa",
            "C:\\Users\\me\\.ssh\\id_rsa",
            "C:/Users/me/.ssh/id_rsa",
            "/p/.env",
            "/p/.env.local",
            "key.pem",
            "/Users/me/projects/b1/x",
            "/Users/me/esc*aped",
            "/p/.git/hooks",
            "/p/.GIT/Hooks/pre-commit",
            "/p/.git/hooksx/y",
            ".git/hooks",
            "/p/.envrc",
            "/p/.env.x",
            "b",
            "/x/b",
            "/x/a",
            "a",
            "gh",
            "/usr/bin/gh",
            "ghx",
            "/k/x.PEM",
            "/k/x.key",
            "/k/sécret/key",
            "/k/s\u{e9}cret",
            "/k/sEcret",
            "/k/}x",
            "/k/a}",
            "/k/a/w/b/c",
            "/k/a/b",
            "C:\\p\\.git\\hooks\\x",
        ];
        // A `\` escapes on Unix and separates on Windows (globset's default
        // per platform), so each reading is checked on every platform; a
        // pattern only one reading parses (`**/a\}`) is checked in that one.
        for pattern in patterns {
            let mut built = false;
            for backslash_escape in [true, false] {
                for case_insensitive in [false, true] {
                    let Ok(g) = GlobBuilder::new(pattern)
                        .literal_separator(true)
                        .backslash_escape(backslash_escape)
                        .case_insensitive(case_insensitive)
                        .build()
                    else {
                        continue;
                    };
                    built = true;
                    let g = LazyGlob::new(g, case_insensitive);
                    for candidate in candidates {
                        assert_eq!(
                            g.is_match(candidate),
                            g.regex_match(candidate),
                            "{pattern:?} {candidate:?} case_insensitive={case_insensitive} \
                             backslash_escape={backslash_escape}"
                        );
                    }
                }
            }
            assert!(built, "{pattern:?} parses under neither reading of `\\`");
        }
    }

    #[test]
    fn the_prefix_stops_at_the_first_glob_character() {
        assert_eq!(glob("/a/b/{c,d}", false).prefix, "/a/b/");
        assert_eq!(glob("/a/*.pem", false).prefix, "/a/");
        assert_eq!(glob("**/.env", false).prefix, "");
        assert_eq!(glob("/a/é/b", false).prefix, "/a/");
    }
}
