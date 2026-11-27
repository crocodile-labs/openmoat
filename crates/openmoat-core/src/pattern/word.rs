//! Matching one shell word against one pattern word.

use std::sync::Arc;

use super::{Built, LazyGlob};

/// Stands in for a literal backslash while matching one shell word. globset
/// rewrites `\` to `/` in every candidate on Windows (it assumes paths), so a
/// backslash would match nothing there; swapping it on both sides first makes
/// shell words match byte for byte on every platform. It is ASCII because
/// globset's character classes do not match characters outside it.
const BACKSLASH: &str = "\u{1}";

/// Characters that make a word more than a literal for globset (wildcards,
/// classes, alternation, escapes), plus `,` and `!`, which are only special
/// inside those but are cheap to send down the glob path.
const GLOB_CHARS: [char; 9] = ['*', '?', '[', ']', '{', '}', '\\', ',', '!'];

/// Whether globset parses `glob` whatever its options, so its glob need not be
/// built to know that. Its parser fails only on a class (`[`), an alternation
/// (`{`, `}`) or an escape (`\`); `*`, `**`, `?`, `,` and `!` outside those
/// always parse (globset 0.4's `Parser::parse`, held by the tests below).
pub(super) fn cannot_fail(glob: &str) -> bool {
    !glob.contains(['[', '{', '}', '\\'])
}

/// A glob for one shell word. A backslash escapes the next character on every
/// platform, as in a POSIX shell, so `\\` is a literal backslash.
///
/// Most words in a policy (`git`, `push`, `--force`) contain no glob syntax.
/// Those compare as strings: for them globset would build a regex that accepts
/// exactly the same word, and building ~500 regexes was most of the cost of
/// loading a policy on every hook call.
#[derive(Debug, Clone)]
pub(super) enum WordGlob {
    Literal(String),
    /// Shared with every word of the same compile spelled the same ([`Built`]).
    Glob(Arc<LazyGlob>),
}

impl WordGlob {
    pub(super) fn new(word: &str) -> Result<Self, globset::Error> {
        Self::new_in(word, &mut Built::default())
    }

    /// [`Self::new`], taking the glob from `built` when the same compile
    /// already built one for `word`.
    pub(super) fn new_in(word: &str, built: &mut Built) -> Result<Self, globset::Error> {
        if !word.contains(GLOB_CHARS) {
            return Ok(Self::Literal(word.to_owned()));
        }
        built
            .word(word, |defer| {
                let mut glob = String::with_capacity(word.len());
                let mut chars = word.chars().peekable();
                while let Some(c) = chars.next() {
                    if c == '\\' && chars.peek() == Some(&'\\') {
                        chars.next();
                        glob.push_str(BACKSLASH);
                    } else {
                        glob.push(c);
                    }
                }
                // Shell words compare case-sensitively. Whether the glob may
                // wait is read from the text globset parses, after the swap.
                let options = super::lazy::Options {
                    literal_separator: false,
                    case_insensitive: false,
                    backslash_escape: Some(true),
                };
                LazyGlob::build(&glob, options, defer)
            })
            .map(Self::Glob)
    }

    pub(super) fn is_match(&self, word: &str) -> bool {
        match self {
            Self::Literal(literal) => literal == word,
            Self::Glob(glob) if word.contains('\\') => {
                glob.is_match(&word.replace('\\', BACKSLASH))
            }
            Self::Glob(glob) => glob.is_match(word),
        }
    }
}

#[cfg(test)]
mod tests {
    use globset::GlobBuilder;

    use super::super::lazy::{Defer, Options};
    use super::*;

    /// The string comparison must agree with the regex globset would have
    /// built for the same word, on every candidate.
    #[test]
    fn literal_words_match_exactly_what_their_glob_matches() {
        let words = [
            "git", "--force", "-rf", "", "ünï", "a/b", "C:", "x.y", "$", "|", "=", "@",
        ];
        let candidates = [
            "git",
            "Git",
            "git ",
            "gitx",
            "xgit",
            "--force",
            "--force-with-lease",
            "-rf",
            "-fr",
            "",
            "ünï",
            "ÜNÏ",
            "a/b",
            "a\\b",
            "a//b",
            "C:",
            "c:",
            "x.y",
            "xzy",
            "$",
            "|",
            "=",
            "@",
        ];
        for word in words {
            let literal = WordGlob::new(word).unwrap();
            assert!(matches!(literal, WordGlob::Literal(_)), "{word}");
            let options = Options {
                literal_separator: false,
                case_insensitive: false,
                backslash_escape: Some(true),
            };
            let glob = WordGlob::Glob(Arc::new(
                LazyGlob::build(word, options, &Defer::Never).unwrap(),
            ));
            for candidate in candidates {
                assert_eq!(
                    literal.is_match(candidate),
                    glob.is_match(candidate),
                    "{word:?} vs {candidate:?}"
                );
            }
        }
    }

    /// Every string up to `len` long over `alphabet`.
    fn strings(alphabet: &[char], len: usize) -> Vec<String> {
        let mut strings = vec![String::new()];
        let mut last = vec![String::new()];
        for _ in 0..len {
            last = last
                .iter()
                .flat_map(|s| alphabet.iter().map(move |c| format!("{s}{c}")))
                .collect();
            strings.extend(last.iter().cloned());
        }
        strings
    }

    /// Whether `s` builds as a path glob in every option it can be built
    /// with: both case modes, with and without `literal_separator`, and `\`
    /// read as an escape and as a separator; and as a word glob.
    fn builds_every_way(s: &str) -> bool {
        WordGlob::new(s).is_ok()
            && [false, true].into_iter().all(|separator| {
                [false, true].into_iter().all(|case_insensitive| {
                    [false, true].into_iter().all(|backslash_escape| {
                        GlobBuilder::new(s)
                            .literal_separator(separator)
                            .case_insensitive(case_insensitive)
                            .backslash_escape(backslash_escape)
                            .build()
                            .is_ok()
                    })
                })
            })
    }

    /// Every string over the characters [`cannot_fail`] lets through parses
    /// as a path glob and as a word glob in every option: what lets the
    /// policy lint skip building them, and a policy compile build them on
    /// first use (ADR-132). Up to four characters over the glob characters,
    /// letters with non-ASCII case foldings (`K`, `ſ`), `é`, `~`, `$` and a
    /// space; up to five over the glob characters and two letters.
    #[test]
    fn what_cannot_fail_always_parses() {
        let wide = [
            'a', '/', '*', '?', ',', '!', '.', '-', ']', 'é', '\u{212A}', '\u{17F}', '~', '$', ' ',
        ];
        let long = ['a', '/', '*', '?', ',', '!', '.', '-', 'é', ']'];
        let mut checked = 0;
        for s in strings(&wide, 4).iter().chain(&strings(&long, 5)) {
            assert!(cannot_fail(s));
            assert!(builds_every_way(s), "{s:?}");
            checked += 1;
        }
        assert!(checked > 150_000, "{checked}");
    }

    #[test]
    fn glob_syntax_still_compiles_to_a_glob() {
        for word in [
            "*sh*", "--force*", "x?", "[ab]", "{a,b}", r"\*", "a]", "!x", "a,b",
        ] {
            assert!(
                matches!(WordGlob::new(word), Ok(WordGlob::Glob(_))),
                "{word}"
            );
        }
        for malformed in ["{a", "[a", "b}", "a\\", "[z-a]", "{a,{b}"] {
            assert!(!cannot_fail(malformed), "{malformed}");
        }
        for malformed in ["{a", "[a", "b}"] {
            assert!(
                WordGlob::new(malformed).is_err(),
                "{malformed} is still rejected"
            );
        }
    }
}
