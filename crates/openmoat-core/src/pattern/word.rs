//! Matching one shell word against one pattern word.

use globset::GlobBuilder;

use super::LazyGlob;

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
    Glob(Box<LazyGlob>),
}

impl WordGlob {
    pub(super) fn new(word: &str) -> Result<Self, globset::Error> {
        if !word.contains(GLOB_CHARS) {
            return Ok(Self::Literal(word.to_owned()));
        }
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
        GlobBuilder::new(&glob)
            .literal_separator(false)
            .backslash_escape(true)
            .build()
            // Shell words compare case-sensitively.
            .map(|g| Self::Glob(Box::new(LazyGlob::new(g, false))))
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
            let glob = WordGlob::Glob(Box::new(LazyGlob::new(
                GlobBuilder::new(word)
                    .literal_separator(false)
                    .backslash_escape(true)
                    .build()
                    .unwrap(),
                false,
            )));
            for candidate in candidates {
                assert_eq!(
                    literal.is_match(candidate),
                    glob.is_match(candidate),
                    "{word:?} vs {candidate:?}"
                );
            }
        }
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
        for malformed in ["{a", "[a", "b}"] {
            assert!(
                WordGlob::new(malformed).is_err(),
                "{malformed} is still rejected"
            );
        }
    }
}
