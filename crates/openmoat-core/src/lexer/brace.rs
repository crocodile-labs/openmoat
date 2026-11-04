//! Brace expansion, as bash does it before any other expansion.
//!
//! Bash makes several words of one without looking at the disk: `cat .{env,x}`
//! runs `cat .env .x`. [`expand_braces`] replaces each word with the words bash
//! makes of it, so the classifier sees every one of them as an operand (and a
//! result holding `*`, `?` or `[` is globbed, `crate::expand`). The rules are
//! those of bash's `braces.c`:
//! - only unquoted, unescaped `{`, `,` and `}` are syntax; `${…}` is a
//!   parameter, not a brace;
//! - a `{` opens a group only when a `}` follows with a comma or a `..` at its
//!   own level in between: `{}`, `{x}` and `{a,b` stay literal;
//! - a group with a comma is split at the commas of its level and each part is
//!   expanded in turn (`{a,{b,c}}`); otherwise it is a sequence (`{1..3}`,
//!   `{a..e..2}`, `{01..10}`) or stays literal with its braces;
//! - groups multiply left to right with the text around them
//!   (`{a,b}{1,2}` → `a1 a2 b1 b2`), and an empty unquoted word is dropped.
//!
//! A word that would make more than [`MAX_BRACE_WORDS`] words, nest deeper, or
//! take more than [`MAX_SCAN`] steps is kept as written and reported, so the
//! command needs review. A here-string is not brace-expanded.

use std::ops::Range;

use super::{LexError, Operator, Token, Word};

/// Most words the braces of one word may make, and the deepest they may nest.
pub const MAX_BRACE_WORDS: usize = 256;
/// Most bytes looked at to expand one word: bounds a hostile `{{{{…`.
const MAX_SCAN: usize = 1 << 16;

/// Words, each as pieces of [`Braces::text`].
type Words = Vec<Vec<Range<usize>>>;

/// `tokens` with each word replaced by the words its braces make, and the first
/// word that made too many (kept as written).
pub fn expand_braces(tokens: Vec<Token>) -> (Vec<Token>, Option<LexError>) {
    let mut out = Vec::with_capacity(tokens.len());
    let mut error = None;
    let mut here_string = false;
    for token in tokens {
        let data = std::mem::replace(
            &mut here_string,
            token == Token::Operator(Operator::HereString),
        );
        match token {
            Token::Word(word) if !data => match expand(&word) {
                Ok(Some(words)) => out.extend(words.into_iter().map(Token::Word)),
                Ok(None) => out.push(Token::Word(word)),
                Err(e) => {
                    error.get_or_insert(e);
                    out.push(Token::Word(word));
                }
            },
            token => out.push(token),
        }
    }
    (out, error)
}

/// The words bash makes of `word`, or `None` when its braces make only itself.
fn expand(word: &Word) -> Result<Option<Vec<Word>>, LexError> {
    if !word.text.contains('{') {
        return Ok(None);
    }
    let mut braces = Braces::new(word);
    let pieces = braces.words(0..word.text.len(), 0)?;
    if !braces.expanded {
        return Ok(None);
    }
    let mut words: Vec<Word> = pieces
        .iter()
        .map(|p| braces.word(p))
        .filter(|w| !w.text.is_empty() || w.quoted)
        .collect();
    // A substitution runs once, and is classified once.
    if let Some(first) = words.first_mut() {
        first.substitutions.clone_from(&word.substitutions);
    }
    Ok(Some(words))
}

struct Braces<'w> {
    word: &'w Word,
    /// The word's text, then the terms of its sequences.
    text: String,
    /// Per byte of the word: the byte where it is brace syntax (unquoted,
    /// unescaped, outside `${…}`), 0 elsewhere.
    syntax: Vec<u8>,
    scanned: usize,
    /// A group made words other than its own text.
    expanded: bool,
}

impl<'w> Braces<'w> {
    fn new(word: &'w Word) -> Self {
        let bytes = word.text.as_bytes();
        let mut syntax = vec![0; bytes.len()];
        for run in &word.unquoted {
            syntax[run.clone()].copy_from_slice(&bytes[run.clone()]);
        }
        let mut i = 0;
        while i + 1 < syntax.len() {
            if syntax[i] == b'$' && syntax[i + 1] == b'{' {
                let end = parameter_end(&syntax, i + 2);
                syntax[i..end].fill(0);
                i = end;
            } else {
                i += 1;
            }
        }
        Self {
            word,
            text: word.text.clone(),
            syntax,
            scanned: 0,
            expanded: false,
        }
    }

    fn at(&mut self, i: usize) -> Result<u8, LexError> {
        self.scanned += 1;
        if self.scanned > MAX_SCAN {
            return Err(LexError::TooManyBraceWords);
        }
        Ok(self.syntax[i])
    }

    /// The words of `span`: every group in it, left to right.
    fn words(&mut self, span: Range<usize>, depth: usize) -> Result<Words, LexError> {
        if depth > MAX_BRACE_WORDS {
            return Err(LexError::TooManyBraceWords);
        }
        let mut words: Words = vec![Vec::new()];
        let mut rest = span.start;
        while let Some((open, close)) = self.group(rest..span.end)? {
            let inner = open + 1..close;
            let made = if self.text[inner.clone()].contains(',') {
                // Bash looks for any comma here, quoted or nested, then splits
                // at the unquoted ones of this level: `{a..{b,c}}` → `a..b a..c`.
                self.expanded = true;
                let mut made = Vec::new();
                for part in self.split(inner)? {
                    made.extend(self.words(part, depth + 1)?);
                    bound(made.len())?;
                }
                made
            } else if let Some(terms) = self.sequence(inner)? {
                self.expanded = true;
                terms
            } else {
                vec![vec![open..close + 1]]
            };
            bound(words.len().saturating_mul(made.len()))?;
            words = words
                .iter()
                .flat_map(|w| {
                    made.iter().map(move |m| {
                        let mut word = w.clone();
                        word.push(rest..open);
                        word.extend(m.iter().cloned());
                        word
                    })
                })
                .collect();
            rest = close + 1;
        }
        for word in &mut words {
            word.push(rest..span.end);
        }
        Ok(words)
    }

    /// The first `{` in `span` that a `}` closes with a comma or a `..` of its
    /// level in between, and that `}`.
    fn group(&mut self, span: Range<usize>) -> Result<Option<(usize, usize)>, LexError> {
        for open in span.clone() {
            if self.at(open)? != b'{' {
                continue;
            }
            let (mut level, mut separated) = (0usize, false);
            for i in open + 1..span.end {
                match self.at(i)? {
                    b'}' if level == 0 && separated => return Ok(Some((open, i))),
                    b'{' => level += 1,
                    b'}' => level = level.saturating_sub(1),
                    b',' if level == 0 => separated = true,
                    b'.' if level == 0 && self.range_dots(i, span.end) => separated = true,
                    _ => {}
                }
            }
        }
        Ok(None)
    }

    /// A `..` at `i` not followed by the closing `}`.
    fn range_dots(&self, i: usize, end: usize) -> bool {
        i + 1 < end && self.syntax[i + 1] == b'.' && (i + 2 == end || self.syntax[i + 2] != b'}')
    }

    /// `inner` split at its unquoted commas outside nested braces.
    fn split(&mut self, inner: Range<usize>) -> Result<Vec<Range<usize>>, LexError> {
        let (mut parts, mut start, mut level) = (Vec::new(), inner.start, 0usize);
        for i in inner.clone() {
            match self.at(i)? {
                b'{' => level += 1,
                b'}' => level = level.saturating_sub(1),
                b',' if level == 0 => {
                    parts.push(start..i);
                    start = i + 1;
                }
                _ => {}
            }
        }
        parts.push(start..inner.end);
        Ok(parts)
    }

    /// The terms of `inner` when it is an unquoted sequence, appended to `text`.
    fn sequence(&mut self, inner: Range<usize>) -> Result<Option<Words>, LexError> {
        if self.syntax[inner.clone()].contains(&0) {
            return Ok(None);
        }
        let Some(terms) = sequence_terms(&self.text[inner])? else {
            return Ok(None);
        };
        let mut words = Vec::with_capacity(terms.len());
        for term in terms {
            let start = self.text.len();
            self.text.push_str(&term);
            words.push(std::iter::once(start..self.text.len()).collect());
        }
        Ok(Some(words))
    }

    /// The word made of `pieces`, with the single-quoted spans it keeps.
    fn word(&self, pieces: &[Range<usize>]) -> Word {
        let mut out = Word {
            quoted: self.word.quoted,
            glob: self.word.glob,
            ..Word::default()
        };
        for piece in pieces {
            let shift = out.text.len();
            out.literal.extend(self.word.literal.iter().filter_map(|l| {
                let (start, end) = (l.start.max(piece.start), l.end.min(piece.end));
                (start < end).then(|| start - piece.start + shift..end - piece.start + shift)
            }));
            out.text.push_str(&self.text[piece.clone()]);
        }
        out
    }
}

/// Where the `${` parameter whose body starts at `body` ends (past its `}`).
fn parameter_end(syntax: &[u8], body: usize) -> usize {
    let mut level = 1usize;
    for (i, &b) in syntax.iter().enumerate().skip(body) {
        match b {
            b'{' => level += 1,
            b'}' => {
                level -= 1;
                if level == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    syntax.len()
}

/// The terms of `x..y` or `x..y..step`, as bash makes them: integers
/// (zero-padded to the longer end when one is written with a leading zero) or
/// single letters, from `x` towards `y`.
fn sequence_terms(text: &str) -> Result<Option<Vec<String>>, LexError> {
    let Some((first, rest)) = text.split_once("..") else {
        return Ok(None);
    };
    let (last, step) = match rest.split_once("..") {
        Some((last, step)) => match step.parse::<i64>() {
            Ok(step) => (last, step),
            Err(_) => return Ok(None),
        },
        None => (rest, 1),
    };
    let letter = |s: &str| match s.as_bytes() {
        [c] if c.is_ascii_alphabetic() => Some(i64::from(*c)),
        _ => None,
    };
    let padded = |s: &str| {
        let digits = s.strip_prefix('-').unwrap_or(s);
        digits.len() > 1 && digits.starts_with('0')
    };
    let (start, end, letters) = match (first.parse::<i64>(), last.parse::<i64>()) {
        (Ok(start), Ok(end)) => (start, end, false),
        _ => match (letter(first), letter(last)) {
            (Some(start), Some(end)) => (start, end, true),
            _ => return Ok(None),
        },
    };
    let width = if padded(first) || padded(last) {
        first.len().max(last.len())
    } else {
        0
    };
    let step = step.unsigned_abs().max(1);
    let count = start.abs_diff(end) / step + 1;
    bound(usize::try_from(count).unwrap_or(usize::MAX))?;
    let direction = if start <= end { 1 } else { -1 };
    let terms = (0..count).map(|k| {
        let n = i128::from(start) + i128::from(direction) * i128::from(k) * i128::from(step);
        if letters {
            u32::try_from(n)
                .ok()
                .and_then(char::from_u32)
                .map(String::from)
        } else {
            Some(format!("{n:0width$}"))
        }
    });
    Ok(terms.collect())
}

fn bound(words: usize) -> Result<(), LexError> {
    if words > MAX_BRACE_WORDS {
        Err(LexError::TooManyBraceWords)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex;

    fn texts(tokens: &[Token]) -> Vec<String> {
        tokens.iter().map(ToString::to_string).collect()
    }

    /// The words of `input` after brace expansion, or `None` when it needs review.
    fn argv(input: &str) -> Option<Vec<String>> {
        let (tokens, error) = expand_braces(lex(input).unwrap());
        error.is_none().then(|| texts(&tokens))
    }

    #[test]
    fn braces_make_the_words_bash_makes() {
        // Each expected line is what `bash` passes for the input.
        for (input, expected) in [
            ("cat .{env,x}", "cat .env .x"),
            ("cat ~/.ssh/{id_rsa,x}", "cat ~/.ssh/id_rsa ~/.ssh/x"),
            ("cat .e{n,m}v", "cat .env .emv"),
            ("cat .{e{nv,x},y}", "cat .env .ex .y"),
            ("cat file{1..3} .{env,}", "cat file1 file2 file3 .env ."),
            ("{cat,.env}", "cat .env"),
            ("x {a,b}{1,2}", "x a1 a2 b1 b2"),
            ("x {a,b,{c,d}e}f", "x af bf cef def"),
            ("x {a..c}{1..2}", "x a1 a2 b1 b2 c1 c2"),
            ("x {5..1} {-2..1} {+1..2}", "x 5 4 3 2 1 -2 -1 0 1 1 2"),
            ("x {1..7..3} {a..e..2} {9..1..-4}", "x 1 4 7 a c e 9 5 1"),
            (
                "x {01..3} {-01..1} {Y..b}",
                "x 01 02 03 -01 000 001 Y Z [ \\ ] ^ _ ` a b",
            ),
            ("x {a,}{,b} {,} x{,}y", "x a ab b xy xy"),
            ("x {a..{b,c}} {a..c,d}", "x a..b a..c a..c d"),
            ("x {a,b}} {{a,b} {a,b}{", "x a} b} {a {b a{ b{"),
            (
                r"x {a{b,c}} {a,{b,c} \${a,b}",
                "x {ab} {ac} {a,b {a,c $a $b",
            ),
            (r"x {a,b\}c} {a\,b,c}", "x a b}c a,b c"),
        ] {
            assert_eq!(argv(input).unwrap().join(" "), expected, "{input}");
        }
    }

    #[test]
    fn literal_braces_stay_one_word() {
        for input in [
            "x {} {x} {a,b {..3} {1...3} {1..3..} {aa..c} {a..} {1..a}",
            r#"x '{a,b}' "{a,b}" \{a,b} {a',b'} {a","b} {1'..'3} {'1'..3}"#,
            r#"x ${a,b} ${x:-{a,b}} "${a}{b,c}" HEAD@{1} find -exec {} \;"#,
        ] {
            assert_eq!(argv(input).unwrap(), texts(&lex(input).unwrap()), "{input}");
        }
    }

    #[test]
    fn quoting_and_substitutions_follow_their_words() {
        let (tokens, _) = expand_braces(lex("echo {'$a',$b}$(id) <<< {c,d}").unwrap());
        let words: Vec<&Word> = tokens
            .iter()
            .filter_map(|t| match t {
                Token::Word(w) => Some(w),
                _ => None,
            })
            .collect();
        assert_eq!(words[1].text, "$a$(…)");
        assert_eq!(words[1].literal.split_first(), Some((&(0..2), &[][..])));
        assert_eq!(words[1].substitutions, ["id"]);
        assert_eq!(words[2].text, "$b$(…)");
        assert!(words[2].literal.is_empty() && words[2].substitutions.is_empty());
        assert_eq!(words[3].text, "{c,d}", "a here-string is not expanded");
    }

    #[test]
    fn too_many_words_keep_the_word_and_say_so() {
        let (tokens, error) = expand_braces(lex("cat .env x{1..257} {a,b}").unwrap());
        assert_eq!(error, Some(LexError::TooManyBraceWords));
        assert_eq!(texts(&tokens), ["cat", ".env", "x{1..257}", "a", "b"]);
        let eight = "{a,b}".repeat(8);
        assert_eq!(argv(&format!("x {eight}")).map(|a| a.len()), Some(257));
        for input in [
            format!("x {eight}{{a,b}}"),
            format!("x {}a,b{}", "{a..".repeat(300), "}".repeat(300)),
            format!("x {}", "{".repeat(1000)),
            "x {1..99999999999999999} {a,b}".to_owned(),
        ] {
            assert_eq!(argv(&input), None, "{input}");
        }
    }
}
