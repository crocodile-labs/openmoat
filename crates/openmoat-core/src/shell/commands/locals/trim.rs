//! `${name#pattern}`, `${name##pattern}`, `${name%pattern}` and
//! `${name%%pattern}`: the shell removes the shortest or longest prefix or
//! suffix of the value that the pattern matches.
//!
//! For a variable whose every value is known (`locals.rs`), each trimmed
//! value is known too. The pattern is a shell glob; only `*`, `?` and plain
//! characters are read. A pattern with anything else (`[`, a quote, a
//! backslash, `$`, a brace) is not, and the use stays unknown. Quotes inside
//! the braces make a `*` or `?` literal (`"${x#"*"}"`), and the lexer's text
//! keeps no trace of empty ones (`"${x#""*""}"` matches a `*` only), so a
//! pattern with either is read only when the whole expansion is unquoted
//! source; elsewhere it stays unknown.

#[cfg(test)]
mod tests;

/// Values longer than this are not trimmed: the use stays unknown.
const MAX_VALUE: usize = 4096;

/// One trim, as written after the variable's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Trim {
    /// `#`/`##` remove a prefix, `%`/`%%` a suffix.
    suffix: bool,
    /// `##` and `%%` remove the longest match, `#` and `%` the shortest.
    longest: bool,
    pattern: Vec<char>,
}

impl Trim {
    /// The trim at the start of `after`, the text that follows `${name`, and
    /// the bytes it takes up to and including the closing `}`; `None` for any
    /// other form or a pattern this module does not read.
    pub(super) fn parse(after: &str) -> Option<(Self, usize)> {
        let (suffix, op) = match after.chars().next()? {
            '#' => (false, '#'),
            '%' => (true, '%'),
            _ => return None,
        };
        let longest = after[1..].starts_with(op);
        let start = 1 + usize::from(longest);
        let end = after.find('}')?;
        let pattern = after.get(start..end)?;
        // Also every character an extended glob gives a meaning: bash's
        // `extglob` (`*(…)`, `+(…)`, `@(…)`, `!(…)`, `|`) and zsh's
        // `extendedglob` (`#`, `^`, `~`, `(…)`), which a command can turn on
        // before the trim (`shopt -s extglob; … ${x#*(a)}`); read as plain
        // characters they would give a value the shell does not.
        if pattern.contains([
            '[', ']', '\'', '"', '\\', '$', '`', '{', '(', ')', '|', '#', '^', '~',
        ]) {
            return None;
        }
        let trim = Self {
            suffix,
            longest,
            pattern: pattern.chars().collect(),
        };
        Some((trim, end + 1))
    }

    /// Whether the pattern matches more than its own text.
    pub(super) fn is_glob(&self) -> bool {
        self.pattern.iter().any(|c| matches!(c, '*' | '?'))
    }

    /// `value` with the match removed, as the shell expands it; `None` for a
    /// value too long to trim.
    pub(super) fn apply(&self, value: &str) -> Option<String> {
        if value.len() > MAX_VALUE {
            return None;
        }
        let chars: Vec<char> = value.chars().collect();
        let n = chars.len();
        let prefix = |i: usize| matches(&self.pattern, &chars[..i]);
        let suffix = |i: usize| matches(&self.pattern, &chars[i..]);
        let kept: &[char] = match (self.suffix, self.longest) {
            (false, false) => (0..=n).find(|&i| prefix(i)).map_or(&chars, |i| &chars[i..]),
            (false, true) => (0..=n)
                .rev()
                .find(|&i| prefix(i))
                .map_or(&chars, |i| &chars[i..]),
            (true, false) => (0..=n)
                .rev()
                .find(|&i| suffix(i))
                .map_or(&chars, |i| &chars[..i]),
            (true, true) => (0..=n).find(|&i| suffix(i)).map_or(&chars, |i| &chars[..i]),
        };
        Some(kept.iter().collect())
    }
}

/// Whether the glob `pattern` (`*`, `?` and plain characters) matches all of `text`.
fn matches(pattern: &[char], text: &[char]) -> bool {
    // `row[j]`: the pattern read so far matches the first `j` characters
    let mut row = vec![false; text.len() + 1];
    row[0] = true;
    for &p in pattern {
        let mut next = vec![false; text.len() + 1];
        if p == '*' {
            let mut any = false;
            for (j, slot) in next.iter_mut().enumerate() {
                any |= row[j];
                *slot = any;
            }
        } else {
            for j in 0..text.len() {
                next[j + 1] = row[j] && (p == '?' || p == text[j]);
            }
        }
        row = next;
    }
    row[text.len()]
}
