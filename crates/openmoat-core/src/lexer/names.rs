//! Where a variable name ends at a quote.
//!
//! The shell reads a name after `$` only as far as the quoting it starts in:
//! `"$d"_rsa`, `$d'_rsa'`, `$d"_rsa"`, `"$d""_rsa"` and `$d\_rsa` all expand
//! `d` and append `_rsa`. A [`Word`]'s text has its quotes removed, so
//! `$d_rsa` would read as the variable `d_rsa`: a secret path through a known
//! variable, or a secret variable's name, would go unseen. Where a quote or an
//! escape ends a name and a name character follows, the reference is written
//! `${d}` instead, which every later step reads the way the shell does.

use std::ops::Range;

use super::Word;

/// Whether `c` may continue a variable name.
fn is_name(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Brace each `$NAME` of `word` that a quoting boundary at one of `boundaries`
/// (byte offsets into its text where the quoting changed) ends while a name
/// character follows.
pub(super) fn end_names(word: &mut Word, boundaries: &[usize]) {
    // in order, so `$a''b''c` ends `a` and leaves `b` text; each pair of
    // braces moves the boundaries after it
    let mut added = 0;
    let mut last = None;
    for &at in boundaries {
        if last == Some(at) {
            continue;
        }
        last = Some(at);
        if end_name(word, at + added) {
            added += 2;
        }
    }
}

/// Brace the `$NAME` that ends at `at`, if a name character follows it there.
fn end_name(word: &mut Word, at: usize) -> bool {
    let text = &word.text;
    if at > text.len() || !text.is_char_boundary(at) || !text[at..].starts_with(is_name) {
        return false;
    }
    let name_len = text[..at].chars().rev().take_while(|c| is_name(*c)).count();
    let name_start = at - name_len;
    // a name starts with a letter or `_`: `$1x` is `$1` and `x` already
    if name_len == 0 || text[name_start..].starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    let dollars = text[..name_start]
        .bytes()
        .rev()
        .take_while(|&b| b == b'$')
        .count();
    let Some(dollar) = name_start.checked_sub(1) else {
        return false;
    };
    // `$$` is the shell's process id, and a `$` from single quotes expands nothing
    if dollars % 2 == 0 || word.literal.iter().any(|span| span.contains(&dollar)) {
        return false;
    }
    word.text.insert(at, '}');
    word.text.insert(name_start, '{');
    // a position moves past each brace inserted before it
    let moved = |x: usize| x + usize::from(x >= name_start) + usize::from(x >= at);
    let shift = |span: &mut Range<usize>| {
        // the braces take the quoting of their `$`
        let holds_dollar = span.contains(&dollar);
        span.start = moved(span.start);
        span.end = if holds_dollar {
            span.end + 2
        } else {
            moved(span.end)
        };
    };
    word.literal.iter_mut().for_each(shift);
    word.unquoted.iter_mut().for_each(shift);
    true
}

#[cfg(test)]
mod tests {
    use crate::lexer::{Token, lex};

    fn words(line: &str) -> Vec<String> {
        lex(line)
            .unwrap()
            .into_iter()
            .filter_map(|t| match t {
                Token::Word(w) => Some(w.text),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_quote_ends_the_name_it_follows() {
        for (line, word) in [
            ("cat \"$d\"_rsa", "${d}_rsa"),
            ("cat $d'_rsa'", "${d}_rsa"),
            ("cat $d\"_rsa\"", "${d}_rsa"),
            ("cat \"$d\"\"_rsa\"", "${d}_rsa"),
            ("cat $d\\_rsa", "${d}_rsa"),
            ("sed \"$n\"p", "${n}p"),
            ("x \"$a\"_\"$b\"_c", "${a}_${b}_c"),
            ("x $a''b''c", "${a}bc"),
        ] {
            assert_eq!(words(line)[1], word, "{line}");
        }
    }

    #[test]
    fn names_that_end_anyway_are_left_as_written() {
        for (line, word) in [
            ("cat \"$d\"/x", "$d/x"),
            ("cat \"$d\"", "$d"),
            ("cat \"${d}\"x", "${d}x"),
            ("cat '$d'_x", "$d_x"),
            ("cat \"$$\"x", "$$x"),
            ("cat \"$1\"x", "$1x"),
            ("cat a\"b\"c", "abc"),
        ] {
            assert_eq!(words(line)[1], word, "{line}");
        }
    }
}
