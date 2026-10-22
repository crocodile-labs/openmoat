//! IR globs as Seatbelt path filters.
//!
//! Seatbelt compares a path in its on-disk spelling. A file or directory that
//! does not exist yet gets the spelling the program asks for, so on a
//! case-insensitive disk `.MCP.json` would match no deny written for
//! `.mcp.json`, while every later open of `.mcp.json` reaches it. Deny filters
//! are therefore written case-folded there ([`Case::Folded`]): each ASCII
//! letter matches in either case.

use super::super::patterns::literal_tree;

/// How a filter compares letters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Case {
    /// As written: allow rules, and every rule on a case-sensitive disk.
    Exact,
    /// Either case for each ASCII letter: deny rules on a case-insensitive disk.
    Folded,
}

/// One IR glob as a Seatbelt path filter.
pub(super) fn filter(pattern: &str, case: Case) -> String {
    match literal_tree(pattern) {
        _ if case == Case::Folded => format!("(regex {})", quote(&regex(pattern, case))),
        Some(dir) if pattern.ends_with("/**") => format!("(subpath {})", quote(dir)),
        Some(path) => format!("(literal {})", quote(path)),
        None => format!("(regex {})", quote(&regex(pattern, case))),
    }
}

/// An SBPL string literal.
fn quote(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// A path glob as an anchored regular expression with the engine's semantics
/// (`docs/POLICY.md` §3): `*` and `?` stop at `/`, `**` as a whole component
/// crosses it, and `dir/**` also matches `dir`.
pub(super) fn regex(glob: &str, case: Case) -> String {
    let mut re = String::from("^");
    let mut depth = 0usize;
    let mut i = 0;
    while let Some(c) = glob[i..].chars().next() {
        let rest = &glob[i..];
        let (piece, used) = if rest == "/**" {
            ("(/.*)?".to_owned(), 3)
        } else if rest.starts_with("/**/") {
            ("/(.*/)?".to_owned(), 4)
        } else if i == 0 && rest == "**" {
            (".*".to_owned(), 2)
        } else if i == 0 && rest.starts_with("**/") {
            ("(.*/)?".to_owned(), 3)
        } else {
            match c {
                '*' => ("[^/]*".to_owned(), 1),
                '?' => ("[^/]".to_owned(), 1),
                '{' => {
                    depth += 1;
                    ("(".to_owned(), 1)
                }
                '}' if depth > 0 => {
                    depth -= 1;
                    (")".to_owned(), 1)
                }
                ',' if depth > 0 => ("|".to_owned(), 1),
                '[' => class(rest, case).unwrap_or_else(|| (escape('[', case), 1)),
                '\\' => match rest[1..].chars().next() {
                    Some(next) => (escape(next, case), 1 + next.len_utf8()),
                    None => (escape('\\', case), 1),
                },
                other => (escape(other, case), other.len_utf8()),
            }
        };
        re.push_str(&piece);
        i += used;
    }
    re.push('$');
    re
}

/// A glob character class at the start of `rest` (`[ab]`, `[!ab]`) and its
/// length, or `None` when it is not closed. Folded, each ASCII letter member
/// and range is added in its other case too.
fn class(rest: &str, case: Case) -> Option<(String, usize)> {
    let body = &rest[1..];
    let (negated, body) = match body.strip_prefix(['!', '^']) {
        Some(b) => (true, b),
        None => (false, body),
    };
    // A `]` right after the opening bracket is a member, not the end.
    let end = body.char_indices().skip(1).find(|(_, c)| *c == ']')?.0;
    let written = &body[..end];
    let mut members = written.replace('\\', "\\\\");
    if case == Case::Folded {
        // The members again with each letter's case swapped: ranges keep their
        // shape (`a-c` adds `A-C`), and a repeated member changes nothing.
        let swapped: String = written.chars().map(swap_case).collect();
        if swapped != written {
            members.push_str(&swapped.replace('\\', "\\\\"));
        }
    }
    let negation = if negated { "^/" } else { "" };
    Some((
        format!("[{negation}{members}]"),
        rest.len() - body.len() + end + 1,
    ))
}

fn swap_case(c: char) -> char {
    if c.is_ascii_lowercase() {
        c.to_ascii_uppercase()
    } else {
        c.to_ascii_lowercase()
    }
}

fn escape(c: char, case: Case) -> String {
    if case == Case::Folded && c.is_ascii_alphabetic() {
        format!("[{}{}]", c.to_ascii_lowercase(), c.to_ascii_uppercase())
    } else if ".^$|()+[]{}\\*?".contains(c) {
        format!("\\{c}")
    } else {
        c.to_string()
    }
}
