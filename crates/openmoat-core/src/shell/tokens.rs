//! Recognisers for what a single shell word can name: an assignment or
//! variable references. Hosts are recognised by `crate::host`.

use std::ops::Range;

use super::tables::{IGNORED_VARS, SPECIAL_PARAMS};
use crate::lexer::Word;

/// `NAME=value` or `NAME+=value` → `NAME`.
pub fn assignment_name(word: &str) -> Option<&str> {
    let (name, _) = word.split_once('=')?;
    let name = name.strip_suffix('+').unwrap_or(name);
    let mut chars = name.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    chars
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
        .then_some(name)
}

/// Names a shell word expands: [`env_refs`] of its text, skipping every `$`
/// that came from single quotes.
pub fn word_env_refs(word: &Word) -> Vec<String> {
    expanded_refs(&word.text, &word.literal)
}

/// Names referenced as `$NAME` or `${NAME…}`, excluding special and positional
/// parameters and well-known non-secret variables. Order-preserving, unique.
pub fn env_refs(token: &str) -> Vec<String> {
    expanded_refs(token, &[])
}

fn expanded_refs(token: &str, literal: &[Range<usize>]) -> Vec<String> {
    let is_name_char = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut names: Vec<String> = Vec::new();
    for (pos, _) in token.match_indices('$') {
        if literal.iter().any(|span| span.contains(&pos)) {
            continue;
        }
        let rest = &token[pos + 1..];
        let body = rest.strip_prefix('{').unwrap_or(rest);
        if body
            .chars()
            .next()
            .is_some_and(|c| SPECIAL_PARAMS.contains(&c))
        {
            continue;
        }
        let end = body.find(|c: char| !is_name_char(c)).unwrap_or(body.len());
        let name = &body[..end];
        let skip = name.is_empty()
            || IGNORED_VARS.contains(&name)
            || name.chars().all(|c| c.is_ascii_digit());
        if !skip && !names.iter().any(|n| n == name) {
            names.push(name.to_owned());
        }
    }
    names
}

/// `curl -d @file` names `file`.
pub fn strip_at(token: &str) -> &str {
    token.strip_prefix('@').unwrap_or(token)
}

/// The argument following the first of `flags`, if any.
pub fn flag_payload<'a>(argv: &'a [String], flags: &[&str]) -> Option<&'a str> {
    let pos = argv.iter().position(|a| flags.contains(&a.as_str()))?;
    argv.get(pos + 1).map(String::as_str)
}

pub fn basename(program: &str) -> &str {
    program.rsplit(['/', '\\']).next().unwrap_or(program)
}

/// `NAME` of `for NAME in WORDS`, when the words are a plain `for` header.
pub(super) fn for_variable(words: &[Word]) -> Option<&str> {
    match words {
        [f, name, i, ..] if !f.quoted && f.text == "for" && i.text == "in" => {
            let ok = !name.text.is_empty()
                && name
                    .text
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && !name.text.as_bytes()[0].is_ascii_digit();
            ok.then_some(name.text.as_str())
        }
        _ => None,
    }
}
