//! Recognisers for what a single shell word can name: an assignment or
//! variable references. Hosts are recognised by `crate::host`.

use std::fmt::Write as _;
use std::ops::Range;

use super::tables::{
    EDITOR_VARS, GNU_PREFIXED, IGNORED_VARS, INERT_EDITOR_VALUES, SPECIAL_PARAMS, SYSTEM_PATH_DIRS,
};
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

/// Whether the assignment `word` (`NAME=value`) changes nothing about what
/// later commands run: an editor variable set to a no-op or a reader
/// (`GIT_EDITOR=true`, `EDITOR=:`, `GIT_EDITOR=cat`), or `PATH` kept as it is
/// (`PATH=$PATH`, `PATH="$PATH"`) or set to system directories only
/// (`PATH=/usr/bin:/bin`), in any order. A `PATH` that adds any other
/// directory, is empty or has an empty entry (the working directory) is not.
pub fn inert_assignment(word: &Word) -> bool {
    let Some((name, value)) = word.text.split_once('=') else {
        return false;
    };
    if EDITOR_VARS.contains(&name) {
        return INERT_EDITOR_VALUES.contains(&value);
    }
    if name != "PATH" {
        return false;
    }
    if value == "$PATH" || value == "${PATH}" {
        // only a `$` the shell expands keeps the path; from single quotes it
        // is a literal, so the value would be a relative directory
        let dollar = name.len() + 1;
        return !word.literal.iter().any(|span| span.contains(&dollar));
    }
    !value.is_empty() && value.split(':').all(|dir| SYSTEM_PATH_DIRS.contains(&dir))
}

/// The argv of a `kill` whose arguments hold a command substitution, with each
/// one's text in place of `$(…)` (`kill $(pgrep openmoat)`), so a rule can name the processes it
/// looks up (`stops-openmoat`); the substituted command is classified on its
/// own as well. `None` for any other command, or a `kill` without one.
pub fn kill_substituted(program: &str, words: &[Word]) -> Option<Vec<String>> {
    if program != "kill" || words.iter().all(|w| w.substitutions.is_empty()) {
        return None;
    }
    let shown = |w: &Word| {
        if w.substitutions.is_empty() {
            w.text.clone()
        } else {
            w.substitutions.iter().fold(String::new(), |mut out, s| {
                let _ = write!(out, "$({s})");
                out
            })
        }
    };
    Some(words.iter().map(shown).collect())
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
        let (body, braced) = match rest.strip_prefix('{') {
            Some(body) => (body, true),
            None => (rest, false),
        };
        if body
            .chars()
            .next()
            .is_some_and(|c| SPECIAL_PARAMS.contains(&c))
        {
            continue;
        }
        let end = body.find(|c: char| !is_name_char(c)).unwrap_or(body.len());
        let name = &body[..end];
        // `${NAME:+word}` and `${NAME+word}` expand to `word` or to nothing: they
        // tell whether `NAME` is set and show nothing of its value (a `$` in
        // `word` is its own reference)
        let presence_only =
            braced && (body[end..].starts_with(":+") || body[end..].starts_with('+'));
        let skip = name.is_empty()
            || presence_only
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
    flag_payload_index(argv, flags).map(|at| argv[at].as_str())
}

/// The argv index of the argument following the first of `flags`, if any.
pub fn flag_payload_index(argv: &[String], flags: &[&str]) -> Option<usize> {
    let pos = argv.iter().position(|a| flags.contains(&a.as_str()))?;
    (pos + 1 < argv.len()).then_some(pos + 1)
}

/// `[ -n "$X" ]`, `[[ -z $X ]]`, `test -n "$X"`: the word at `i` is the one
/// operand of a `-n`/`-z` test, which tells whether `X` has a value and shows
/// nothing of it. Only a word that is a single `$X` or `${X}` counts; any other
/// use of the variable in the test (`[ "$X" = y ]`, `${X:0:4}`) is a read.
pub fn tests_presence(argv: &[String], i: usize) -> bool {
    matches!(program_name(&argv[0]), "[" | "[[" | "test")
        && i >= 2
        && matches!(argv[i - 1].as_str(), "-n" | "-z")
        && is_single_reference(&argv[i])
}

/// `$NAME` or `${NAME}` and nothing else.
fn is_single_reference(word: &str) -> bool {
    let Some(rest) = word.strip_prefix('$') else {
        return false;
    };
    let name = match rest.strip_prefix('{') {
        Some(inner) => match inner.strip_suffix('}') {
            Some(name) => name,
            None => return false,
        },
        None => rest,
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn basename(program: &str) -> &str {
    program.rsplit(['/', '\\']).next().unwrap_or(program)
}

/// The program `word` runs, as the classifier's tables name it: its
/// [`basename`], with the `g` of a GNU tool installed under a prefix dropped
/// (`/opt/homebrew/bin/gcp` is `cp`, [`GNU_PREFIXED`]).
pub fn program_name(word: &str) -> &str {
    let name = basename(word);
    name.strip_prefix('g')
        .filter(|tool| GNU_PREFIXED.contains(tool))
        .unwrap_or(name)
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
