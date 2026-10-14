//! Shell variables set earlier on the line, substituted where they are used.
//!
//! After `d=~/.ssh;` the word `$d/id_rsa` names `~/.ssh/id_rsa`, so it is
//! classified as that path. A variable is only substituted when every value it
//! can hold is known text: an assignment without `$`, `$( … )`, a glob or a
//! quoted `~`, or the words of a `for` header. Any other use of one keeps its
//! `env.read` and leaves the path unknown (`Sink::paths`).

use std::ops::Range;

use super::{SimpleCommand, classify_simple};
use crate::lexer::Word;
use crate::shell::{ClassifyError, MAX_DIRS, ShellContext, Sink};

/// Classify `cmd` once for each value of the known variables it uses; `false`
/// when it uses none, and the caller classifies it as written.
pub(super) fn classify_with_values(
    cmd: &SimpleCommand,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<bool, ClassifyError> {
    let (variants, used) = match expand(cmd, &sink.known_locals(depth)) {
        Ok(Some(expanded)) => expanded,
        Ok(None) => return Ok(false),
        Err(e) => {
            sink.skip(e);
            return Ok(false);
        }
    };
    // an uppercase name is by convention an environment variable: its read
    // stays an atom, which the substitution took out of the words
    sink.enter(depth);
    for name in used.into_iter().filter(|n| !crate::shell::is_lowercase(n)) {
        sink.push(crate::action::AtomicAction::EnvRead { name })?;
    }
    for variant in &variants {
        for w in variant.words.iter().chain(&variant.stdin) {
            sink.note_dollar_word(w);
        }
        for text in variant.reads.iter().chain(&variant.writes) {
            sink.note_dollar_word(&Word {
                text: text.clone(),
                ..Word::default()
            });
        }
        classify_simple(variant, ctx, sink, depth)?;
    }
    Ok(true)
}

/// The value of `name=value` when the shell's result is known text, with a
/// leading unquoted `~` expanded against `home`.
pub(super) fn assignment_value(word: &Word, home: &str) -> Option<String> {
    let (name, value) = word.text.split_once('=')?;
    if name.ends_with('+') || !word.substitutions.is_empty() || word.glob {
        return None;
    }
    let start = name.len() + 1;
    literal_value(value, start, word, home)
}

/// `export X=v`, `readonly X=v`, `local x=v`: the shell variables they set, as
/// an assignment on its own does. With an option (`declare -a`, `-i`, `-n`) the
/// value may be an array, a number or a reference: not known.
pub(super) fn note_builtin(args: &[Word], program: &str, home: &str, sink: &mut Sink) {
    if !matches!(
        program,
        "export" | "readonly" | "local" | "declare" | "typeset"
    ) {
        return;
    }
    let with_options = args.iter().any(|w| w.text.starts_with(['-', '+']));
    for word in args {
        if let Some(name) = super::assignment_name(&word.text) {
            let value = (!with_options)
                .then(|| assignment_value(word, home))
                .flatten();
            sink.note_local(name, value.map(|v| vec![v]));
        }
    }
}

/// The words of a `for` header after `in`, when each is known text.
pub(super) fn loop_values(words: &[Word], home: &str) -> Option<Vec<String>> {
    words
        .iter()
        .map(|w| {
            if !w.substitutions.is_empty() || w.glob {
                return None;
            }
            literal_value(&w.text, 0, w, home)
        })
        .collect()
}

fn literal_value(value: &str, start: usize, word: &Word, home: &str) -> Option<String> {
    // a `$` the shell expands makes the value depend on something else
    let expands = value.match_indices('$').any(|(i, _)| {
        let pos = start + i;
        !word.literal.iter().any(|span| span.contains(&pos))
    });
    if expands {
        return None;
    }
    if value == "~" || value.starts_with("~/") {
        // a quoted `~` stays literal; an unquoted one is the home directory
        let unquoted = word.unquoted.iter().any(|span| span.contains(&start));
        return unquoted.then(|| format!("{home}{}", &value[1..]));
    }
    (!value.starts_with('~')).then(|| value.to_owned())
}

/// The variants of a command, and the names substituted in them.
type Expanded = (Vec<SimpleCommand>, Vec<String>);

/// The variants of `cmd` with every use of a known variable substituted, one
/// per combination of values, and the names substituted; `None` when it uses
/// none. A use the shell would
/// transform (`${d:-x}`, `${d#*/}`) cannot be substituted: an error, which
/// leaves the command to be classified as written.
pub(super) fn expand(
    cmd: &SimpleCommand,
    known: &[(String, Vec<String>)],
) -> Result<Option<Expanded>, ClassifyError> {
    let mut used: Vec<&(String, Vec<String>)> = Vec::new();
    let words = cmd.words.iter().chain(&cmd.stdin);
    for w in words {
        for local in known {
            if uses(&w.text, &local.0, &w.literal)? && !used.iter().any(|u| u.0 == local.0) {
                used.push(local);
            }
        }
    }
    for text in cmd.reads.iter().chain(&cmd.writes) {
        for local in known {
            if uses(text, &local.0, &[])? && !used.iter().any(|u| u.0 == local.0) {
                used.push(local);
            }
        }
    }
    if used.is_empty() {
        return Ok(None);
    }
    let count = used.iter().map(|u| u.1.len().max(1)).product::<usize>();
    if count > MAX_DIRS {
        return Err(ClassifyError::TooManyValues);
    }
    let mut variants = Vec::with_capacity(count);
    for n in 0..count {
        let mut rest = n;
        let mut out = cmd.clone();
        for (name, values) in &used {
            let value = values
                .get(rest % values.len().max(1))
                .map_or("", String::as_str);
            rest /= values.len().max(1);
            for w in out.words.iter_mut().chain(out.stdin.iter_mut()) {
                substitute(w, name, value);
            }
            for text in out.reads.iter_mut().chain(out.writes.iter_mut()) {
                let mut w = Word {
                    text: std::mem::take(text),
                    ..Word::default()
                };
                substitute(&mut w, name, value);
                *text = w.text;
            }
        }
        variants.push(out);
    }
    Ok(Some((variants, used.iter().map(|u| u.0.clone()).collect())))
}

/// Whether `text` expands `$name` or `${name}` outside `literal` spans; an
/// error for a `${name…}` form with an operator.
fn uses(text: &str, name: &str, literal: &[Range<usize>]) -> Result<bool, ClassifyError> {
    let mut found = false;
    for (_, at) in references(text, name, literal) {
        match at {
            Ref::Plain | Ref::Braced => found = true,
            Ref::Transformed => return Err(ClassifyError::UnknownValue(text.to_owned())),
        }
    }
    Ok(found)
}

enum Ref {
    Plain,
    Braced,
    Transformed,
}

/// Every expanded reference to `name` in `text`: its byte position and form.
fn references(text: &str, name: &str, literal: &[Range<usize>]) -> Vec<(usize, Ref)> {
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = Vec::new();
    for (pos, _) in text.match_indices('$') {
        if literal.iter().any(|span| span.contains(&pos)) {
            continue;
        }
        let rest = &text[pos + 1..];
        if let Some(body) = rest.strip_prefix('{') {
            if let Some(after) = body.strip_prefix(name) {
                match after.chars().next() {
                    Some('}') => out.push((pos, Ref::Braced)),
                    Some(c) if !is_name(c) => out.push((pos, Ref::Transformed)),
                    _ => {}
                }
            }
        } else if let Some(after) = rest.strip_prefix(name)
            && !after.starts_with(is_name)
        {
            out.push((pos, Ref::Plain));
        }
    }
    out
}

/// Replace every expanded `$name` and `${name}` in `word` with `value`, moving
/// the quoting spans that follow.
fn substitute(word: &mut Word, name: &str, value: &str) {
    let refs = references(&word.text, name, &word.literal);
    for (pos, form) in refs.into_iter().rev() {
        let len = match form {
            Ref::Plain => 1 + name.len(),
            Ref::Braced => 3 + name.len(),
            Ref::Transformed => continue,
        };
        word.text.replace_range(pos..pos + len, value);
        // a position after the reference moves by the change in length; one inside
        // it stays within the value
        let moved = |x: usize| {
            if x >= pos + len {
                x - len + value.len()
            } else {
                pos + (x - pos).min(value.len())
            }
        };
        let shift = |r: &mut Range<usize>| {
            if r.start > pos {
                r.start = moved(r.start);
            }
            if r.end > pos {
                r.end = moved(r.end).max(r.start);
            }
        };
        word.literal.iter_mut().for_each(shift);
        word.unquoted.iter_mut().for_each(shift);
    }
}
