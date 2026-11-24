//! Shell variables set earlier on the line, substituted where they are used.
//!
//! After `d=~/.ssh;` the word `$d/id_rsa` names `~/.ssh/id_rsa`, so it is
//! classified as that path. A variable is only substituted when every value it
//! can hold is known text: an assignment without `$`, `$( … )`, a glob or a
//! quoted `~`, the words of a `for` header, or an assignment from known
//! variables, plainly or with a prefix or suffix removed (`n=${x#*:}`,
//! `trim.rs`). A command classified once per value leaves each variable it
//! sets with every value it took (`merge_variants`). Any other use of one
//! keeps its `env.read` and leaves the path unknown (`Sink::paths`).

mod slice;
mod trim;

use std::ops::Range;

use super::{SimpleCommand, classify_as_written};
use crate::lexer::Word;
use crate::shell::{ClassifyError, MAX_DIRS, ShellContext, Sink};
use slice::Slice;
use trim::Trim;

/// Classify `cmd` once for each value of the known variables it uses; `false`
/// when it uses none, and the caller classifies it as written.
pub(super) fn classify_with_values(
    cmd: &SimpleCommand,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<bool, ClassifyError> {
    let separators = separator_sets(sink, depth);
    let (variants, used) = match expand(cmd, &sink.known_locals(depth), &separators) {
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
    let before = sink.locals.clone();
    let mut set = Vec::with_capacity(variants.len());
    for variant in &variants {
        for w in variant.words.iter().chain(&variant.stdin) {
            sink.note_dollar_word(w);
            // `x='.e*'; cat $x`: the shell expands a glob an unquoted value holds
            if w.glob && !sink.glob_words.contains(&w.text) {
                sink.glob_words.push(w.text.clone());
            }
        }
        for text in variant.reads.iter().chain(&variant.writes) {
            sink.note_dollar_word(&Word {
                text: text.clone(),
                ..Word::default()
            });
        }
        // one round, as the shell does: a value is not expanded again
        sink.locals.clone_from(&before);
        let classified = classify_as_written(variant, ctx, sink, depth);
        set.push(std::mem::take(&mut sink.locals));
        if let Err(e) = classified {
            sink.locals = merge_variants(&before, &set, false);
            return Err(e);
        }
    }
    sink.locals = merge_variants(&before, &set, true);
    Ok(true)
}

/// A shell variable, the depth it was set at, and its values when all are known.
type Local = (String, u8, Option<Vec<String>>);

/// The variables after a command classified once per variant: each one a
/// variant set (`n=${x#*:}`, `y=$x`) may hold any value it took in any
/// variant, so `for x in a b; do y=$x` leaves `y` as `a` or `b`, not the last.
/// One that some variant did not set, or any variant when they did not all
/// finish (`complete` false), is not known.
fn merge_variants(before: &[Local], sets: &[Vec<Local>], complete: bool) -> Vec<Local> {
    let mut changed: Vec<(&str, u8)> = Vec::new();
    for (name, depth, _) in sets.iter().flatten().filter(|l| !before.contains(l)) {
        if !changed.contains(&(name.as_str(), *depth)) {
            changed.push((name, *depth));
        }
    }
    let mut merged = before.to_vec();
    for (name, depth) in changed {
        let mut values = complete.then(Vec::new);
        for set in sets {
            let local = set.iter().find(|(n, d, _)| n == name && *d == depth);
            match (local.and_then(|(_, _, v)| v.as_ref()), values.as_mut()) {
                (Some(known), Some(all)) => {
                    for value in known {
                        if !all.contains(value) {
                            all.push(value.clone());
                        }
                    }
                }
                _ => values = None,
            }
        }
        merged.retain(|(n, d, _)| !(n == name && *d == depth));
        merged.push((name.to_owned(), depth, values));
    }
    merged
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

/// `read`, `mapfile`, `readarray` and `getopts` set the variables they name to
/// text the line does not show: each name-shaped argument is noted as a shell
/// variable whose value is not known (an option's value noted too only makes
/// a path unknown).
pub(super) fn note_read_targets(args: &[Word], program: &str, sink: &mut Sink) {
    if !matches!(program, "read" | "mapfile" | "readarray" | "getopts") {
        return;
    }
    let is_name = |t: &str| {
        t.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    for word in args.iter().filter(|w| is_name(&w.text)) {
        sink.note_local(&word.text, None);
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

/// The characters the shell splits an unquoted expansion at: space, tab and
/// newline, and each value the line gave `IFS`, all of which are classified
/// so that a split never loosens the verdict. An `IFS` whose value is not
/// known (`read IFS`) leaves the split unknown too (skipped).
fn separator_sets(sink: &mut Sink, depth: u8) -> Vec<String> {
    let default = " \t\n".to_owned();
    let ifs = sink
        .locals
        .iter()
        .find(|(n, d, _)| n == "IFS" && *d == depth)
        .map(|(_, _, v)| v.clone());
    match ifs {
        None => vec![default],
        Some(Some(values)) => std::iter::once(default).chain(values).collect(),
        Some(None) => {
            sink.skip(ClassifyError::UnknownValue("$IFS".to_owned()));
            vec![default]
        }
    }
}

/// The variants of a command, and the names substituted in them.
type Expanded = (Vec<SimpleCommand>, Vec<String>);

/// The variants of `cmd` with every use of a known variable substituted, one
/// per combination of values and set of `separators`, and the names
/// substituted; `None` when it uses none. A use the shell would
/// transform (`${d:-x}`, `${d#*/}`) cannot be substituted: an error, which
/// leaves the command to be classified as written.
pub(super) fn expand(
    cmd: &SimpleCommand,
    known: &[(String, Vec<String>)],
    separators: &[String],
) -> Result<Option<Expanded>, ClassifyError> {
    let mut used: Vec<&(String, Vec<String>)> = Vec::new();
    let words = cmd.words.iter().chain(&cmd.stdin);
    for w in words {
        for local in known {
            if uses(&w.text, &local.0, &w.literal, &w.unquoted)?
                && !used.iter().any(|u| u.0 == local.0)
            {
                used.push(local);
            }
        }
    }
    for text in cmd.reads.iter().chain(&cmd.writes) {
        for local in known {
            if uses(text, &local.0, &[], &[])? && !used.iter().any(|u| u.0 == local.0) {
                used.push(local);
            }
        }
    }
    if used.is_empty() {
        return Ok(None);
    }
    // `${!r}` may name any of them: each is substituted with every value it holds
    let indirect = cmd
        .words
        .iter()
        .chain(&cmd.stdin)
        .any(|w| w.text.contains("${!"));
    if indirect {
        for local in known {
            if !used.iter().any(|u| u.0 == local.0) {
                used.push(local);
            }
        }
    }
    let count = used.iter().map(|u| u.1.len().max(1)).product::<usize>();
    if count * separators.len() > MAX_DIRS {
        return Err(ClassifyError::TooManyValues);
    }
    let mut variants = Vec::with_capacity(count * separators.len());
    for n in 0..count {
        let mut rest = n;
        let mut out = cmd.clone();
        // per word, the text unquoted references put there: the shell splits it
        let mut fields = vec![Vec::new(); out.words.len()];
        let chosen: Vec<(&str, &str)> = used
            .iter()
            .map(|(name, values)| {
                let value = values
                    .get(rest % values.len().max(1))
                    .map_or("", String::as_str);
                rest /= values.len().max(1);
                (name.as_str(), value)
            })
            .collect();
        let lookup = |target: &str| {
            chosen
                .iter()
                .find(|(n, _)| *n == target)
                .map(|(_, v)| (*v).to_owned())
        };
        for &(name, value) in &chosen {
            for (w, f) in out.words.iter_mut().zip(fields.iter_mut()) {
                substitute(w, name, value, f, &lookup)?;
            }
            // a here-string and a redirection target are not split
            for w in &mut out.stdin {
                substitute(w, name, value, &mut Vec::new(), &lookup)?;
            }
            for text in out.reads.iter_mut().chain(out.writes.iter_mut()) {
                let mut w = Word {
                    text: std::mem::take(text),
                    ..Word::default()
                };
                substitute(&mut w, name, value, &mut Vec::new(), &lookup)?;
                *text = w.text;
            }
        }
        for set in separators {
            let mut split = out.clone();
            split.words = out
                .words
                .iter()
                .zip(&fields)
                .flat_map(|(w, f)| split_fields(w, f, set))
                .collect();
            variants.push(split);
        }
    }
    Ok(Some((variants, used.iter().map(|u| u.0.clone()).collect())))
}

/// The words the shell makes of `word` after expansion (field splitting):
/// it is cut at each of `separators` inside `fields`, the text unquoted
/// references put there, and empty pieces are dropped (`x=; $x env` runs
/// `env`). An unquoted value's `*`, `?` or `[` makes its piece a glob.
fn split_fields(word: &Word, fields: &[Range<usize>], separators: &str) -> Vec<Word> {
    if fields.is_empty() {
        return vec![word.clone()];
    }
    let in_field = |at: usize| fields.iter().any(|f| f.contains(&at));
    let mut cuts = vec![0];
    for (at, c) in word.text.char_indices() {
        if separators.contains(c) && in_field(at) {
            cuts.extend([at, at + c.len_utf8()]);
        }
    }
    cuts.push(word.text.len());
    let mut out: Vec<Word> = Vec::new();
    for piece in cuts.chunks(2).filter_map(|c| match c {
        [a, b] if a < b => Some(*a..*b),
        _ => None,
    }) {
        let within = |spans: &[Range<usize>]| -> Vec<Range<usize>> {
            spans
                .iter()
                .filter(|s| s.start < piece.end && s.end > piece.start)
                .map(|s| s.start.max(piece.start) - piece.start..s.end.min(piece.end) - piece.start)
                .collect()
        };
        let glob = word.glob
            || word.text[piece.clone()]
                .char_indices()
                .any(|(i, c)| matches!(c, '*' | '?' | '[') && in_field(piece.start + i));
        out.push(Word {
            text: word.text[piece.clone()].to_owned(),
            quoted: word.quoted,
            glob,
            literal: within(&word.literal),
            unquoted: within(&word.unquoted),
            substitutions: if out.is_empty() {
                word.substitutions.clone()
            } else {
                Vec::new()
            },
        });
    }
    // `""$x` with an empty `x` is still an (empty) word
    if out.is_empty() && word.quoted {
        out.push(word.clone());
    }
    out
}

/// Whether `text` expands `$name`, `${name}` or a trim of it ([`Trim`])
/// outside `literal` spans; an error for a `${name…}` form with any other
/// operator, or a trim this module does not read.
fn uses(
    text: &str,
    name: &str,
    literal: &[Range<usize>],
    unquoted: &[Range<usize>],
) -> Result<bool, ClassifyError> {
    let mut found = false;
    for (_, at) in references(text, name, literal, unquoted) {
        match at {
            Ref::Plain | Ref::Braced | Ref::Trimmed(..) | Ref::Sliced(..) | Ref::Indirect(_) => {
                found = true;
            }
            Ref::Transformed => return Err(ClassifyError::UnknownValue(text.to_owned())),
        }
    }
    Ok(found)
}

enum Ref {
    Plain,
    Braced,
    /// `${name#pattern}` and its kin, with the length of the whole expansion.
    Trimmed(Trim, usize),
    /// `${name:offset:length}`, with the length of the whole expansion (`slice.rs`).
    Sliced(Slice, usize),
    /// `${!name}`: the variable `name`'s value names, with the length of the
    /// whole expansion.
    Indirect(usize),
    Transformed,
}

/// Every expanded reference to `name` in `text`: its byte position and form.
/// A trim whose pattern holds `*` or `?` is read only when all of it lies in
/// one of `unquoted` (`trim.rs`).
fn references(
    text: &str,
    name: &str,
    literal: &[Range<usize>],
    unquoted: &[Range<usize>],
) -> Vec<(usize, Ref)> {
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = Vec::new();
    for (pos, _) in text.match_indices('$') {
        if literal.iter().any(|span| span.contains(&pos)) {
            continue;
        }
        let rest = &text[pos + 1..];
        if rest
            .strip_prefix("{!")
            .and_then(|b| b.strip_prefix(name))
            .is_some_and(|a| a.starts_with('}'))
        {
            out.push((pos, Ref::Indirect(4 + name.len())));
        } else if let Some(body) = rest.strip_prefix('{') {
            if let Some(after) = body.strip_prefix(name) {
                match after.chars().next() {
                    Some('}') => out.push((pos, Ref::Braced)),
                    Some(c) if !is_name(c) => {
                        if let Some((slice, used)) = Slice::parse(after) {
                            out.push((pos, Ref::Sliced(slice, 2 + name.len() + used)));
                            continue;
                        }
                        let read = Trim::parse(after).and_then(|(trim, used)| {
                            let len = 2 + name.len() + used;
                            let whole = unquoted
                                .iter()
                                .any(|s| s.start <= pos && pos + len <= s.end);
                            (whole || !trim.is_glob()).then_some(Ref::Trimmed(trim, len))
                        });
                        out.push((pos, read.unwrap_or(Ref::Transformed)));
                    }
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
/// the quoting spans that follow, and add to `fields` where an unquoted one
/// put its value (not in double quotes: `"$x"` stays one word).
fn substitute(
    word: &mut Word,
    name: &str,
    value: &str,
    fields: &mut Vec<Range<usize>>,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<(), ClassifyError> {
    let refs = references(&word.text, name, &word.literal, &word.unquoted);
    let mut trimmed = false;
    for (pos, form) in refs.into_iter().rev() {
        let (len, value) = match form {
            Ref::Plain => (1 + name.len(), value.to_owned()),
            Ref::Braced => (3 + name.len(), value.to_owned()),
            Ref::Trimmed(trim, len) => {
                trimmed = true;
                let kept = trim
                    .apply(value)
                    .ok_or_else(|| ClassifyError::UnknownValue(word.text.clone()))?;
                (len, kept)
            }
            Ref::Sliced(slice, len) => {
                trimmed = true;
                let kept = slice
                    .apply(value)
                    .ok_or_else(|| ClassifyError::UnknownValue(word.text.clone()))?;
                (len, kept)
            }
            // `r=v; ${!r}` is `$v`: its value when it is known, else the
            // variable itself, whose read is still an atom (`${GITHUB_TOKEN}`)
            Ref::Indirect(len) => {
                let target = value;
                let is_name = target.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                    && target
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_');
                if !is_name {
                    return Err(ClassifyError::UnknownValue(word.text.clone()));
                }
                (
                    len,
                    lookup(target).unwrap_or_else(|| format!("${{{target}}}")),
                )
            }
            Ref::Transformed => continue,
        };
        let value = value.as_str();
        let unquoted = word.unquoted.iter().any(|span| span.contains(&pos));
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
        fields.iter_mut().for_each(shift);
        if unquoted {
            fields.push(pos..pos + value.len());
        }
    }
    if trimmed {
        // a trim's `*` is its pattern, not a glob the shell expands; what is
        // left unquoted (the value an unquoted trim put there included) still is
        word.glob = word.text.char_indices().any(|(at, c)| {
            matches!(c, '*' | '?' | '[') && word.unquoted.iter().any(|s| s.contains(&at))
        });
    }
    Ok(())
}
