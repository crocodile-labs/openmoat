//! OpenMoat's entries in a YAML file's `hooks` mapping
//! (`hooks: {<event>: [entry, …]}`, Hermes Agent's `config.yaml`), edited as
//! text.
//!
//! The host writes the file itself and people annotate it, so it is never
//! rewritten from a parsed value, which would drop every comment and change
//! the layout. Only the lines of OpenMoat's own entries are added or taken
//! out, in block style. The edit is then checked: the new text, parsed, must
//! be exactly the old document with the [`HookFile`] edit applied
//! (`upsert` and `remove` on `dyn HookFile`). A file the
//! line edit cannot change that way (a `hooks` written inline, a quoted key,
//! anchors under `hooks`) is refused with the entry to add by hand; nothing is
//! written then.
//!
//! The parse is OpenMoat's strict YAML ([`openmoat_core::yaml`]): a file with a
//! repeated key, a merge key or an unknown tag is refused as well.

use serde_json::{Map, Value};
use thiserror::Error;

use super::{HookFile, HookFileError, HookOutcome};
use crate::HookSpec;

/// Why a YAML hook file was not edited.
#[derive(Debug, Error)]
pub enum YamlHookError {
    /// The file is not one YAML document OpenMoat reads.
    #[error("{file} is not YAML OpenMoat reads: {reason}")]
    Unreadable {
        /// The file, as the message names it.
        file: String,
        /// What the parser said.
        reason: String,
    },
    /// The document has no place for the entries.
    #[error(transparent)]
    Shape(#[from] HookFileError),
    /// The line edit would not give the document it must.
    #[error(
        "OpenMoat edits only its own lines of {file} and cannot do that here ({why}); \
         nothing was written. Add this under `hooks:` in {file} yourself, then run \
         `openmoat init` again:\n{entry}"
    )]
    Layout {
        /// The file, as the message names it.
        file: String,
        /// What stopped the edit.
        why: String,
        /// The entries to add, as YAML.
        entry: String,
    },
}

/// `text` parsed: an empty file, or one that holds only comments, is an
/// empty mapping.
///
/// # Errors
/// The text is not one well-formed YAML document under OpenMoat's strict
/// rules ([`openmoat_core::yaml`]).
pub fn parse(text: &str) -> Result<Value, String> {
    if text
        .lines()
        .all(|l| blank(l) || l.trim_start().starts_with('#'))
    {
        return Ok(Value::Object(Map::new()));
    }
    match openmoat_core::yaml::from_str::<Value>(text) {
        Ok(Value::Null) => Ok(Value::Object(Map::new())),
        Ok(value) => Ok(value),
        Err(e) => Err(e.to_string()),
    }
}

/// `text` with an entry of `layout` for each of `hooks` that runs `binary`
/// as `guard --host <id>`, and what that changed; the text unchanged when
/// every entry was already there.
///
/// # Errors
/// The file does not parse, has no place for the entries, or the line edit
/// cannot give the document the edit must ([`YamlHookError`]).
pub fn upsert(
    layout: &'static dyn HookFile,
    text: &str,
    file: &str,
    id: &str,
    hooks: &[HookSpec],
    binary: &str,
) -> Result<(HookOutcome, String), YamlHookError> {
    let root = parse(text).map_err(|reason| YamlHookError::Unreadable {
        file: file.to_owned(),
        reason,
    })?;
    let mut expected = root.clone();
    fill_empty(&mut expected, hooks);
    let outcome = layout.upsert(&mut expected, file, id, hooks, binary, || false)?;
    if outcome == HookOutcome::Unchanged {
        return Ok((outcome, text.to_owned()));
    }
    let layout_error = |why: String| YamlHookError::Layout {
        file: file.to_owned(),
        why,
        entry: entries_text(layout, id, hooks, binary),
    };
    let mut doc = Lines::of(text);
    for spec in hooks {
        let entry = layout.entry(spec, id, binary, false);
        doc.upsert(spec.event, &entry, layout, id)
            .map_err(layout_error)?;
    }
    let edited = doc.text();
    check(&edited, &expected).map_err(layout_error)?;
    Ok((outcome, edited))
}

/// `text` without `layout`'s entries for `id`, and without the event lists
/// and `hooks` mapping that leaves empty; `None` when it holds none.
///
/// # Errors
/// The file does not parse, or the line edit cannot give the document the
/// removal must ([`YamlHookError`]).
pub fn remove(
    layout: &'static dyn HookFile,
    text: &str,
    file: &str,
    id: &str,
) -> Result<Option<String>, YamlHookError> {
    let root = parse(text).map_err(|reason| YamlHookError::Unreadable {
        file: file.to_owned(),
        reason,
    })?;
    let mut expected = root;
    if !layout.remove(&mut expected, id) {
        return Ok(None);
    }
    let mut doc = Lines::of(text);
    doc.remove_ours(layout, id);
    let edited = doc.text();
    check(&edited, &expected).map_err(|why| YamlHookError::Layout {
        file: file.to_owned(),
        why,
        entry: "(remove the entries whose `command` runs `guard --host ".to_owned() + id + "`)",
    })?;
    Ok(Some(edited))
}

/// `root` with a `hooks:` or `hooks.<event>:` written with no value (`null`
/// in YAML, which Hermes reads as none) as the empty mapping or list it
/// stands for, so the entries can go below it.
fn fill_empty(root: &mut Value, hooks: &[HookSpec]) {
    let Some(top) = root.as_object_mut() else {
        return;
    };
    if top.get("hooks").is_some_and(Value::is_null) {
        top.insert("hooks".to_owned(), Value::Object(Map::new()));
    }
    if let Some(Value::Object(events)) = top.get_mut("hooks") {
        for spec in hooks {
            if events.get(spec.event).is_some_and(Value::is_null) {
                events.insert(spec.event.to_owned(), Value::Array(Vec::new()));
            }
        }
    }
}

/// Whether `edited` parses to `expected`.
fn check(edited: &str, expected: &Value) -> Result<(), String> {
    match parse(edited) {
        Ok(value) if value == *expected => Ok(()),
        Ok(_) => {
            Err("the file's `hooks` is laid out in a way the line edit does not follow".into())
        }
        Err(e) => Err(format!("the edited file would not parse: {e}")),
    }
}

/// The entries for `hooks`, as the YAML a person adds under `hooks:`.
fn entries_text(layout: &dyn HookFile, id: &str, hooks: &[HookSpec], binary: &str) -> String {
    let mut out = String::new();
    for spec in hooks {
        out.push_str("  ");
        out.push_str(spec.event);
        out.push_str(":\n");
        for line in item_lines(&layout.entry(spec, id, binary, false), 4).unwrap_or_default() {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// The block-style lines of one sequence item at `indent`: `- key: value`,
/// then each further key below the first. Values are written as JSON
/// scalars, which YAML reads as the same values; `None` for an entry that is
/// not a mapping of scalars.
fn item_lines(entry: &Value, indent: usize) -> Option<Vec<String>> {
    let object = entry.as_object()?;
    let mut lines = Vec::new();
    for (i, (key, value)) in object.iter().enumerate() {
        if value.is_object() || value.is_array() || !plain_key(key) {
            return None;
        }
        let lead = if i == 0 {
            format!("{}- ", " ".repeat(indent))
        } else {
            " ".repeat(indent + 2)
        };
        lines.push(format!("{lead}{key}: {value}"));
    }
    (!lines.is_empty()).then_some(lines)
}

/// A key written without quotes that YAML reads back as itself.
fn plain_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn blank(line: &str) -> bool {
    line.trim().is_empty()
}

/// A line that holds no YAML content: blank, or only a comment.
fn inert(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.is_empty() || trimmed.starts_with('#')
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// Whether `line` (indented `at`) is the mapping key `key` and what follows
/// its colon, comment and spaces taken off: `Some("")` for a key whose value
/// is below it.
fn key_value<'l>(line: &'l str, at: usize, key: &str) -> Option<&'l str> {
    if indent_of(line) != at {
        return None;
    }
    let rest = line.trim_start_matches(' ').strip_prefix(key)?;
    let rest = rest.trim_start_matches(' ').strip_prefix(':')?;
    let rest = rest.trim_end_matches(['\n', '\r']);
    if !(rest.is_empty() || rest.starts_with([' ', '\t'])) {
        return None;
    }
    let value = match rest.find(" #").or_else(|| rest.find("\t#")) {
        Some(comment) => &rest[..comment],
        None => rest,
    };
    Some(value.trim())
}

/// A value that is no mapping and no sequence yet: OpenMoat may write its
/// own below the key.
fn empty_value(value: &str) -> bool {
    matches!(value, "" | "~" | "null" | "Null" | "NULL" | "{}" | "[]")
}

/// A sequence item line at `at`: `-` alone or followed by a space.
fn item_at(line: &str, at: usize) -> bool {
    indent_of(line) == at && {
        let trimmed = line.trim_start_matches(' ');
        trimmed.trim_end_matches(['\n', '\r']) == "-" || trimmed.starts_with("- ")
    }
}

/// The file as lines, each with its line ending.
struct Lines {
    lines: Vec<String>,
    newline: &'static str,
}

impl Lines {
    fn of(text: &str) -> Self {
        Self {
            lines: text.split_inclusive('\n').map(str::to_owned).collect(),
            newline: if text.contains("\r\n") { "\r\n" } else { "\n" },
        }
    }

    fn text(&self) -> String {
        self.lines.concat()
    }

    /// The line of the top-level `hooks:` key.
    fn hooks_line(&self) -> Option<usize> {
        self.lines
            .iter()
            .position(|l| key_value(l, 0, "hooks").is_some())
    }

    /// The end (exclusive) of the block below the key on line `key` indented
    /// `at`: the next line with content at that indentation or less, or, when
    /// `items` (a key whose value may be a sequence at its own indentation),
    /// one at that indentation that is not a sequence item. Trailing blank
    /// and comment lines are not part of it.
    fn block_end(&self, key: usize, at: usize, items: bool) -> usize {
        let mut end = key + 1;
        for (i, line) in self.lines.iter().enumerate().skip(key + 1) {
            if inert(line) {
                continue;
            }
            let indent = indent_of(line);
            if indent > at || (items && item_at(line, at)) {
                end = i + 1;
            } else {
                break;
            }
        }
        end
    }

    /// The indentation of the first line with content in `from..to`.
    fn first_indent(&self, from: usize, to: usize) -> Option<usize> {
        self.lines[from..to]
            .iter()
            .find(|l| !inert(l))
            .map(|l| indent_of(l))
    }

    /// The `hooks` children: each key line, its indentation and the end of its block.
    fn events(&self, hooks: usize) -> Vec<(usize, usize, usize)> {
        let end = self.block_end(hooks, 0, false);
        let Some(child) = self.first_indent(hooks + 1, end) else {
            return Vec::new();
        };
        (hooks + 1..end)
            .filter(|&i| {
                let line = &self.lines[i];
                indent_of(line) == child && !inert(line) && !item_at(line, child)
            })
            .map(|i| (i, child, self.block_end(i, child, true)))
            .collect()
    }

    /// Take out every sequence item under a `hooks` child that is one of
    /// `layout`'s entries for `id`, an event key left with no item and a
    /// `hooks:` left with no child.
    fn remove_ours(&mut self, layout: &dyn HookFile, id: &str) {
        let Some(hooks) = self.hooks_line() else {
            return;
        };
        // From the last event up, so earlier line numbers stay valid.
        for (key, at, end) in self.events(hooks).into_iter().rev() {
            let items = self.items(key, at, end);
            let mut kept = 0;
            for &(start, stop, item_indent) in items.iter().rev() {
                if self.is_ours_item(start, stop, item_indent, layout, id) {
                    self.lines.drain(start..stop);
                } else {
                    kept += 1;
                }
            }
            if kept == 0 && !items.is_empty() {
                self.lines.remove(key);
            }
        }
        let end = self.block_end(hooks, 0, false);
        if self.first_indent(hooks + 1, end).is_none() && hooks_value_is_empty(&self.lines[hooks]) {
            self.lines.remove(hooks);
        }
    }

    /// The sequence items below the key on line `key` (indented `at`, block
    /// ending at `end`): each item's first line, end and indentation.
    fn items(&self, key: usize, at: usize, end: usize) -> Vec<(usize, usize, usize)> {
        let Some(item_indent) = self.first_indent(key + 1, end) else {
            return Vec::new();
        };
        if item_indent < at {
            return Vec::new();
        }
        let starts: Vec<usize> = (key + 1..end)
            .filter(|&i| item_at(&self.lines[i], item_indent))
            .collect();
        starts
            .iter()
            .enumerate()
            .map(|(n, &start)| {
                let limit = starts.get(n + 1).copied().unwrap_or(end);
                // Trailing blank and comment lines stay with what follows.
                let mut stop = limit;
                while stop > start + 1 && inert(&self.lines[stop - 1]) {
                    stop -= 1;
                }
                (start, stop, item_indent)
            })
            .collect()
    }

    fn is_ours_item(
        &self,
        start: usize,
        stop: usize,
        indent: usize,
        layout: &dyn HookFile,
        id: &str,
    ) -> bool {
        let text: String = self.lines[start..stop]
            .iter()
            .map(|l| l.get(indent.min(indent_of(l))..).unwrap_or(l))
            .collect();
        match parse(&text) {
            Ok(Value::Array(items)) => items.len() == 1 && layout.is_ours(&items[0], id),
            _ => false,
        }
    }

    /// Put `entry` in `hooks.<event>` as `upsert` on `dyn HookFile` does: in place of
    /// the first of `layout`'s entries for `id`, else after the last item,
    /// adding the event key and the `hooks:` key when they are missing.
    fn upsert(
        &mut self,
        event: &str,
        entry: &Value,
        layout: &dyn HookFile,
        id: &str,
    ) -> Result<(), String> {
        let nl = self.newline;
        let Some(hooks) = self.hooks_line() else {
            if let Some(last) = self.lines.last_mut()
                && !last.ends_with('\n')
            {
                last.push_str(nl);
            }
            self.lines.push(format!("hooks:{nl}"));
            self.lines.push(format!("  {event}:{nl}"));
            self.push_item(self.lines.len(), entry, 4)?;
            return Ok(());
        };
        let value = key_value(&self.lines[hooks], 0, "hooks").unwrap_or_default();
        if !value.is_empty() {
            if !empty_value(value) {
                return Err("`hooks` is written on one line".into());
            }
            self.lines[hooks] = format!("hooks:{nl}");
        }
        let events = self.events(hooks);
        let child = events.first().map_or(2, |&(_, at, _)| at);
        let found = events
            .iter()
            .copied()
            .find(|&(line, at, _)| key_value(&self.lines[line], at, event).is_some());
        let Some((line, at, end)) = found else {
            self.lines
                .insert(hooks + 1, format!("{}{event}:{nl}", " ".repeat(child)));
            return self.push_item(hooks + 2, entry, child + 2);
        };
        let value = key_value(&self.lines[line], at, event).unwrap_or_default();
        if !value.is_empty() {
            if !empty_value(value) {
                return Err(format!("`hooks.{event}` is written on one line"));
            }
            self.lines[line] = format!("{}{event}:{nl}", " ".repeat(at));
        }
        let items = self.items(line, at, end);
        if let Some(&(start, stop, indent)) = items
            .iter()
            .find(|&&(start, stop, indent)| self.is_ours_item(start, stop, indent, layout, id))
        {
            self.lines.drain(start..stop);
            return self.push_item(start, entry, indent);
        }
        let (at_line, indent) = match items.last() {
            Some(&(_, stop, indent)) => (stop, indent),
            None if self.first_indent(line + 1, end).is_some() => {
                return Err(format!("`hooks.{event}` is not a list of entries"));
            }
            None => (line + 1, at + 2),
        };
        self.push_item(at_line, entry, indent)
    }

    fn push_item(&mut self, at: usize, entry: &Value, indent: usize) -> Result<(), String> {
        let lines = item_lines(entry, indent).ok_or("the entry is not a mapping of values")?;
        for (n, line) in lines.into_iter().enumerate() {
            self.lines.insert(at + n, line + self.newline);
        }
        Ok(())
    }
}

/// Whether the `hooks:` line holds no value of its own after the colon.
fn hooks_value_is_empty(line: &str) -> bool {
    key_value(line, 0, "hooks").is_some_and(empty_value)
}

#[cfg(test)]
mod tests;
