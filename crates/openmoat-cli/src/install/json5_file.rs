//! A host's JSON5 file on disk: read, and refused for an edit that would drop
//! its comments. [`crate::json5`] is the parser and touches no file; a host's
//! spec says which files are JSON5 (`McpSyntax::Json5`, `HookLayout::Plugin`).

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde_json::{Map, Value};

use crate::json5::{Parsed, parse};

/// `text` (a host's file, empty when there is none) as JSON5: an empty object
/// for no text, where [`parse`] refuses it.
pub fn parse_or_empty(text: &str) -> Result<Parsed> {
    if text.trim().is_empty() {
        return Ok(Parsed {
            value: Value::Object(Map::new()),
            comments: false,
        });
    }
    parse(text)
}

fn read_parsed(path: &Path) -> Result<Parsed> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    parse_or_empty(&text).with_context(|| format!("parsing {}", path.display()))
}

/// The JSON5 file at `path` parsed, an empty object when there is none.
pub fn read(path: &Path) -> Result<Value> {
    Ok(read_parsed(path)?.value)
}

/// Refuse to write `file` back when `parsed` has comments: plain JSON has
/// none, so writing it would drop them.
pub fn refuse_comments(parsed: &Parsed, file: &Path) -> Result<()> {
    if parsed.comments {
        bail!(
            "{} has comments (JSON5), and OpenMoat writes it back as plain JSON, which would \
             drop them; move the comments out of the file (or delete them), then run the \
             command again. No file was changed",
            file.display()
        );
    }
    Ok(())
}

/// The JSON5 file at `path` parsed for an edit: refused when writing it back
/// would drop comments.
pub fn read_for_edit(path: &Path) -> Result<Value> {
    let parsed = read_parsed(path)?;
    refuse_comments(&parsed, path)?;
    Ok(parsed.value)
}

#[cfg(test)]
mod tests;
