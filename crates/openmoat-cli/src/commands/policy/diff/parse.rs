//! Reading a unified diff: the files it changes, their modes, and the lines it
//! adds, from `git diff` or from any tool that writes the unified format.
//!
//! Input that is not a diff is an error, never an empty change: a check that
//! read nothing must not pass. Hunks are read by their line counts, so a
//! removed line that reads `--- x` is never taken for the next file's header.

use std::fmt;

use openmoat_core::diffscan::{Block, Change};

/// One file a diff changes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FileChange {
    /// The path before the change; `None` for a new file.
    pub old: Option<String>,
    /// The path after the change; `None` for a deleted file.
    pub new: Option<String>,
    /// git's file mode before (`100644`, `100755`, `120000` a symbolic link,
    /// `160000` a submodule), when the diff gives it.
    pub old_mode: Option<String>,
    /// git's file mode after, when the diff gives it.
    pub new_mode: Option<String>,
    /// The diff only says the file is binary: none of its content was read.
    pub binary: bool,
    /// Each added line with its line number in the new file.
    pub added: Vec<(usize, String)>,
    /// Each run of removed and added lines with no kept line between them,
    /// for the content checks that compare what a line was with what it is.
    pub blocks: Vec<Block>,
}

impl FileChange {
    /// The file as the content checks read it, under its new path (its old
    /// one when the change deletes it).
    pub fn content(&self) -> Option<Change<'_>> {
        Some(Change {
            path: self.new.as_deref().or(self.old.as_deref())?,
            added: &self.added,
            blocks: &self.blocks,
        })
    }

    /// Every path the change writes: the old one (removed or renamed away) and
    /// the new one, once each.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        let new = self
            .new
            .as_deref()
            .filter(|n| self.old.as_deref() != Some(*n));
        self.old.as_deref().into_iter().chain(new)
    }
}

/// Why the input is not a unified diff OpenMoat can read in full.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line of the input.
    pub line: usize,
    pub problem: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.problem)
    }
}

impl std::error::Error for ParseError {}

/// Lines left in the hunk being read, the new file's next line number, and
/// whether the last line read was removed or added (a block is open).
struct Hunk {
    old: usize,
    new: usize,
    line: usize,
    changing: bool,
}

impl Hunk {
    /// The open block of `change`, opened at this line if the last line was kept.
    fn block<'c>(&mut self, change: &'c mut FileChange) -> Option<&'c mut Block> {
        if !self.changing {
            self.changing = true;
            let at = change.added.len();
            change.blocks.push(Block {
                at: self.line,
                removed: Vec::new(),
                added: at..at,
            });
        }
        change.blocks.last_mut()
    }
}

/// The file being read, with what its header said.
#[derive(Default)]
struct Current {
    change: FileChange,
    created: bool,
    deleted: bool,
    /// A hunk was read: a `---` line after it starts the next file.
    hunks: bool,
}

impl Current {
    fn finish(self) -> FileChange {
        let mut change = self.change;
        if self.created {
            change.old = None;
        }
        if self.deleted {
            change.new = None;
        }
        change
    }
}

/// The files `text` changes. Lines may end in `\n` or `\r\n`.
pub fn parse(text: &str) -> Result<Vec<FileChange>, ParseError> {
    let mut files = Vec::new();
    let mut current: Option<Current> = None;
    let mut hunk: Option<Hunk> = None;
    let mut last = 0;
    for (index, raw) in text.split('\n').enumerate() {
        let number = index + 1;
        last = number;
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(open) = hunk.as_mut().filter(|h| h.old > 0 || h.new > 0) {
            let change = current.as_mut().map(|c| &mut c.change);
            read_hunk_line(open, line, change).map_err(|problem| ParseError {
                line: number,
                problem,
            })?;
            continue;
        }
        hunk = None;
        if line.starts_with('\\') {
            // `\ No newline at end of file`, after a hunk's last line
            continue;
        }
        if let Some(rest) = line.strip_prefix("diff --git ") {
            files.extend(current.take().map(Current::finish));
            let (old, new) = header_paths(rest);
            current = Some(Current {
                change: FileChange {
                    old,
                    new,
                    ..FileChange::default()
                },
                ..Current::default()
            });
            continue;
        }
        if let Some(rest) = line.strip_prefix("--- ") {
            // A plain unified diff has no `diff --git` line: `---` starts a file.
            if current.as_ref().is_none_or(|c| c.hunks) {
                files.extend(current.take().map(Current::finish));
            }
            let file = current.get_or_insert_with(Current::default);
            file.change.old = file_path(rest, "a/");
            file.created |= file.change.old.is_none();
            continue;
        }
        let Some(file) = current.as_mut() else {
            // text before the first file: a commit message, `git format-patch` mail headers
            continue;
        };
        if let Some(rest) = line.strip_prefix("+++ ") {
            file.change.new = file_path(rest, "b/");
            file.deleted |= file.change.new.is_none();
        } else if line.starts_with("@@ ") {
            hunk = Some(hunk_header(line).ok_or(ParseError {
                line: number,
                problem: "a hunk header OpenMoat cannot read",
            })?);
            file.hunks = true;
        } else {
            read_extended_header(file, line);
        }
    }
    if hunk.is_some_and(|h| h.old > 0 || h.new > 0) {
        return Err(ParseError {
            line: last,
            problem: "the diff ends inside a hunk",
        });
    }
    files.extend(current.map(Current::finish));
    if files.is_empty() && !text.trim().is_empty() {
        return Err(ParseError {
            line: 1,
            problem: "no changed file found; the input is not a unified diff",
        });
    }
    Ok(files)
}

/// One line inside a hunk: added, removed or kept.
fn read_hunk_line(
    hunk: &mut Hunk,
    line: &str,
    change: Option<&mut FileChange>,
) -> Result<(), &'static str> {
    let taken = |left: &mut usize| -> Result<(), &'static str> {
        *left = left
            .checked_sub(1)
            .ok_or("a hunk has more lines than its header says")?;
        Ok(())
    };
    match line.chars().next() {
        Some('+') => {
            taken(&mut hunk.new)?;
            if let Some(change) = change {
                // open the block first: it starts at this line's index
                hunk.block(change);
                change.added.push((hunk.line, line[1..].to_owned()));
                let end = change.added.len();
                if let Some(block) = change.blocks.last_mut() {
                    block.added.end = end;
                }
            }
            hunk.line += 1;
        }
        Some('-') => {
            taken(&mut hunk.old)?;
            if let Some(block) = change.and_then(|c| hunk.block(c)) {
                block.removed.push(line[1..].to_owned());
            }
        }
        // An empty line is a kept empty line whose leading space was trimmed.
        Some(' ') | None => {
            taken(&mut hunk.old)?;
            taken(&mut hunk.new)?;
            hunk.line += 1;
            hunk.changing = false;
        }
        Some('\\') => {}
        Some(_) => return Err("a hunk has fewer lines than its header says"),
    }
    Ok(())
}

/// The mode, rename, copy and binary lines of a git header.
fn read_extended_header(file: &mut Current, line: &str) {
    let mode = |rest: &str| rest.trim().to_owned();
    if let Some(rest) = line.strip_prefix("new file mode ") {
        file.change.new_mode = Some(mode(rest));
        file.created = true;
    } else if let Some(rest) = line.strip_prefix("deleted file mode ") {
        file.change.old_mode = Some(mode(rest));
        file.deleted = true;
    } else if let Some(rest) = line.strip_prefix("old mode ") {
        file.change.old_mode = Some(mode(rest));
    } else if let Some(rest) = line.strip_prefix("new mode ") {
        file.change.new_mode = Some(mode(rest));
    } else if let Some(rest) = line.strip_prefix("index ") {
        // `index <old>..<new> <mode>`: the mode when it did not change
        if let Some((_, unchanged)) = rest.split_once(' ') {
            file.change.old_mode.get_or_insert_with(|| mode(unchanged));
            file.change.new_mode.get_or_insert_with(|| mode(unchanged));
        }
    } else if let Some(rest) = line
        .strip_prefix("rename from ")
        .or_else(|| line.strip_prefix("copy from "))
    {
        file.change.old = Some(unquote(rest));
    } else if let Some(rest) = line
        .strip_prefix("rename to ")
        .or_else(|| line.strip_prefix("copy to "))
    {
        file.change.new = Some(unquote(rest));
    } else if line.starts_with("Binary files ") || line == "GIT binary patch" {
        file.change.binary = true;
    }
}

/// `@@ -a[,b] +c[,d] @@`: the lines the hunk removes and adds, and where it starts.
fn hunk_header(line: &str) -> Option<Hunk> {
    let mut parts = line.strip_prefix("@@ ")?.split(' ');
    let range = |part: Option<&str>, sign: char| -> Option<(usize, usize)> {
        let range = part?.strip_prefix(sign)?;
        match range.split_once(',') {
            Some((start, count)) => Some((start.parse().ok()?, count.parse().ok()?)),
            None => Some((range.parse().ok()?, 1)),
        }
    };
    let (_, old) = range(parts.next(), '-')?;
    let (start, new) = range(parts.next(), '+')?;
    (parts.next()? == "@@").then_some(Hunk {
        old,
        new,
        line: start,
        changing: false,
    })
}

/// The path of a `---` or `+++` line: `None` for `/dev/null`, `prefix`
/// removed, and anything after a tab (a timestamp; git adds a tab after a
/// name with a space) dropped.
fn file_path(rest: &str, prefix: &str) -> Option<String> {
    let name = if rest.starts_with('"') {
        unquote(rest)
    } else {
        rest.split('\t').next().unwrap_or(rest).to_owned()
    };
    if name == "/dev/null" {
        return None;
    }
    Some(
        name.strip_prefix(prefix)
            .map_or(name.clone(), str::to_owned),
    )
}

/// The two paths of `diff --git a/<old> b/<new>`. Unquoted names may hold
/// spaces, so when both are the same name (every change but a rename or
/// copy, whose own lines then give the names) the line is split in half.
fn header_paths(rest: &str) -> (Option<String>, Option<String>) {
    let strip = |name: String, prefix: &str| name.strip_prefix(prefix).map(str::to_owned);
    if rest.starts_with('"') {
        let (old, tail) = quoted(rest);
        let new = unquote(tail.trim_start());
        return (strip(old, "a/"), strip(new, "b/"));
    }
    let len = rest.len();
    if rest.starts_with("a/") && len >= 5 && (len - 5).is_multiple_of(2) {
        let half = (len - 5) / 2;
        if let (Some(old), Some(sep), Some(new)) = (
            rest.get(2..2 + half),
            rest.get(2 + half..5 + half),
            rest.get(5 + half..),
        ) && sep == " b/"
            && old == new
        {
            return (Some(old.to_owned()), Some(new.to_owned()));
        }
    }
    match rest.split_once(" \"").or_else(|| rest.split_once(" b/")) {
        Some((old, _)) if rest.contains(" \"") => (
            strip(old.to_owned(), "a/"),
            strip(unquote(&rest[old.len() + 1..]), "b/"),
        ),
        Some((old, new)) => (strip(old.to_owned(), "a/"), Some(new.to_owned())),
        None => (None, None),
    }
}

/// A C-style quoted name as git writes it (`"a/x\ty"`, octal for other bytes),
/// or `text` as it is when it is not quoted.
pub fn unquote(text: &str) -> String {
    if text.starts_with('"') {
        quoted(text).0
    } else {
        text.to_owned()
    }
}

/// The quoted name at the start of `text`, and what follows its closing quote.
fn quoted(text: &str) -> (String, &str) {
    let body = &text[1..];
    let mut bytes = Vec::new();
    let mut chars = body.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return (String::from_utf8_lossy(&bytes).into_owned(), &body[i + 1..]),
            '\\' => {
                let Some((_, escaped)) = chars.next() else {
                    break;
                };
                let byte = match escaped {
                    'a' => 0x07,
                    'b' => 0x08,
                    't' => b'\t',
                    'n' => b'\n',
                    'v' => 0x0b,
                    'f' => 0x0c,
                    'r' => b'\r',
                    '0'..='7' => {
                        let mut value = escaped.to_digit(8).unwrap_or_default();
                        for _ in 0..2 {
                            let next = chars.clone().next().and_then(|(_, d)| d.to_digit(8));
                            if let Some(d) = next {
                                value = value * 8 + d;
                                chars.next();
                            }
                        }
                        u8::try_from(value).unwrap_or(b'?')
                    }
                    other => {
                        let mut buf = [0; 4];
                        bytes.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
                        continue;
                    }
                };
                bytes.push(byte);
            }
            other => {
                let mut buf = [0; 4];
                bytes.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    // no closing quote: the text is the name
    (text.to_owned(), "")
}
