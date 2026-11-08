//! The content a Codex `apply_patch` envelope leaves in each file it adds or
//! updates, worked out from the patch and the files as they are, so a caller
//! can judge what a file will hold before the patch is applied.
//!
//! An added file holds its `+` lines. An updated file has each hunk's old
//! lines (context and `-`) replaced by its new lines (context and `+`), found
//! in order from where the last hunk ended, as Codex finds them: exactly, then
//! ignoring trailing white space, then ignoring white space at both ends. A
//! `@@ <line>` header moves the search past that line first. A file whose
//! hunks cannot be found this way is reported with no content: Codex may still
//! apply the patch with a match this replay does not make, so its outcome is
//! unknown, never guessed.

use super::strip_header;

/// One file the patch adds or updates and the content it leaves there:
/// `None` when that cannot be worked out (the file to update cannot be read,
/// or a hunk is not found in it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replayed {
    /// The path as the patch names it (a move's destination for a moved file).
    pub path: String,
    /// The whole content the patch leaves in the file.
    pub content: Option<String>,
}

/// What a file section of the patch does.
enum Op<'a> {
    Add,
    Update { to: Option<&'a str> },
    Delete,
}

/// One file section: its header, the path it names and its body lines.
struct Section<'a> {
    op: Op<'a>,
    path: &'a str,
    body: Vec<&'a str>,
}

/// The content the patch `text` leaves in every file it adds or updates, in
/// the order it names them, `read` giving a file's content as it is now
/// (`None` when it cannot be read). A file the patch touches twice is
/// replayed in order. Deleted files and a move's source are left out: they
/// hold nothing afterwards.
#[must_use]
pub fn replay(text: &str, read: &dyn Fn(&str) -> Option<String>) -> Vec<Replayed> {
    let mut out: Vec<Replayed> = Vec::new();
    for section in sections(text) {
        let (dest, content) = match section.op {
            Op::Delete => {
                out.retain(|r| r.path != section.path);
                continue;
            }
            Op::Add => (section.path, Some(added(&section.body))),
            Op::Update { to } => {
                let before = match out.iter().find(|r| r.path == section.path) {
                    Some(earlier) => earlier.content.clone(),
                    None => read(section.path),
                };
                let content = before.and_then(|text| updated(&text, &section.body));
                if to.is_some() {
                    out.retain(|r| r.path != section.path);
                }
                (to.unwrap_or(section.path), content)
            }
        };
        out.retain(|r| r.path != dest);
        out.push(Replayed {
            path: dest.to_owned(),
            content,
        });
    }
    out
}

/// The file sections of `text`, split at the headers [`super::writes`]
/// reads. A `*** Move to:` line belongs to the update before it.
fn sections(text: &str) -> Vec<Section<'_>> {
    let mut out: Vec<Section<'_>> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let header = |h: &str| strip_header(trimmed, h).map(str::trim);
        if let Some(path) = header("*** Add File:") {
            out.push(Section {
                op: Op::Add,
                path,
                body: Vec::new(),
            });
        } else if let Some(path) = header("*** Update File:") {
            out.push(Section {
                op: Op::Update { to: None },
                path,
                body: Vec::new(),
            });
        } else if let Some(path) = header("*** Delete File:") {
            out.push(Section {
                op: Op::Delete,
                path,
                body: Vec::new(),
            });
        } else if let Some(dest) = header("*** Move to:") {
            if let Some(Section {
                op: Op::Update { to },
                ..
            }) = out.last_mut()
            {
                *to = Some(dest);
            }
        } else if !trimmed.eq_ignore_ascii_case("*** End Patch")
            && !trimmed.eq_ignore_ascii_case("*** Begin Patch")
            && let Some(section) = out.last_mut()
        {
            section.body.push(line);
        }
    }
    out.retain(|s| !s.path.is_empty());
    out
}

/// An added file's content: its `+` lines.
fn added(body: &[&str]) -> String {
    let mut text = String::new();
    for line in body {
        if let Some(rest) = line.strip_prefix('+') {
            text.push_str(rest);
            text.push('\n');
        }
    }
    text
}

/// One hunk of an update: the line after `@@`, if any, and its old and new
/// lines.
#[derive(Default)]
struct Hunk<'a> {
    anchor: Option<&'a str>,
    old: Vec<&'a str>,
    new: Vec<&'a str>,
}

/// `text` with the hunks of `body` applied; `None` when one is not found or
/// the body holds a line that is no hunk line.
fn updated(text: &str, body: &[&str]) -> Option<String> {
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let mut cursor = 0;
    for hunk in hunks(body)? {
        if let Some(anchor) = hunk.anchor {
            let at = (cursor..lines.len()).find(|&i| lines[i].trim() == anchor.trim())?;
            cursor = at + 1;
        }
        let at = if hunk.old.is_empty() {
            lines.len()
        } else {
            find(&lines, &hunk.old, cursor)?
        };
        let new: Vec<String> = hunk.new.iter().map(|l| (*l).to_owned()).collect();
        let len = new.len();
        lines.splice(at..at + hunk.old.len(), new);
        cursor = at + len;
    }
    let mut out = lines.join("\n");
    out.push('\n');
    Some(out)
}

/// The hunks of an update's `body`; `None` for a line that is none of
/// context, `-`, `+`, `@@` or `*** End of File`.
fn hunks<'a>(body: &[&'a str]) -> Option<Vec<Hunk<'a>>> {
    let mut out: Vec<Hunk<'a>> = Vec::new();
    for line in body {
        if let Some(rest) = line.strip_prefix("@@") {
            let anchor = rest.trim();
            out.push(Hunk {
                anchor: (!anchor.is_empty()).then_some(anchor),
                ..Hunk::default()
            });
            continue;
        }
        if line.trim().eq_ignore_ascii_case("*** End of File") {
            continue;
        }
        if out.is_empty() {
            out.push(Hunk::default());
        }
        let hunk = out.last_mut()?;
        match line.chars().next() {
            Some('-') => hunk.old.push(&line[1..]),
            Some('+') => hunk.new.push(&line[1..]),
            Some(' ') => {
                hunk.old.push(&line[1..]);
                hunk.new.push(&line[1..]);
            }
            None => {
                hunk.old.push("");
                hunk.new.push("");
            }
            Some(_) => return None,
        }
    }
    Some(out)
}

/// Where `old` first occurs in `lines` at or after `from`: exactly, then
/// ignoring trailing white space, then ignoring white space at both ends.
fn find(lines: &[String], old: &[&str], from: usize) -> Option<usize> {
    let same = |eq: &dyn Fn(&str, &str) -> bool| {
        (from..=lines.len().checked_sub(old.len())?)
            .find(|&i| old.iter().enumerate().all(|(k, o)| eq(&lines[i + k], o)))
    };
    same(&|a, b| a == b)
        .or_else(|| same(&|a, b| a.trim_end() == b.trim_end()))
        .or_else(|| same(&|a, b| a.trim() == b.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn an_added_file_holds_its_plus_lines() {
        let patch = "*** Begin Patch\n*** Add File: .codex/config.toml\n+[features]\n+hooks = false\n*** End Patch\n";
        assert_eq!(
            replay(patch, &none),
            [Replayed {
                path: ".codex/config.toml".to_owned(),
                content: Some("[features]\nhooks = false\n".to_owned()),
            }]
        );
    }

    #[test]
    fn an_update_replaces_each_hunk_in_order() {
        let now = "model = \"x\"\n[features]\nhooks = true\nweb = true\n";
        let read = |_: &str| Some(now.to_owned());
        let patch = "*** Begin Patch\n*** Update File: c.toml\n@@ [features]\n-hooks = true\n+hooks = false\n web = true\n*** End Patch\n";
        let out = replay(patch, &read);
        assert_eq!(
            out[0].content.as_deref(),
            Some("model = \"x\"\n[features]\nhooks = false\nweb = true\n")
        );
        // Trailing white space in the file does not stop the match.
        let spaced = |_: &str| Some("hooks = true   \n".to_owned());
        let plain = "*** Update File: c.toml\n@@\n-hooks = true\n+hooks = false\n";
        assert_eq!(
            replay(plain, &spaced)[0].content.as_deref(),
            Some("hooks = false\n")
        );
    }

    #[test]
    fn an_update_that_does_not_apply_or_cannot_be_read_is_unknown() {
        let read = |_: &str| Some("a\n".to_owned());
        let patch = "*** Update File: c.toml\n@@\n-missing\n+b\n";
        assert_eq!(replay(patch, &read)[0].content, None);
        assert_eq!(replay(patch, &none)[0].content, None);
        // A line that is no hunk line.
        assert_eq!(replay("*** Update File: c\nx\n", &read)[0].content, None);
    }

    #[test]
    fn a_move_lands_at_its_destination_and_a_delete_leaves_nothing() {
        let read = |p: &str| (p == "notes.toml").then(|| "[features]\nhooks = true\n".to_owned());
        let patch = "*** Update File: notes.toml\n*** Move to: .codex/config.toml\n@@\n-hooks = true\n+hooks = false\n\
                     *** Add File: gone\n+x\n*** Delete File: gone\n";
        let out = replay(patch, &read);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].path, ".codex/config.toml");
        assert_eq!(
            out[0].content.as_deref(),
            Some("[features]\nhooks = false\n")
        );
    }

    #[test]
    fn a_file_named_twice_is_replayed_in_order() {
        let patch = "*** Add File: a\n+one\n*** Update File: a\n@@\n-one\n+two\n";
        assert_eq!(replay(patch, &none)[0].content.as_deref(), Some("two\n"));
    }
}
