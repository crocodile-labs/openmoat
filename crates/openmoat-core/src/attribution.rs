//! Agent provenance for commits (ADR-056): which files of a commit an agent
//! session wrote, and, where the record allows, which added lines.
//!
//! Pure: the CLI reads the audit log's record of each session's writes
//! (ADR-039) and the commit from git, and passes both in. A write is matched
//! to a file of the commit by its content hashes, which the hook recorded when
//! it decided the call:
//!
//! - [`Evidence::Lines`]: the write turned the parent's content into the
//!   committed content, so every added line of the file is the session's.
//! - [`Evidence::Content`]: the committed content is what the write left; the
//!   person may have written some of it before.
//! - [`Evidence::Touched`]: the session wrote the file after the parent commit
//!   and before this one; what the file holds may have changed since.
//!
//! What the hook never saw (a script that writes files, an editor) is not here,
//! so a commit with no record is not shown to be a person's.

mod hunks;
mod note;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::engine::UntrustedKind;

pub use hunks::added_lines;
pub use note::{AuditHead, Discrepancy, EventHash, NOTE_FORMAT, Note, NoteFormat, compare};

/// A write recorded this long after a commit's time still counts toward it:
/// git keeps whole seconds, the audit log milliseconds.
pub const CLOCK_SLACK_MS: i64 = 2_000;

/// Lines of the committed file, from 1, both ends included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineRange {
    /// The first line.
    pub start: u32,
    /// The last line.
    pub end: u32,
}

impl LineRange {
    /// How many lines it covers.
    #[must_use]
    pub fn len(self) -> u32 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    /// Never: a range holds at least its first line.
    #[must_use]
    pub fn is_empty(self) -> bool {
        false
    }
}

/// The untrusted content a session had read before it wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Untrusted {
    /// Where it came from.
    pub kind: UntrustedKind,
    /// What it was, as the audit log has it (redacted): `fetch docs.rs`.
    pub source: String,
}

/// One session's newest recorded write of a file, as the caller found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentWrite {
    /// The file, relative to the repository, `/`-separated.
    pub path: String,
    /// The host's id.
    pub host: String,
    /// The host's session id, as the audit log has it.
    pub session: String,
    /// The audit event of the call that wrote it.
    pub event: i64,
    /// When that call was recorded (ms since the epoch).
    pub ts_ms: i64,
    /// The content hash the write left, when the hook knew it.
    pub sha256: Option<String>,
    /// The content hash before it (`""`: no file), when the hook knew it.
    pub before: Option<String>,
    /// What untrusted content the session had read before the write.
    pub untrusted: Option<Untrusted>,
}

/// A file a commit changes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChangedFile {
    /// The file, relative to the repository, `/`-separated.
    pub path: String,
    /// The content hash at the parent (`""`: no file there); `None` when not
    /// known (too large, not a regular file).
    pub before: Option<String>,
    /// The content hash at the commit, as [`ChangedFile::before`].
    pub after: Option<String>,
    /// The lines the commit adds to it.
    pub added: Vec<LineRange>,
}

/// The commit being attributed.
#[derive(Debug, Clone, Copy)]
pub struct Commit<'a> {
    /// The first parent's committer time (ms); `None` for a root commit.
    pub parent_ms: Option<i64>,
    /// The commit's committer time (ms).
    pub commit_ms: i64,
    /// What it changes.
    pub files: &'a [ChangedFile],
}

/// How strongly a write is tied to a committed file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Evidence {
    /// The write made the commit's whole change to the file.
    Lines,
    /// The committed content is what the write left.
    Content,
    /// The session wrote the file after the parent commit.
    Touched,
}

impl Evidence {
    /// The spelling notes and reports use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lines => "lines",
            Self::Content => "content",
            Self::Touched => "touched",
        }
    }
}

/// A file of a commit an agent session wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRecord {
    /// The file, relative to the repository.
    pub path: String,
    /// The host's id.
    pub host: String,
    /// The session, as the audit log has it.
    pub session: String,
    /// The audit event of the write.
    pub event: i64,
    /// When it was recorded (ms since the epoch).
    pub ts_ms: i64,
    /// How the write is tied to the file.
    pub evidence: Evidence,
    /// The added lines that are the session's: all of them for
    /// [`Evidence::Lines`], none claimed otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<LineRange>,
    /// What untrusted content the session had read before the write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub untrusted: Option<Untrusted>,
}

impl FileRecord {
    /// How many added lines are claimed.
    #[must_use]
    pub fn line_count(&self) -> u64 {
        self.lines.iter().map(|r| u64::from(r.len())).sum()
    }
}

/// The files of `commit` the recorded `writes` account for, ordered by path,
/// then event: for each session, its newest write of the file up to the
/// commit's time, matched by content, else by time after the parent commit.
#[must_use]
pub fn attribute(commit: &Commit<'_>, writes: &[AgentWrite]) -> Vec<FileRecord> {
    let until = commit.commit_ms.saturating_add(CLOCK_SLACK_MS);
    let mut out = Vec::new();
    for file in commit.files {
        // one write per session: the newest up to the commit
        let mut newest: BTreeMap<(&str, &str), &AgentWrite> = BTreeMap::new();
        for write in writes
            .iter()
            .filter(|w| w.path == file.path && w.ts_ms <= until)
        {
            let slot = newest
                .entry((write.host.as_str(), write.session.as_str()))
                .or_insert(write);
            if write.event > slot.event {
                *slot = write;
            }
        }
        for write in newest.into_values() {
            if let Some(evidence) = evidence(commit, file, write) {
                out.push(FileRecord {
                    path: file.path.clone(),
                    host: write.host.clone(),
                    session: write.session.clone(),
                    event: write.event,
                    ts_ms: write.ts_ms,
                    evidence,
                    lines: if evidence == Evidence::Lines {
                        file.added.clone()
                    } else {
                        Vec::new()
                    },
                    untrusted: write.untrusted.clone(),
                });
            }
        }
    }
    out.sort_by(|a, b| (&a.path, a.event).cmp(&(&b.path, b.event)));
    out
}

fn evidence(commit: &Commit<'_>, file: &ChangedFile, write: &AgentWrite) -> Option<Evidence> {
    let after = file.after.as_deref().filter(|h| !h.is_empty());
    if let (Some(after), Some(wrote)) = (after, write.sha256.as_deref())
        && after == wrote
    {
        let whole = file.before.is_some() && file.before == write.before;
        return Some(if whole {
            Evidence::Lines
        } else {
            Evidence::Content
        });
    }
    let after_parent = commit.parent_ms.is_none_or(|parent| write.ts_ms > parent);
    after_parent.then_some(Evidence::Touched)
}

/// What one session wrote across the commits of a change, for a review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionSummary {
    /// The host's id.
    pub host: String,
    /// The session.
    pub session: String,
    /// How many distinct files it wrote.
    pub files: usize,
    /// How many added lines are its own ([`Evidence::Lines`]).
    pub lines: u64,
    /// The untrusted content it had read before its first write that had
    /// read any, if one had.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untrusted: Option<Untrusted>,
    /// The commits it wrote in.
    pub commits: usize,
}

/// One summary per session over `notes`, ordered by host, then session.
#[must_use]
pub fn summarise(notes: &[Note]) -> Vec<SessionSummary> {
    type Acc<'a> = (
        std::collections::BTreeSet<&'a str>,
        u64,
        Option<(i64, &'a Untrusted)>,
        std::collections::BTreeSet<&'a str>,
    );
    let mut by: BTreeMap<(&str, &str), Acc<'_>> = BTreeMap::new();
    for note in notes {
        for file in &note.files {
            let acc = by
                .entry((file.host.as_str(), file.session.as_str()))
                .or_default();
            acc.0.insert(file.path.as_str());
            acc.1 = acc.1.saturating_add(file.line_count());
            if let Some(untrusted) = &file.untrusted
                && acc.2.is_none_or(|(event, _)| file.event < event)
            {
                acc.2 = Some((file.event, untrusted));
            }
            acc.3.insert(note.commit.as_str());
        }
    }
    by.into_iter()
        .map(
            |((host, session), (files, lines, untrusted, commits))| SessionSummary {
                host: host.to_owned(),
                session: session.to_owned(),
                files: files.len(),
                lines,
                untrusted: untrusted.map(|(_, u)| u.clone()),
                commits: commits.len(),
            },
        )
        .collect()
}

#[cfg(test)]
mod tests;
