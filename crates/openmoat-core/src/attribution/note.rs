//! The record `openmoat provenance --write-notes` keeps per commit in git
//! notes (`refs/notes/openmoat`), and the checks `--verify` makes of it.
//!
//! A note says what the local audit log held when it was written: the
//! log's head, and the chain hash of every event it cites. The digest over
//! those rows and the claims ([`Note::digest_input`]) is hashed by the CLI
//! (the core has no hash function); a note edited without the log cannot be
//! made to verify, since `--verify` checks every cited event against the
//! chain and attributes the commit again ([`compare`]).

use serde::{Deserialize, Serialize};

use super::FileRecord;

/// The `format` of every note this build writes.
pub const NOTE_FORMAT: &str = "openmoat-provenance-v1";

/// The note format; an unknown one does not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoteFormat {
    /// The first format.
    #[serde(rename = "openmoat-provenance-v1")]
    V1,
}

/// The audit log's newest event when the note was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditHead {
    /// Its id.
    pub event: i64,
    /// Its chain hash.
    pub hash: String,
}

/// An event a note cites, with its chain hash.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventHash {
    /// The event's id.
    pub event: i64,
    /// Its chain hash.
    pub hash: String,
}

/// One commit's provenance record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
    /// [`NOTE_FORMAT`].
    pub format: NoteFormat,
    /// The commit, as a full hash.
    pub commit: String,
    /// The log's head when the note was written.
    pub head: AuditHead,
    /// Every event [`Note::files`] cites, by id.
    pub events: Vec<EventHash>,
    /// The CLI's SHA-256 of [`Note::digest_input`], lowercase hex.
    pub digest: String,
    /// The files agent sessions wrote; empty when the log has none.
    pub files: Vec<FileRecord>,
}

impl Note {
    /// The bytes the digest covers: the format, the commit, the head, the
    /// cited rows and every claim, each field length-prefixed so no two
    /// notes give the same bytes.
    #[must_use]
    pub fn digest_input(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut field = |text: &str| {
            out.extend_from_slice(text.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(text.as_bytes());
            out.push(b'\n');
        };
        field(NOTE_FORMAT);
        field(&self.commit);
        field(&self.head.event.to_string());
        field(&self.head.hash);
        for row in &self.events {
            field(&row.event.to_string());
            field(&row.hash);
        }
        for file in &self.files {
            field(&file.path);
            field(&file.host);
            field(&file.session);
            field(&file.event.to_string());
            field(&file.ts_ms.to_string());
            field(file.evidence.as_str());
            let lines: Vec<String> = file
                .lines
                .iter()
                .map(|r| format!("{}-{}", r.start, r.end))
                .collect();
            field(&lines.join(","));
            match &file.untrusted {
                Some(u) => {
                    field(u.kind.as_str());
                    field(&u.source);
                }
                None => field("-"),
            }
        }
        out
    }
}

/// How a note differs from what the log says now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Discrepancy {
    /// The log has a write of the file by a session the note leaves out.
    Omitted {
        /// The file.
        path: String,
        /// The host.
        host: String,
        /// The session.
        session: String,
    },
    /// The note says something else about a write the log still has.
    Changed {
        /// The file.
        path: String,
        /// The host.
        host: String,
        /// The session.
        session: String,
        /// What differs.
        what: &'static str,
    },
}

/// How `claimed` (a note's files) differs from `found` (the commit
/// attributed again from today's log). A claim the log can no longer
/// recompute (the lookup row was replaced by a later write, or aged out) is
/// not a discrepancy: the cited event's chain hash is checked instead.
#[must_use]
pub fn compare(claimed: &[FileRecord], found: &[FileRecord]) -> Vec<Discrepancy> {
    let mut out = Vec::new();
    let same = |a: &FileRecord, b: &FileRecord| {
        a.path == b.path && a.host == b.host && a.session == b.session
    };
    for now in found {
        let Some(note) = claimed.iter().find(|c| same(c, now)) else {
            out.push(Discrepancy::Omitted {
                path: now.path.clone(),
                host: now.host.clone(),
                session: now.session.clone(),
            });
            continue;
        };
        let what = if note.event != now.event || note.ts_ms != now.ts_ms {
            Some("the write it cites")
        } else if note.evidence != now.evidence || note.lines != now.lines {
            Some("how the write is tied to the file")
        } else if note.untrusted.as_ref().map(|u| u.kind) != now.untrusted.as_ref().map(|u| u.kind)
        {
            Some("whether the session had read untrusted content")
        } else {
            None
        };
        if let Some(what) = what {
            out.push(Discrepancy::Changed {
                path: now.path.clone(),
                host: now.host.clone(),
                session: now.session.clone(),
                what,
            });
        }
    }
    out
}
