//! Provenance notes (ADR-056): built from the local audit log, kept as JSON
//! in git notes, and verified against the log they came from.
//!
//! An agent may not forge one: `openmoat provenance --write-notes` is for a
//! person, the audit log an agent would need to cite is outside its sandbox,
//! and [`verify`] checks every cited event's chain hash, the head, the digest
//! and the claims themselves against the log. A note that is simply missing
//! proves nothing; the docs say so.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result};
use openmoat_audit::{ChainReport, EventId, Store};
use openmoat_core::attribution::{
    AuditHead, Discrepancy, EventHash, FileRecord, NOTE_FORMAT, Note, NoteFormat, compare,
};
use serde::Serialize;

use crate::integrity::sha256_hex;

/// Most bytes of a note that are read: a commit with every file of a large
/// change attributed stays far below it.
pub const MAX_NOTE_BYTES: usize = 4 * 1024 * 1024;

/// The note for `commit` with the attributed `files`, citing the log as it
/// is now.
pub fn build(store: &Store, commit: &str, files: Vec<FileRecord>) -> Result<Note> {
    let head = store
        .head()?
        .context("the audit log has no chained events yet; there is nothing to cite")?;
    let cited: BTreeSet<i64> = files.iter().map(|f| f.event).collect();
    let mut events = Vec::new();
    for event in cited {
        let hash = store.hash_of(EventId(event))?.unwrap_or_default();
        events.push(EventHash { event, hash });
    }
    let mut note = Note {
        format: NoteFormat::V1,
        commit: commit.to_owned(),
        head: AuditHead {
            event: head.id.0,
            hash: head.hash,
        },
        events,
        digest: String::new(),
        files,
    };
    note.digest = digest(&note);
    Ok(note)
}

/// The SHA-256 of what the note's digest covers.
pub fn digest(note: &Note) -> String {
    sha256_hex(&note.digest_input())
}

/// The note as the one line of JSON git keeps.
pub fn encode(note: &Note) -> Result<String> {
    Ok(serde_json::to_string(note)?)
}

/// A note read back; an unknown format or field is an error.
pub fn decode(text: &str) -> Result<Note> {
    serde_json::from_str(text.trim()).with_context(|| format!("not an {NOTE_FORMAT} note"))
}

/// What `--verify` found for one commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Checked {
    /// The commit.
    pub commit: String,
    /// Whether it has a note.
    pub noted: bool,
    /// Each way the note and the log disagree; empty when it verifies.
    pub problems: Vec<String>,
}

/// Check `note`, the note on `commit`, against the log: the digest, the
/// head, every cited event, and the claims against `found` (the commit
/// attributed again from today's log). `chain` is the log's own check.
pub fn verify(
    store: &Store,
    chain: &ChainReport,
    commit: &str,
    note: &Note,
    found: &[FileRecord],
) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    if note.commit != commit {
        problems.push(format!("the note names another commit ({})", note.commit));
    }
    if note.digest != digest(note) {
        problems.push("the note was edited after it was written: its digest does not match".into());
    }
    if let Some(broken) = chain.broken.as_ref().filter(|b| b.id.0 <= note.head.event) {
        problems.push(format!(
            "the audit log's hash chain breaks at event {}, before the head the note cites",
            broken.id
        ));
    }
    if store.hash_of(EventId(note.head.event))?.as_deref() != Some(note.head.hash.as_str()) {
        problems.push(format!(
            "the log no longer holds the head the note cites (event {:x}): events were \
             rewritten or deleted, or the note comes from another machine's log",
            note.head.event
        ));
    }
    for row in &note.events {
        if store.hash_of(EventId(row.event))?.as_deref() != Some(row.hash.as_str()) {
            problems.push(format!(
                "event {:x} the note cites is not in this log with that hash",
                row.event
            ));
        }
    }
    for file in &note.files {
        problems.extend(cited_write(store, note, file)?);
    }
    for discrepancy in compare(&note.files, found) {
        problems.push(describe(&discrepancy));
    }
    Ok(problems)
}

/// Why `file`'s cited event does not back it, if it does not.
fn cited_write(store: &Store, note: &Note, file: &FileRecord) -> Result<Option<String>> {
    if !note.events.iter().any(|e| e.event == file.event) {
        return Ok(Some(format!(
            "{} cites event {:x} without its hash",
            file.path, file.event
        )));
    }
    // the write's row is added right after its event, so it is never older
    let backs = store.get(EventId(file.event))?.is_some_and(|event| {
        event.host == file.host && event.session_id == file.session && event.ts_ms <= file.ts_ms
    });
    Ok((!backs).then(|| {
        format!(
            "{}: event {:x} is not a call of {} session {}",
            file.path, file.event, file.host, file.session
        )
    }))
}

fn describe(discrepancy: &Discrepancy) -> String {
    match discrepancy {
        Discrepancy::Omitted {
            path,
            host,
            session,
        } => format!("the note leaves out that {host} session {session} wrote {path}"),
        Discrepancy::Changed {
            path,
            host,
            session,
            what,
        } => format!("the note changes {what} for {path} ({host} session {session})"),
    }
}
