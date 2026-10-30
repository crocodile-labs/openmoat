//! File provenance (ADR-029): session taint that follows what a tainted
//! session wrote into a file, so a later session that reads or runs the file
//! is tainted as if it had read the untrusted content itself.
//!
//! While a call is decided, [`observe`] looks up, by path, the newest write
//! row of every file the call reads or runs and the rows its writes add. The
//! rows are appended with the call's audit event when the call may have run
//! (`guard.rs`); [`super::of_session`] adds a session's tainted reads to its
//! taint. Nothing here asks or denies on its own: the taint it adds tightens
//! later calls as untrusted content does (`engine/taint.rs`).

use std::collections::BTreeSet;

use anyhow::{Context as _, Result};
use openmoat_audit::{FileProvenance, NewProvenance, ProvenanceKind, SessionWrite, Store};
use openmoat_core::{Action, AtomicAction, CompiledPolicy, TaintSettings};
use openmoat_hosts::Replacement;

use crate::guard_relay::MAX_PAYLOAD_BYTES;
use crate::integrity::sha256_hex;
use crate::realpath::FsPathResolver;

/// Longest `source` a row keeps: each hop of a file written by a session a
/// file tainted quotes the one before.
const MAX_SOURCE_CHARS: usize = 400;

/// The call being decided, as provenance needs it.
pub struct Call<'a> {
    /// The host's session id, which a tainted write names.
    pub session: &'a str,
    pub action: &'a Action,
    /// The whole content the call writes to its one file (`Write`), if known.
    pub content: Option<&'a str>,
    /// The replacements a partial edit makes (`Edit`, `MultiEdit`), in order;
    /// applied to the file as it is to learn the content the call leaves
    /// (ADR-048). Empty for every other call.
    pub edits: &'a [Replacement],
    /// The untrusted content the session had read before this call.
    pub untrusted: Option<&'a str>,
}

/// What [`observe`] found for one call.
#[derive(Debug, Default)]
pub struct Seen {
    /// The rows to append with the call's event.
    pub rows: Vec<NewProvenance>,
    /// The files the call writes, for the session's own record of what it
    /// wrote (ADR-039), kept whatever the session read.
    pub written: Vec<SessionWrite>,
}

impl Seen {
    /// Append the rows for the call recorded as `event`.
    pub fn write(
        &self,
        store: &Store,
        event: openmoat_audit::EventId,
        host: &str,
        session: &str,
    ) -> Result<()> {
        store
            .add_provenance(event, host, session, &self.rows)
            .context("recording file provenance")?;
        store
            .add_session_writes(event, host, session, &self.written)
            .context("recording the files this session wrote")
    }
}

/// The provenance rows `call` adds, looked up in `store`, and the files it
/// writes. Provenance is off when the policy's `taint: { provenance: false }`
/// says so; nothing is looked up for a clean session while no row exists at
/// all. The files written are listed either way.
pub fn observe(store: &Store, policy: &CompiledPolicy<'_>, call: &Call<'_>) -> Result<Seen> {
    let mut seen = Seen::default();
    let files = Files::of(policy, call.action);
    let ci = policy.context().case_insensitive_paths;
    // The whole content a `Write` sends. Provenance (below) records only that:
    // an edit may keep what a tainted session wrote, whatever hash it leaves.
    let sha256 = call.content.map(|c| content_hash(c.as_bytes()));
    seen.written = files
        .writes
        .iter()
        .map(|path| {
            // The content the call leaves and what the file held before it, so
            // a later call can tell this one ran and changed the file (ADR-048).
            // For an edit, the content is the file as it is with the
            // replacements applied; without a content there is nothing a later
            // call could compare the file against, so the state before is not
            // kept either.
            let (sha256, before) = match (&sha256, call.edits.is_empty()) {
                (Some(sha256), _) => (Some(sha256.clone()), state_of(path)),
                (None, false) => match edited(path, call.edits) {
                    Some((after, before)) => (Some(after), Some(before)),
                    None => (None, None),
                },
                (None, true) => (None, None),
            };
            SessionWrite {
                path: key(path, ci),
                sha256,
                before,
            }
        })
        .collect();
    if !TaintSettings::provenance_on(policy.policy().taint.as_ref())
        || (call.untrusted.is_none() && !store.has_provenance()?)
    {
        return Ok(seen);
    }
    let mut exposure = None;
    for path in &files.reads {
        let key = key(path, ci);
        let Some(row) = store.file_provenance(&key)? else {
            continue;
        };
        if row.tainted && holds(path, row.sha256.as_deref()) {
            let reason = clip(&format!("read {path}, {}", row.source));
            exposure.get_or_insert_with(|| reason.clone());
            seen.rows.push(NewProvenance {
                kind: ProvenanceKind::TaintedRead,
                path: key,
                sha256: None,
                source: reason,
            });
        }
    }
    // What a call writes after it read a tainted file in the same command
    // (`bash run.sh > out.txt`) is tainted too.
    let untrusted = call.untrusted.map(str::to_owned).or(exposure);
    for path in &files.writes {
        let key = key(path, ci);
        let row = match &untrusted {
            Some(source) => Some(tainted_write(key, sha256.clone(), call.session, source)),
            None => store
                .file_provenance(&key)?
                .and_then(|known| clean_write(key, sha256.clone(), &known)),
        };
        seen.rows.extend(row);
    }
    Ok(seen)
}

/// The row a write by a session that read untrusted content adds.
fn tainted_write(
    key: String,
    sha256: Option<String>,
    session: &str,
    untrusted: &str,
) -> NewProvenance {
    NewProvenance {
        kind: ProvenanceKind::TaintedWrite,
        path: key,
        sha256,
        source: clip(&format!(
            "which session {session} wrote after it read untrusted content ({untrusted})"
        )),
    }
}

/// The row a write by a clean session adds to a file of tainted provenance,
/// if any. Replacing the whole file (`sha256` known) makes it clean. A partial
/// change (`Edit`, a shell write) may leave what the tainted session wrote, so
/// the file stays tainted whatever its hash becomes: a tainted row with no
/// hash, unless the newest row already has none.
fn clean_write(
    key: String,
    sha256: Option<String>,
    known: &FileProvenance,
) -> Option<NewProvenance> {
    if !known.tainted {
        return None;
    }
    match sha256 {
        Some(sha256) => Some(NewProvenance {
            kind: ProvenanceKind::CleanWrite,
            path: key,
            sha256: Some(sha256),
            source: String::new(),
        }),
        None if known.sha256.is_some() => Some(NewProvenance {
            kind: ProvenanceKind::TaintedWrite,
            path: key,
            sha256: None,
            source: known.source.clone(),
        }),
        None => None,
    }
}

/// The files a call reads or runs, and the ones it writes by a literal path.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Files {
    pub reads: BTreeSet<String>,
    pub writes: BTreeSet<String>,
}

impl Files {
    pub(crate) fn of(policy: &CompiledPolicy<'_>, action: &Action) -> Self {
        let ctx = policy.context();
        let mut files = Self::default();
        for atom in policy.atoms(action, &FsPathResolver).0 {
            match atom {
                AtomicAction::FsRead { path } => {
                    files.reads.insert(path);
                }
                AtomicAction::FsWrite { path } if literal(&path) => {
                    files.writes.insert(path);
                }
                // A program named by a path (`./run.sh`, `bin/x`) is a file
                // the shell runs; a bare name is looked up on the search path.
                AtomicAction::Shell { argv } => {
                    let Some(program) = argv.first().filter(|p| p.contains('/') && literal(p))
                    else {
                        continue;
                    };
                    let project = ctx.project.as_deref();
                    if let Some(path) =
                        openmoat_core::resolve_path(program, &ctx.home, project, Some(&ctx.cwd))
                    {
                        files.reads.insert(path);
                    }
                }
                _ => {}
            }
        }
        files
    }
}

/// A path the call names as written, not a glob or a word the shell expands.
fn literal(path: &str) -> bool {
    !path.contains(['*', '?', '[', '$', '`']) && !path.starts_with('@')
}

/// The form a path is looked up by: one spelling per file where the file
/// system ignores case.
pub(crate) fn key(path: &str, case_insensitive: bool) -> String {
    if case_insensitive {
        path.to_lowercase()
    } else {
        path.to_owned()
    }
}

/// Whether the regular file at `path` still holds what a write of `sha256`
/// wrote; any content when the hash is not known. A file larger than a hook
/// payload cannot hold what a `Write` sent.
/// A file as it is now, when that is known.
enum FileNow {
    /// No file there.
    Missing,
    /// A plain file within the size the hook reads, and its bytes.
    Content(Vec<u8>),
}

/// The file at `path` as it is now; `None` when it cannot be read, is not a
/// plain file, or is larger than the hook reads.
fn file_now(path: &str) -> Option<FileNow> {
    match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(FileNow::Missing),
        Err(_) => None,
        Ok(meta) if !meta.is_file() || meta.len() > MAX_PAYLOAD_BYTES => None,
        Ok(_) => std::fs::read(path).ok().map(FileNow::Content),
    }
}

/// The content hash of the file at `path` as it is now: `""` when there is no
/// file there, `None` when it cannot be read ([`file_now`]).
pub(crate) fn state_of(path: &str) -> Option<String> {
    Some(match file_now(path)? {
        FileNow::Missing => String::new(),
        FileNow::Content(bytes) => content_hash(&bytes),
    })
}

/// The hashes of the file at `path` with `edits` applied, and of the file as
/// it is: `None` when the file is missing or unreadable, is not UTF-8, or an
/// edit does not apply ([`apply_edits`]), since the edit then fails or its
/// outcome is not known.
fn edited(path: &str, edits: &[Replacement]) -> Option<(String, String)> {
    let FileNow::Content(bytes) = file_now(path)? else {
        return None;
    };
    let text = std::str::from_utf8(&bytes).ok()?;
    let after = apply_edits(text, edits)?;
    Some((content_hash(after.as_bytes()), content_hash(&bytes)))
}

/// `text` with `edits` applied in order, as Claude Code applies them: each
/// `old` must be found, must differ from its `new`, and must occur exactly once
/// unless the edit replaces every occurrence. `None` when one does not apply,
/// since Claude Code then refuses the whole edit.
pub(crate) fn apply_edits(text: &str, edits: &[Replacement]) -> Option<String> {
    let mut text = text.to_owned();
    for edit in edits {
        if edit.old.is_empty() || edit.old == edit.new {
            return None;
        }
        let occurrences = text.matches(edit.old.as_str()).count();
        text = match occurrences {
            0 => return None,
            1 => text.replacen(edit.old.as_str(), &edit.new, 1),
            _ if edit.all => text.replace(edit.old.as_str(), &edit.new),
            _ => return None,
        };
    }
    Some(text)
}

/// Whether a plain file at `path` is there, and holds content hashing to
/// `sha256` when one is given.
pub(crate) fn holds(path: &str, sha256: Option<&str>) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    let Some(want) = sha256 else {
        return true;
    };
    meta.len() <= MAX_PAYLOAD_BYTES
        && std::fs::read(path).is_ok_and(|bytes| content_hash(&bytes) == want)
}

/// SHA-256 of `bytes` with CRLF line ends read as LF, so a host that writes
/// the platform's line ends still matches the content it was sent.
pub(crate) fn content_hash(bytes: &[u8]) -> String {
    if !bytes.windows(2).any(|w| w == b"\r\n") {
        return sha256_hex(bytes);
    }
    let mut unix = Vec::with_capacity(bytes.len());
    let mut iter = bytes.iter().peekable();
    while let Some(&b) = iter.next() {
        if b == b'\r' && iter.peek() == Some(&&b'\n') {
            continue;
        }
        unix.push(b);
    }
    sha256_hex(&unix)
}

fn clip(text: &str) -> String {
    match text.char_indices().nth(MAX_SOURCE_CHARS) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_owned(),
    }
}

#[cfg(test)]
mod tests;
