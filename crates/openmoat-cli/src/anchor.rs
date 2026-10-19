//! Audit anchors (ADR-031): the log's head recorded outside the log, so that
//! deleting or rewriting the newest events, which leaves a valid shorter chain,
//! shows.
//!
//! An anchor is one JSON line ([`Record`]). `moat audit anchor` appends it to a
//! file the person keeps, or commits it on [`git::REF`] in a git repository
//! they name; nothing is sent anywhere. `moat audit verify --against` reads
//! every anchor back and checks each against today's log: the event it names
//! must still be there with the hash it had, in a chain that verifies, so each
//! anchor is still a prefix of the chain.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_audit::{ChainHead, ChainReport, EventId};
use serde::{Deserialize, Serialize};

use crate::home::{Home, private_append_options, write_private};

pub mod git;

/// The `format` of every anchor line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Format {
    #[serde(rename = "moat-audit-anchor-v1")]
    V1,
}

/// One anchor: the chain head at the time it was made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub format: Format,
    /// The newest event's id.
    pub event: EventId,
    /// Its chain hash.
    pub hash: String,
    /// When that event was recorded (ms since the epoch).
    pub event_ms: i64,
    /// When the anchor was made.
    pub anchored_ms: i64,
}

impl Record {
    pub fn new(head: &ChainHead, now_ms: i64) -> Self {
        Self {
            format: Format::V1,
            event: head.id,
            hash: head.hash.clone(),
            event_ms: head.ts_ms,
            anchored_ms: now_ms,
        }
    }

    /// The record as one line, without the newline.
    pub fn line(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

/// Where anchors are kept: a git repository or a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    Git(PathBuf),
    File(PathBuf),
}

impl Place {
    /// A directory is a git repository, anything else a file.
    pub fn of(path: &Path) -> Self {
        if path.is_dir() {
            Self::Git(path.to_path_buf())
        } else {
            Self::File(path.to_path_buf())
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Git(repo) => format!("{} ({})", repo.display(), git::REF),
            Self::File(file) => file.display().to_string(),
        }
    }

    /// Record `record` here. For git, the commit's id.
    pub fn append(&self, record: &Record, git_program: &Path) -> Result<Option<String>> {
        match self {
            Self::Git(repo) => git::Repo::new(git_program, repo)?.append(record).map(Some),
            Self::File(file) => {
                let mut out = private_append_options()
                    .open(file)
                    .with_context(|| format!("opening {}", file.display()))?;
                writeln!(out, "{}", record.line()?)
                    .and_then(|()| out.sync_all())
                    .with_context(|| format!("writing {}", file.display()))?;
                Ok(None)
            }
        }
    }

    /// Every anchor recorded here, oldest first.
    pub fn records(&self, git_program: &Path) -> Result<Vec<Record>> {
        let text = match self {
            Self::Git(repo) => git::Repo::new(git_program, repo)?.read()?,
            Self::File(file) => {
                fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?
            }
        };
        parse(&text).with_context(|| format!("reading the anchors in {}", self.describe()))
    }
}

/// Anchor lines, blank lines skipped; any other line is an error, as an
/// anchor file that cannot be read in full cannot vouch for the log.
pub fn parse(text: &str) -> Result<Vec<Record>> {
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: Record = serde_json::from_str(line)
            .with_context(|| format!("line {} is not a moat-audit-anchor-v1 record", index + 1))?;
        out.push(record);
    }
    if out.is_empty() {
        bail!("no anchors recorded");
    }
    Ok(out)
}

/// Why an anchor no longer matches the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mismatch {
    /// The event is gone: the newest events were deleted.
    Missing,
    /// The event has another hash: events up to it were rewritten.
    Rewritten,
    /// The chain breaks at or before the event.
    ChainBroken,
}

impl Mismatch {
    pub fn describe(self) -> &'static str {
        match self {
            Self::Missing => "its event is no longer in the log: events were deleted",
            Self::Rewritten => "its event has another hash now: events up to it were rewritten",
            Self::ChainBroken => "the hash chain breaks at or before its event",
        }
    }
}

/// The first anchor that no longer matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Failed {
    /// Its place among the anchors, from 1.
    pub number: usize,
    pub record: Record,
    pub why: Mismatch,
}

/// Check `records` in order against the log whose chain verification is
/// `chain`, looking each event's stored hash up with `hash_of`.
pub fn check(
    records: &[Record],
    chain: &ChainReport,
    hash_of: impl Fn(EventId) -> Result<Option<String>>,
) -> Result<Option<Failed>> {
    for (index, record) in records.iter().enumerate() {
        let broken_before = chain
            .broken
            .as_ref()
            .is_some_and(|b| b.id.0 <= record.event.0);
        let why = match hash_of(record.event)? {
            _ if broken_before => Some(Mismatch::ChainBroken),
            None => Some(Mismatch::Missing),
            Some(hash) if hash != record.hash => Some(Mismatch::Rewritten),
            Some(_) => None,
        };
        if let Some(why) = why {
            return Ok(Some(Failed {
                number: index + 1,
                record: record.clone(),
                why,
            }));
        }
    }
    Ok(None)
}

/// What `moat doctor` shows: the last anchor this machine made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Last {
    pub anchored_ms: i64,
    pub event: EventId,
    /// Where it went, as [`Place::describe`] says.
    pub to: String,
}

impl Last {
    /// `None` when no anchor was made or the file cannot be read: it is
    /// information only.
    pub fn load(home: &Home) -> Option<Self> {
        let text = fs::read_to_string(home.anchor_path()).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn save(&self, home: &Home) -> Result<()> {
        write_private(
            &home.anchor_path(),
            (serde_json::to_string_pretty(self)? + "\n").as_bytes(),
        )
    }
}

#[cfg(test)]
mod tests;
