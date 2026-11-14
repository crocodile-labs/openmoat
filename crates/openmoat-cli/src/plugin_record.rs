//! What an OpenMoat package installed through an agent's own plugin channel
//! did last (ADR-099), for `openmoat doctor`.
//!
//! The package runs `openmoat guard --plugin --host <id>`, which writes
//! `plugins/<id>.json` in the state directory: the host, when, this release,
//! and whether the guard stood aside for `openmoat init`'s hook or decided
//! the call itself. Nothing decides on it; a record that cannot be written is
//! skipped, and the call is decided as before.

use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use openmoat_hosts::Host;
use serde::{Deserialize, Serialize};

use crate::home::{Home, write_private};

/// The state directory's folder of records.
const DIR: &str = "plugins";
/// A record is a few dozen bytes; anything longer is not one.
const MAX_BYTES: u64 = 4096;
/// How often an unchanged record is rewritten: once a minute is enough for
/// "last ran", and keeps a write off most calls.
const REWRITE_AFTER_MS: i64 = 60_000;

/// What `plugins/<id>.json` holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub host: String,
    pub seen_ms: i64,
    pub openmoat: String,
    /// Whether the guard gave no decision because `openmoat init`'s own
    /// hook for the host decides the call.
    pub stood_aside: bool,
}

fn path(home: &Home, host: Host) -> PathBuf {
    home.root().join(DIR).join(format!("{}.json", host.id()))
}

/// Record that `host`'s package ran at `now_ms`, and whether it stood aside.
/// Skipped where there is no state directory (no `openmoat init` yet), and
/// when the record says the same and is under a minute old.
pub fn note(home: &Home, host: Host, now_ms: i64, stood_aside: bool) -> Result<()> {
    if !home.root().is_dir() {
        return Ok(());
    }
    if let Some(last) = last(home, host)
        && last.stood_aside == stood_aside
        && (0..REWRITE_AFTER_MS).contains(&(now_ms - last.seen_ms))
    {
        return Ok(());
    }
    let record = Record {
        host: host.id().to_owned(),
        seen_ms: now_ms,
        openmoat: env!("CARGO_PKG_VERSION").to_owned(),
        stood_aside,
    };
    write_private(&path(home, host), &serde_json::to_vec(&record)?)
}

/// `host`'s package's last record; `None` without one, or for a file that is
/// not a small record of `host`'s.
pub fn last(home: &Home, host: Host) -> Option<Record> {
    let path = path(home, host);
    let meta = fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > MAX_BYTES {
        return None;
    }
    let record: Record = serde_json::from_slice(&fs::read(&path).ok()?).ok()?;
    (record.host == host.id()).then_some(record)
}

/// The line `openmoat doctor` prints for `record`.
pub fn line(record: &Record) -> String {
    let when = crate::time::timestamp(record.seen_ms);
    if record.stood_aside {
        format!(
            "OpenMoat plugin installed through the agent's channel (last ran {when}): it gives no \
             decision while `openmoat init`'s hook decides each call"
        )
    } else {
        format!(
            "OpenMoat plugin installed through the agent's channel (last ran {when}): it decided \
             the calls itself"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> (tempfile::TempDir, Home) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("state");
        fs::create_dir_all(&root).unwrap();
        let home = Home::at(root);
        (dir, home)
    }

    #[test]
    fn a_record_is_rewritten_when_it_changes_or_ages() {
        let (_dir, home) = home();
        let host = Host::ALL[0];
        note(&home, host, 1_000, false).unwrap();
        assert_eq!(last(&home, host).unwrap().seen_ms, 1_000);
        // Unchanged and under a minute old: kept.
        note(&home, host, 2_000, false).unwrap();
        assert_eq!(last(&home, host).unwrap().seen_ms, 1_000);
        // Standing aside now: rewritten at once.
        note(&home, host, 3_000, true).unwrap();
        let record = last(&home, host).unwrap();
        assert!(record.stood_aside);
        assert_eq!(record.seen_ms, 3_000);
        // A minute later: rewritten.
        note(&home, host, 3_000 + REWRITE_AFTER_MS, true).unwrap();
        assert_eq!(last(&home, host).unwrap().seen_ms, 3_000 + REWRITE_AFTER_MS);
    }

    #[test]
    fn no_state_directory_records_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("absent"));
        note(&home, Host::ALL[0], 1, false).unwrap();
        assert!(!dir.path().join("absent").exists());
    }
}
