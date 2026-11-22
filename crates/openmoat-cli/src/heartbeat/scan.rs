//! The file dates a heartbeat is judged from: the host's program on the
//! search path, and the session files it writes.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use openmoat_hosts::Activity;

use super::Active;

/// How many directories an [`Activity::ANY`] level and how many files in all
/// are looked at, so a huge sessions folder costs `status` little.
const MAX_DIRS: usize = 256;
const MAX_FILES: usize = 4096;

/// When `program` on the search path last changed: the newer of the entry
/// there (a link a package manager made) and the file it names.
pub(super) fn program_ms(program: &str) -> Option<i64> {
    let found = crate::environment::find_on_path(program)?;
    let link = fs::symlink_metadata(&found)
        .ok()
        .and_then(|m| modified_ms(&m));
    let file = fs::metadata(&found).ok().and_then(|m| modified_ms(&m));
    link.max(file)
}

/// When the file at `path` was last written; `None` when it cannot be read.
pub(super) fn file_ms(path: &Path) -> Option<i64> {
    modified_ms(&fs::metadata(path).ok()?)
}

/// The session files in the directories `activity` names under `dir` that
/// were written at or after `since_ms` and started at or before
/// `started_by_ms`; links are not followed. A file whose start the system
/// does not keep counts from its last write, so it is counted later, never
/// sooner. `None` when there is none.
pub(super) fn sessions(
    dir: &Path,
    activity: &[Activity],
    since_ms: i64,
    started_by_ms: i64,
) -> Option<Active> {
    let mut files = 0;
    let mut found: Option<Active> = None;
    for a in activity {
        let entries = expand(dir, a.dir)
            .into_iter()
            .filter_map(|folder| fs::read_dir(folder).ok())
            .flatten()
            .take_while(|_| {
                files += 1;
                files <= MAX_FILES
            })
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(a.ending));
        for entry in entries {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let Some(written) = modified_ms(&meta).filter(|_| meta.is_file()) else {
                continue;
            };
            // A file is written after it is made; the earlier of the two is
            // its start also where a copy kept its write time.
            let started = created_ms(&meta).map_or(written, |made| made.min(written));
            if written < since_ms || started > started_by_ms {
                continue;
            }
            found = Some(match found {
                Some(seen) => Active {
                    last_ms: seen.last_ms.max(written),
                    sessions: seen.sessions + 1,
                },
                None => Active {
                    last_ms: written,
                    sessions: 1,
                },
            });
        }
    }
    found
}

/// The file of session `id` (`<id><ending>`) in the directories `activity`
/// names under `dir`, and its start and last write; `None` when there is
/// none, the id cannot be a file name, or the system keeps no start time.
pub(super) fn session_file(
    dir: &Path,
    activity: &[Activity],
    id: &str,
) -> Option<(PathBuf, i64, i64)> {
    let plain = !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !plain {
        return None;
    }
    activity.iter().find_map(|a| {
        expand(dir, a.dir).into_iter().find_map(|folder| {
            let path = folder.join(format!("{id}{}", a.ending));
            let meta = fs::symlink_metadata(&path)
                .ok()
                .filter(fs::Metadata::is_file)?;
            Some((path, created_ms(&meta)?, modified_ms(&meta)?))
        })
    })
}

/// How much of a session's file [`first_tool`] reads.
const MAX_SESSION_BYTES: u64 = 4 * 1024 * 1024;

/// The first tool `uses` finds in a line of the file at `path` that `named`
/// says reaches the guard; `None` when there is none in its first
/// [`MAX_SESSION_BYTES`].
pub(super) fn first_tool(
    path: &Path,
    uses: fn(&serde_json::Value) -> Vec<String>,
    named: &dyn Fn(&str) -> bool,
) -> Option<String> {
    use std::io::{BufRead as _, BufReader, Read as _};
    let file = fs::File::open(path).ok()?;
    let reader = BufReader::new(file.take(MAX_SESSION_BYTES));
    reader
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(&line).ok())
        .flat_map(|line| uses(&line))
        .find(|tool| named(tool))
}

/// The directories `parts` names under `dir`, each [`Activity::ANY`] every
/// directory at its level (at most [`MAX_DIRS`]).
fn expand(dir: &Path, parts: &[&str]) -> Vec<PathBuf> {
    let mut dirs = vec![dir.to_path_buf()];
    for part in parts {
        dirs = if *part == Activity::ANY {
            dirs.iter()
                .filter_map(|d| fs::read_dir(d).ok())
                .flatten()
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .map(|e| e.path())
                .take(MAX_DIRS)
                .collect()
        } else {
            dirs.iter().map(|d| d.join(part)).collect()
        };
    }
    dirs
}

pub(super) fn modified_ms(meta: &fs::Metadata) -> Option<i64> {
    epoch_ms(meta.modified().ok()?)
}

fn created_ms(meta: &fs::Metadata) -> Option<i64> {
    epoch_ms(meta.created().ok()?)
}

fn epoch_ms(at: SystemTime) -> Option<i64> {
    let since_epoch = at.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(since_epoch.as_millis()).ok()
}
