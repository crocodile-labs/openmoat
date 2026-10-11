//! The calls the guard denied because no decision came within its budget.
//!
//! The audit log cannot hold them: what hangs may be the audit log itself. The
//! guard's watchdog appends one line, `<ms since the epoch> <host>`, to a side
//! file in the state directory instead, from a thread it waits for only
//! briefly, and ignores any failure: the deny never depends on the record.

use std::fs;
use std::io::{self, Write as _};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use openmoat_hosts::Host;

use crate::home::{self, Home};

/// The side file stops growing at this size, so a stream of hangs cannot fill
/// the disk; 64 KiB holds a few thousand lines.
const MAX_BYTES: u64 = 64 * 1024;

/// How long the watchdog waits for its line before it exits anyway.
const WRITE_WAIT: Duration = Duration::from_millis(200);

/// Record that `host`'s call was denied at `now_ms` with no decision, waiting
/// at most [`WRITE_WAIT`] for the line.
pub fn record(host: Host, now_ms: i64) {
    let (done, written) = mpsc::channel();
    let writer = thread::Builder::new().spawn(move || {
        if let Ok(home) = Home::locate() {
            let _ = append(&home.hangs_path(), &format!("{now_ms} {}\n", host.id()));
        }
        let _ = done.send(());
    });
    if writer.is_ok() {
        let _ = written.recv_timeout(WRITE_WAIT);
    }
}

/// Append `line` to `path` unless it is something other than a regular file
/// (a symlink, or a FIFO that would block) or already full. The state
/// directory is not created: without it there is no installation to report on.
fn append(path: &Path, line: &str) -> io::Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && (!meta.is_file() || meta.len() >= MAX_BYTES)
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    home::private_append_options()
        .open(path)?
        .write_all(line.as_bytes())
}

/// How many hangs `path` records at or after `since_ms`, and when the newest
/// was; `None` when there are none or the file cannot be read.
pub fn since(path: &Path, since_ms: i64) -> Option<(usize, i64)> {
    if !fs::symlink_metadata(path).ok()?.is_file() {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    let times: Vec<i64> = text
        .lines()
        .filter_map(|line| line.split(' ').next()?.parse().ok())
        .filter(|ms| *ms >= since_ms)
        .collect();
    Some((times.len(), *times.iter().max()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_counted_from_a_time_on() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guard-hangs.log");
        assert_eq!(since(&path, 0), None);
        for line in ["100 codex\n", "not a line\n", "300 claude-code\n"] {
            append(&path, line).unwrap();
        }
        assert_eq!(since(&path, 0), Some((2, 300)));
        assert_eq!(since(&path, 200), Some((1, 300)));
        assert_eq!(since(&path, 301), None);
    }

    #[test]
    fn a_full_file_or_a_directory_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guard-hangs.log");
        fs::write(&path, vec![b'\n'; usize::try_from(MAX_BYTES).unwrap()]).unwrap();
        assert!(append(&path, "1 codex\n").is_err());
        assert_eq!(fs::metadata(&path).unwrap().len(), MAX_BYTES);
        assert!(append(dir.path(), "1 codex\n").is_err());
        assert_eq!(since(dir.path(), 0), None);
    }
}
