//! The calls the guard denied because no decision came within its budget.
//!
//! The audit log cannot hold them: what hangs may be the audit log itself. The
//! guard's watchdog appends one line, `<ms since the epoch> <host> <phase>
//! <elapsed ms>`, to a side file in the state directory instead, from a thread
//! it waits for only briefly, and ignores any failure: the deny never depends
//! on the record. The phase is the step the guard was in when the budget ran
//! out, and the elapsed time is measured from the guard's start, so a line
//! tells a slow step (machine load) from a stuck one. Builds before the phase
//! wrote `<ms> <host>` only; those lines still count.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write as _};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
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

/// The step `moat guard` is in, in the order it takes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    /// Reading the hook payload.
    Stdin,
    /// Inside `moat run`: waiting for the run's process outside the sandbox
    /// to decide (its own guard records the phase it reached).
    Relay,
    /// Checking the policy lock.
    Lock,
    /// Loading the policy, its context, secrets and search path.
    Context,
    /// Compiling the policy and deciding the call.
    Compile,
    /// Reading the session's earlier calls from the audit log.
    Taint,
    /// Writing the session cache.
    Cache,
    /// Recording the decision in the audit log.
    Record,
    /// Writing the answer to the host.
    Answer,
}

const PHASES: [Phase; 9] = [
    Phase::Stdin,
    Phase::Relay,
    Phase::Lock,
    Phase::Context,
    Phase::Compile,
    Phase::Taint,
    Phase::Cache,
    Phase::Record,
    Phase::Answer,
];

impl Phase {
    /// The name in a hangs line.
    pub fn name(self) -> &'static str {
        match self {
            Self::Stdin => "stdin",
            Self::Relay => "relay",
            Self::Lock => "lock",
            Self::Context => "context",
            Self::Compile => "compile",
            Self::Taint => "taint",
            Self::Cache => "cache",
            Self::Record => "record",
            Self::Answer => "answer",
        }
    }

    /// What the guard was doing, for `moat doctor`.
    pub fn doing(self) -> &'static str {
        match self {
            Self::Stdin => "reading the tool call",
            Self::Relay => "waiting for `moat run` to decide",
            Self::Lock => "checking the policy lock",
            Self::Context => "loading the policy",
            Self::Compile => "deciding",
            Self::Taint => "reading the session's earlier calls",
            Self::Cache => "writing the session cache",
            Self::Record => "writing the audit log",
            Self::Answer => "answering the host",
        }
    }

    /// The phase named `name` in a hangs line.
    pub fn from_name(name: &str) -> Option<Self> {
        PHASES.into_iter().find(|p| p.name() == name)
    }
}

/// The guard's current phase, as an index into [`PHASES`]; one guard per process.
static CURRENT: AtomicU8 = AtomicU8::new(0);

/// The guard moves on to `phase`.
pub fn enter(phase: Phase) {
    let index = PHASES.iter().position(|p| *p == phase).unwrap_or(0);
    CURRENT.store(u8::try_from(index).unwrap_or(0), Ordering::Relaxed);
}

/// The phase the guard is in now.
pub fn current() -> Phase {
    PHASES
        .get(usize::from(CURRENT.load(Ordering::Relaxed)))
        .copied()
        .unwrap_or(Phase::Stdin)
}

/// Record that `host`'s call was denied at `now_ms` with no decision, while in
/// `phase` after `elapsed_ms`, waiting at most [`WRITE_WAIT`] for the line.
pub fn record(home: &Home, host: Host, now_ms: i64, phase: Phase, elapsed_ms: u128) {
    let (done, written) = mpsc::channel();
    let path = home.hangs_path();
    let line = line(now_ms, host, phase, elapsed_ms);
    let writer = thread::Builder::new().spawn(move || {
        let _ = append(&path, &line);
        let _ = done.send(());
    });
    if writer.is_ok() {
        let _ = written.recv_timeout(WRITE_WAIT);
    }
}

fn line(now_ms: i64, host: Host, phase: Phase, elapsed_ms: u128) -> String {
    format!("{now_ms} {} {} {elapsed_ms}\n", host.id(), phase.name())
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

/// The hangs of a time window.
#[derive(Debug, PartialEq, Eq)]
pub struct Hangs {
    /// How many.
    pub count: usize,
    /// When the newest was.
    pub newest_ms: i64,
    /// The phase most of them were in; `None` when no line names one.
    pub common_phase: Option<Phase>,
}

/// The hangs `path` records at or after `since_ms`; `None` when there are none
/// or the file cannot be read.
pub fn since(path: &Path, since_ms: i64) -> Option<Hangs> {
    if !fs::symlink_metadata(path).ok()?.is_file() {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    let lines: Vec<(i64, Option<Phase>)> = text
        .lines()
        .filter_map(parse)
        .filter(|(ms, _)| *ms >= since_ms)
        .collect();
    let newest_ms = lines.iter().map(|(ms, _)| *ms).max()?;
    let mut counts: HashMap<Phase, usize> = HashMap::new();
    for phase in lines.iter().filter_map(|(_, p)| *p) {
        *counts.entry(phase).or_default() += 1;
    }
    // Ties go to the earliest phase, so the answer does not depend on hashing.
    let common_phase = PHASES
        .into_iter()
        .filter_map(|p| Some((p, *counts.get(&p)?)))
        .fold(None::<(Phase, usize)>, |best, (p, n)| match best {
            Some((_, m)) if m >= n => best,
            _ => Some((p, n)),
        })
        .map(|(p, _)| p);
    Some(Hangs {
        count: lines.len(),
        newest_ms,
        common_phase,
    })
}

/// The time and phase of one line; a line without a phase (an older build's)
/// or with one this build does not know has none.
fn parse(line: &str) -> Option<(i64, Option<Phase>)> {
    let mut fields = line.split(' ');
    let ms = fields.next()?.parse().ok()?;
    let phase = fields.nth(1).and_then(Phase::from_name);
    Some((ms, phase))
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
        let all = since(&path, 0).unwrap();
        assert_eq!((all.count, all.newest_ms, all.common_phase), (2, 300, None));
        assert_eq!(since(&path, 200).unwrap().count, 1);
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

    #[test]
    fn every_phase_has_a_distinct_name_that_reads_back() {
        let mut names: Vec<&str> = PHASES.iter().map(|p| p.name()).collect();
        for phase in PHASES {
            assert_eq!(Phase::from_name(phase.name()), Some(phase));
            enter(phase);
            assert_eq!(current(), phase);
        }
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), PHASES.len());
        assert_eq!(Phase::from_name("nap"), None);
    }

    #[test]
    fn a_line_names_the_time_host_phase_and_elapsed_ms() {
        let line = line(1_700, Host::Codex, Phase::Record, 30_012);
        assert_eq!(line, "1700 codex record 30012\n");
        assert_eq!(parse(line.trim_end()), Some((1_700, Some(Phase::Record))));
        assert_eq!(parse("1700 codex"), Some((1_700, None)), "an older line");
        assert_eq!(parse("1700 codex later 5"), Some((1_700, None)));
    }

    #[test]
    fn the_most_common_phase_is_reported_and_older_lines_still_count() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guard-hangs.log");
        let text = "10 codex\n20 codex taint 30001\n30 cursor record 30002\n\
                    40 claude-code record 30500\n";
        fs::write(&path, text).unwrap();
        let hangs = since(&path, 0).unwrap();
        assert_eq!(hangs.count, 4);
        assert_eq!(hangs.newest_ms, 40);
        assert_eq!(hangs.common_phase, Some(Phase::Record));
        fs::write(&path, "20 codex taint 1\n30 codex record 1\n").unwrap();
        assert_eq!(since(&path, 0).unwrap().common_phase, Some(Phase::Taint));
    }
}
