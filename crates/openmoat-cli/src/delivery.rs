//! Live audit delivery to a SIEM or log collector (ADR-081).
//!
//! The guard never sends anything. After it has answered the host, and only
//! when `~/.moat/delivery.yaml` exists, it starts `openmoat audit deliver
//! flush --background` detached ([`kick`]) unless a run is already going or
//! the hold file says no run is due yet; that costs a file check per call and
//! a process start now and then, after the decision is out. Every run writes
//! the hold, whatever its outcome: after a run, the earliest time a sink is
//! due and at least a second away; after a run that failed as a whole (the
//! audit log or the policy unreadable), a minute, doubling to 15 minutes while
//! it keeps failing; after a configuration no person accepted, 5 minutes. A
//! new configuration or lock ends any hold. The run reads the
//! events after each sink's cursor from the audit log, which is the queue,
//! masks them again, and sends them; it never writes to the hook's streams
//! and its failures change no decision.

mod config;
mod detach;
mod flush;
mod send;
mod sign;
mod state;

use std::fs::{File, TryLockError};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context as _, Result};

pub use config::{Config, Sink, load_pinned};
pub use flush::{DELIVERY_HOST, SinkRun};
pub use send::{Ready, Sent};
pub use state::State;

use crate::home::{self, Home};
use crate::time;

/// The lock one run holds, in the delivery directory.
const LOCK_FILE: &str = "run.lock";
/// The time (ms) before which no sink is due, which spares the guard a start.
const HOLD_FILE: &str = "hold";

/// How long the guard starts no run after one found the configuration not
/// honoured, unless the file or the lock changes first.
const REFUSED_HOLD_MS: i64 = 5 * 60 * 1000;

/// The least time between two runs the guard starts.
const MIN_SPACING: Duration = Duration::from_secs(1);

/// How long the guard starts no run after one failed as a whole, the first
/// time; doubled each time in a row, at most [`ERROR_HOLD_MAX`].
const ERROR_HOLD_FIRST: Duration = Duration::from_mins(1);
const ERROR_HOLD_MAX: Duration = Duration::from_mins(15);

/// How long a run the guard started may send for; the next call starts
/// another.
pub const BACKGROUND_BUDGET: Duration = Duration::from_secs(120);

/// The variables a background run keeps: where the home and the state
/// directory are, and on Linux the session bus a keychain read needs. Nothing
/// else of the agent's environment reaches it: `SSL_CERT_FILE` would choose
/// the roots it trusts.
const KEPT_ENV: &[&str] = &[
    "HOME",
    "USERPROFILE",
    "SystemRoot",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
];

/// [`kick`] for the state directory this process locates; nothing when there
/// is none.
pub fn kick_located() {
    if let Ok(home) = Home::locate() {
        kick(&home);
    }
}

/// After the guard answered: start a background run when delivery is
/// configured, a sink may be due and no run holds the lock. Never fails and
/// never waits; what it skips the next call or `flush` sends.
pub fn kick(home: &Home) {
    if !home.delivery_config_path().is_file() {
        return;
    }
    let dir = home.delivery_dir();
    let changed = [home.delivery_config_path(), home.lock_path()];
    if held(&dir, &changed, time::now_ms()) || running(&dir) {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut command = Command::new(exe);
    command
        .args(["audit", "deliver", "flush", "--background"])
        .env_clear()
        .env(home::ENV, home.root());
    for name in KEPT_ENV {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    detach::detach(&mut command);
    // A run that cannot start leaves the events where they are.
    let _ = command.spawn();
}

/// Whether the hold file says no sink is due before `now_ms`. Nothing is held
/// once one of `changed` is newer than the hold: a changed configuration (a new
/// sink, a fixed URL) or a new lock (a person accepted the file).
fn held(dir: &Path, changed: &[PathBuf], now_ms: i64) -> bool {
    let hold = dir.join(HOLD_FILE);
    let modified = |path: &Path| std::fs::metadata(path).and_then(|m| m.modified()).ok();
    let Some(hold_at) = modified(&hold) else {
        return false;
    };
    if changed
        .iter()
        .any(|path| modified(path).is_none_or(|at| at > hold_at))
    {
        return false;
    }
    read_hold(dir).is_some_and(|(until, _)| now_ms < until)
}

/// Whether another run holds the lock.
fn running(dir: &Path) -> bool {
    match File::open(dir.join(LOCK_FILE)) {
        Ok(file) => matches!(file.try_lock(), Err(TryLockError::WouldBlock)),
        Err(_) => false,
    }
}

/// One run under the lock: `None` when another run holds it. With `forced`
/// (a person's `flush`) every sink is tried now, paused ones included.
/// After the lock is let go, a run starts again when events arrived that a
/// guard, seeing the lock held, did not start a run for.
pub fn run(home: &Home, forced: bool, budget: Duration) -> Result<Option<Vec<SinkRun>>> {
    let dir = home.delivery_dir();
    let (config, lock) = match load_pinned(home) {
        Ok(Some(loaded)) => loaded,
        Ok(None) => return Ok(Some(Vec::new())),
        Err(error) => {
            // A file no person accepted: the guard need not start a run per
            // call to find that out again, until the file or the lock changes.
            let until = time::now_ms().saturating_add(REFUSED_HOLD_MS);
            let _ = home::write_private(&dir.join(HOLD_FILE), until.to_string().as_bytes());
            return Err(error);
        }
    };
    let ran = runs(home, &config, lock.pinned_at_ms, forced, budget);
    held_after(&dir, ran, time::now_ms())
}

/// `ran`, after writing the hold of a run that failed: every way out of a
/// run writes one ([`runs`] writes it after each run that ended), since
/// without it each guard call would start a run that fails the same way.
fn held_after<T>(dir: &Path, ran: Result<T>, now_ms: i64) -> Result<T> {
    if ran.is_err() {
        let _ = error_hold(dir, now_ms);
    }
    ran
}

/// [`run`] once the configuration is honoured: run after run under the lock
/// while events keep arriving and the budget lasts.
fn runs(
    home: &Home,
    config: &Config,
    accepted_ms: i64,
    forced: bool,
    budget: Duration,
) -> Result<Option<Vec<SinkRun>>> {
    let dir = home.delivery_dir();
    home::create_private_dir(&dir)?;
    let started = std::time::Instant::now();
    let mut all: Option<Vec<SinkRun>> = None;
    loop {
        let file = home::private_lock_options()
            .open(dir.join(LOCK_FILE))
            .with_context(|| format!("opening {}", dir.join(LOCK_FILE).display()))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Ok(all),
            Err(TryLockError::Error(e)) => return Err(e).context("locking the delivery run"),
        }
        let left = budget.saturating_sub(started.elapsed());
        let runs = flush::run(home, config, accepted_ms, forced, left)?;
        write_hold(home, config, &dir, time::now_ms())?;
        // Let go first, then look: a guard that recorded while the lock was
        // held and so started no run is seen here.
        drop(file);
        let behind = behind(home, config)?;
        all.get_or_insert_with(Vec::new).extend(runs);
        if !behind || started.elapsed() >= budget {
            return Ok(all);
        }
    }
}

/// Whether a due sink has events after its cursor.
fn behind(home: &Home, config: &Config) -> Result<bool> {
    let head = home.open_audit()?.latest_id()?.map_or(0, |id| id.0);
    let now = time::now_ms();
    for sink in &config.sinks {
        let state = State::load(&State::path(home, &sink.id))?;
        if state.due(now) && state.cursor.is_some_and(|c| c.0 < head) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// After a run: the earliest time a sink is due, for [`held`], and never
/// sooner than [`MIN_SPACING`] from `now_ms`, so a burst of calls starts one
/// run, not one per call (what the burst records, the next call after it
/// sends); a paused sink is never due until a person resumes it. The run
/// failures [`error_hold`] counted start again from none.
fn write_hold(home: &Home, config: &Config, dir: &Path, now_ms: i64) -> Result<()> {
    let mut until = i64::MAX;
    for sink in &config.sinks {
        let state = State::load(&State::path(home, &sink.id))?;
        if state.paused.is_none() {
            until = until.min(state.next_attempt_ms);
        }
    }
    let spaced = now_ms.saturating_add(i64::try_from(MIN_SPACING.as_millis()).unwrap_or(0));
    home::write_private(
        &dir.join(HOLD_FILE),
        format!("{} 0", until.max(spaced)).as_bytes(),
    )
}

/// After a run that failed as a whole (the audit log or the policy could not
/// be read, a state file could not be written): no run for
/// [`ERROR_HOLD_FIRST`], doubled with each such failure in a row, at most
/// [`ERROR_HOLD_MAX`].
fn error_hold(dir: &Path, now_ms: i64) -> Result<()> {
    let failures = read_hold(dir)
        .map_or(0, |(_, failures)| failures)
        .saturating_add(1);
    let wait = ERROR_HOLD_FIRST
        .saturating_mul(1u32 << failures.saturating_sub(1).min(16))
        .min(ERROR_HOLD_MAX);
    let until = now_ms.saturating_add(i64::try_from(wait.as_millis()).unwrap_or(i64::MAX));
    home::create_private_dir(dir)?;
    home::write_private(
        &dir.join(HOLD_FILE),
        format!("{until} {failures}").as_bytes(),
    )
}

/// The hold file's time (ms) and the failed runs in a row it counts; an
/// older file holds the time alone.
fn read_hold(dir: &Path) -> Option<(i64, u32)> {
    let text = std::fs::read_to_string(dir.join(HOLD_FILE)).ok()?;
    let mut words = text.split_whitespace();
    let until = words.next()?.parse().ok()?;
    let failures = words.next().and_then(|w| w.parse().ok()).unwrap_or(0);
    Some((until, failures))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hold_lasts_until_its_time_or_a_newer_configuration_or_lock() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("delivery.yaml");
        let lock = dir.path().join("policy.lock");
        std::fs::write(&config, "x").unwrap();
        std::fs::write(&lock, "x").unwrap();
        let changed = [config.clone(), lock.clone()];
        assert!(!held(dir.path(), &changed, 0), "no hold file");
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(dir.path().join(HOLD_FILE), "1000").unwrap();
        assert!(held(dir.path(), &changed, 999));
        assert!(!held(dir.path(), &changed, 1000));
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&lock, "re-pinned").unwrap();
        assert!(!held(dir.path(), &changed, 999), "a person accepted since");
        std::fs::remove_file(&config).unwrap();
        assert!(!held(dir.path(), &changed, 999));
    }

    /// A run that fails as a whole holds the guard off a minute, doubling to
    /// 15; a run that ends holds it off until a sink is due, never "now".
    #[test]
    fn every_run_writes_a_hold_and_failures_back_off() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("state"));
        let delivery = home.delivery_dir();
        let config = config::parse(
            "version: 1\nmachine: m\nsinks:\n  - id: c\n    otlp: http://127.0.0.1:9/v1/logs\n",
            &home,
        )
        .unwrap();
        let minute = 60_000;
        let mut waits = Vec::new();
        for _ in 0..6 {
            error_hold(&delivery, 0).unwrap();
            waits.push(read_hold(&delivery).unwrap().0);
        }
        assert_eq!(
            waits,
            [
                minute,
                2 * minute,
                4 * minute,
                8 * minute,
                15 * minute,
                15 * minute
            ]
        );
        // A run that ended: no sink waits, yet the hold is not "now".
        write_hold(&home, &config, &delivery, 5_000).unwrap();
        assert_eq!(read_hold(&delivery), Some((6_000, 0)));
        // The failures counted start again.
        error_hold(&delivery, 0).unwrap();
        assert_eq!(read_hold(&delivery), Some((minute, 1)));
        // A sink waiting after a failure holds until it is due.
        let mut state = State::default();
        state.failed("HTTP 503".to_owned(), Some(120), 5_000, 0.0);
        state.save(&State::path(&home, "c")).unwrap();
        write_hold(&home, &config, &delivery, 5_000).unwrap();
        assert_eq!(read_hold(&delivery), Some((125_000, 0)));
    }

    /// The error path of a run writes the hold: a run whose audit log is
    /// missing does not leave the guard starting it again on every call.
    #[test]
    fn a_run_that_fails_writes_a_hold() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("state"));
        let config = config::parse(
            "version: 1\nmachine: m\nsinks:\n  - id: c\n    otlp: http://127.0.0.1:9/v1/logs\n",
            &home,
        )
        .unwrap();
        let changed = [home.delivery_config_path(), home.lock_path()];
        std::fs::create_dir_all(home.root()).unwrap();
        std::fs::write(&changed[0], "x").unwrap();
        std::fs::write(&changed[1], "x").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let now = time::now_ms();
        let ran = runs(&home, &config, 0, false, Duration::from_secs(1));
        assert!(held_after(&home.delivery_dir(), ran, now).is_err());
        let delivery = home.delivery_dir();
        assert_eq!(read_hold(&delivery), Some((now + 60_000, 1)));
        assert!(held(&delivery, &changed, now + 59_000));
        assert!(!held(&delivery, &changed, now + 60_000));
    }
}
