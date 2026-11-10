//! Live audit delivery to a SIEM or log collector (ADR-081).
//!
//! The guard never sends anything. After it has answered the host, and only
//! when `~/.moat/delivery.yaml` exists, it starts `openmoat audit deliver
//! flush --background` detached ([`kick`]) unless a run is already going or
//! every sink is waiting after a failure; that costs a file check per call and
//! a process start now and then, after the decision is out. The run reads the
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
    std::fs::read_to_string(hold)
        .ok()
        .and_then(|text| text.trim().parse::<i64>().ok())
        .is_some_and(|until| now_ms < until)
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
    home::create_private_dir(&dir)?;
    let started = std::time::Instant::now();
    let mut all: Option<Vec<SinkRun>> = None;
    loop {
        let file = home::private_append_options()
            .open(dir.join(LOCK_FILE))
            .with_context(|| format!("opening {}", dir.join(LOCK_FILE).display()))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Ok(all),
            Err(TryLockError::Error(e)) => return Err(e).context("locking the delivery run"),
        }
        let left = budget.saturating_sub(started.elapsed());
        let runs = flush::run(home, &config, lock.pinned_at_ms, forced, left)?;
        write_hold(home, &config, &dir)?;
        // Let go first, then look: a guard that recorded while the lock was
        // held and so started no run is seen here.
        drop(file);
        let behind = behind(home, &config)?;
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

/// The earliest time a sink is due, for [`held`]; a paused sink is never
/// due until a person resumes it.
fn write_hold(home: &Home, config: &Config, dir: &Path) -> Result<()> {
    let mut until = i64::MAX;
    for sink in &config.sinks {
        let state = State::load(&State::path(home, &sink.id))?;
        if state.paused.is_none() {
            until = until.min(state.next_attempt_ms);
        }
    }
    home::write_private(&dir.join(HOLD_FILE), until.to_string().as_bytes())
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
}
