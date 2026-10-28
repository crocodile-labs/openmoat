//! A plugin's report that its host loaded it (ADR-042).
//!
//! OpenClaw, pi and OpenCode run OpenMoat through a plugin they load, and each
//! keeps running when it cannot load one, so its tool calls then run
//! unchecked. The plugin runs `openmoat guard --heartbeat --host <id>` as it
//! loads ([`report`]), which writes `loaded/<id>.json` in the state directory:
//! the host, the time and this release, nothing from the host. `openmoat
//! status` and `openmoat doctor` compare it ([`check`]) with the last thing
//! that could have stopped the plugin loading: OpenMoat writing the plugin
//! file, or a newer host program on the search path. A decision the guard
//! recorded for the host since then counts as a report too: the plugin sent
//! the call. Nothing decides on it; it only says what OpenMoat can tell.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Result, bail};
use openmoat_hosts::{Activity, Heartbeat, Host};
use serde::{Deserialize, Serialize};

use crate::home::{Home, write_private};
use crate::install::HostConfig;

/// The state directory's folder of reports.
const DIR: &str = "loaded";
/// A report is a few dozen bytes; anything longer is not one.
const MAX_BYTES: u64 = 4096;
/// How many directories an [`Activity::ANY`] level and how many files in all
/// are looked at, so a huge sessions folder costs `status` little.
const MAX_DIRS: usize = 256;
const MAX_FILES: usize = 4096;

/// What `loaded/<id>.json` holds.
#[derive(Debug, Serialize, Deserialize)]
struct Record {
    host: String,
    reported_ms: i64,
    openmoat: String,
}

/// The facts about `host`'s plugin, for a host that runs OpenMoat through one.
fn spec(host: Host) -> Option<&'static Heartbeat> {
    host.spec().install.as_ref()?.heartbeat.as_ref()
}

fn path(home: &Home, host: Host) -> PathBuf {
    home.root().join(DIR).join(format!("{}.json", host.id()))
}

/// Record that `host` loaded OpenMoat's plugin at `now_ms`.
pub fn report(home: &Home, host: Host, now_ms: i64) -> Result<()> {
    if spec(host).is_none() {
        bail!(
            "{} runs a hook command, not a plugin of OpenMoat's",
            host.display_name()
        );
    }
    // A plugin without a state directory was not installed by `init`.
    home.require_exists()?;
    let record = Record {
        host: host.id().to_owned(),
        reported_ms: now_ms,
        openmoat: env!("CARGO_PKG_VERSION").to_owned(),
    };
    write_private(&path(home, host), &serde_json::to_vec(&record)?)
}

/// When `host`'s plugin last reported; `None` without a report, or for one
/// that is not a small file of `host`'s.
fn last(home: &Home, host: Host) -> Option<i64> {
    let path = path(home, host);
    let meta = fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > MAX_BYTES {
        return None;
    }
    let record: Record = serde_json::from_slice(&fs::read(&path).ok()?).ok()?;
    (record.host == host.id()).then_some(record.reported_ms)
}

/// The last change the plugin has to have loaded after.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Change {
    /// OpenMoat wrote the plugin file (`openmoat init`).
    PluginWritten,
    /// The host's program on the search path is newer: an update.
    HostUpdated,
}

/// A [`Change`] and when it happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Since {
    pub change: Change,
    pub at_ms: i64,
}

/// Whether the host has loaded OpenMoat's plugin since it last changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum Loaded {
    /// It reported, or sent a call the guard decided, at `at_ms`.
    Reported { since: Since, at_ms: i64 },
    /// Neither, and the host has not run since, as far as OpenMoat can tell.
    NotYet { since: Since },
    /// Neither, though the host wrote its sessions at `active_ms`: it ran
    /// without loading the plugin, or a process from before still runs.
    Missing { since: Since, active_ms: i64 },
}

/// What [`judge`] decides from.
#[derive(Debug, Clone, Copy)]
pub struct Facts {
    pub since: Since,
    /// The plugin's last report.
    pub reported_ms: Option<i64>,
    /// The newest decision the guard recorded for the host at or after `since`.
    pub decided_ms: Option<i64>,
    /// The newest file the host wrote where it works; `None` when unknown.
    pub active_ms: Option<i64>,
}

/// The state the facts show. A report or a decision since the change means
/// the plugin loaded after it; without either, the host's own writes since
/// the change mean it ran without the plugin.
pub fn judge(facts: &Facts) -> Loaded {
    let since = facts.since;
    let sign = [facts.reported_ms, facts.decided_ms]
        .into_iter()
        .flatten()
        .filter(|at| *at >= since.at_ms)
        .max();
    match (sign, facts.active_ms) {
        (Some(at_ms), _) => Loaded::Reported { since, at_ms },
        (None, Some(active_ms)) if active_ms >= since.at_ms => Loaded::Missing { since, active_ms },
        (None, _) => Loaded::NotYet { since },
    }
}

/// Whether `config`'s host has loaded OpenMoat's plugin since it last
/// changed; `None` for a host that runs a hook command, or when the plugin
/// file cannot be read.
pub fn check(home: &Home, config: &HostConfig) -> Option<Loaded> {
    let heartbeat = spec(config.host)?;
    let written = modified_ms(&fs::metadata(config.plugin_file()?).ok()?)?;
    let updated = program_ms(heartbeat.program);
    let since = match updated {
        Some(at_ms) if at_ms > written => Since {
            change: Change::HostUpdated,
            at_ms,
        },
        _ => Since {
            change: Change::PluginWritten,
            at_ms: written,
        },
    };
    let decided_ms = openmoat_audit::Store::open_read_only(&home.audit_path())
        .ok()
        .and_then(|store| store.host_seen_since(config.host.id(), since.at_ms).ok())
        .flatten();
    Some(judge(&Facts {
        since,
        reported_ms: last(home, config.host),
        decided_ms,
        active_ms: newest_activity(config.dir(), heartbeat.activity),
    }))
}

/// One host's [`Loaded`], for `openmoat status --format json` (`plugins`).
#[derive(Debug, Serialize)]
pub struct HostLoaded {
    pub host: &'static str,
    #[serde(flatten)]
    pub loaded: Loaded,
}

/// [`check`] for every host whose plugin OpenMoat installed for `binary`.
pub fn all(home: &Home, binary: &Path) -> Vec<HostLoaded> {
    Host::ALL
        .into_iter()
        .filter_map(|host| {
            let config = HostConfig::for_host(home, host).ok()?;
            if !config.set_up(binary) {
                return None;
            }
            Some(HostLoaded {
                host: host.id(),
                loaded: check(home, &config)?,
            })
        })
        .collect()
}

/// When `program` on the search path last changed: the newer of the entry
/// there (a link a package manager made) and the file it names.
fn program_ms(program: &str) -> Option<i64> {
    let dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    let found = crate::environment::find_in(&dirs, &[], program)?;
    let link = fs::symlink_metadata(&found)
        .ok()
        .and_then(|m| modified_ms(&m));
    let file = fs::metadata(&found).ok().and_then(|m| modified_ms(&m));
    link.max(file)
}

/// The newest modification time of a file in the directories `activity`
/// names under `dir`; links are not followed.
fn newest_activity(dir: &Path, activity: &[Activity]) -> Option<i64> {
    let mut files = 0;
    activity
        .iter()
        .flat_map(|a| expand(dir, a.dir))
        .filter_map(|folder| fs::read_dir(folder).ok())
        .flatten()
        .take_while(|_| {
            files += 1;
            files <= MAX_FILES
        })
        .filter_map(|entry| entry.ok()?.metadata().ok())
        .filter(fs::Metadata::is_file)
        .filter_map(|meta| modified_ms(&meta))
        .max()
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

fn modified_ms(meta: &fs::Metadata) -> Option<i64> {
    let since_epoch = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(since_epoch.as_millis()).ok()
}

/// How a [`Loaded`] reads in `status` and `doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// `·`: information.
    Note,
    /// `!`: the plugin may not be loaded.
    Warning,
}

/// The line `status` and `doctor` print for `loaded` under `name`'s hook line.
pub fn line(name: &str, loaded: &Loaded) -> (Mark, String) {
    let ts = crate::time::timestamp;
    let what = |since: &Since| match since.change {
        Change::PluginWritten => format!("OpenMoat wrote it ({})", ts(since.at_ms)),
        Change::HostUpdated => format!("{name} was updated ({})", ts(since.at_ms)),
    };
    match loaded {
        Loaded::Reported { at_ms, .. } => (
            Mark::Note,
            format!("plugin loaded: last report or call {}", ts(*at_ms)),
        ),
        Loaded::NotYet { since } => (
            Mark::Note,
            format!(
                "plugin not loaded yet since {}; {name} reports it the next time it starts",
                what(since)
            ),
        ),
        Loaded::Missing { since, active_ms } => (
            Mark::Warning,
            format!(
                "plugin has not reported loading since {}, but {name} has run since (last {}): \
                 its tool calls may run unchecked. Restart {name}; if this stays, look for a \
                 plugin error in its log",
                what(since),
                ts(*active_ms)
            ),
        ),
    }
}

/// Why a [`Loaded::Missing`] host is not protected; `None` otherwise.
pub fn not_loaded(name: &str, loaded: &Loaded) -> Option<String> {
    match loaded {
        Loaded::Missing { since, .. } => Some(format!(
            "plugin not loaded since {} {}, though {name} has run since",
            match since.change {
                Change::PluginWritten => "it was written",
                Change::HostUpdated => "the update",
            },
            crate::time::timestamp(since.at_ms)
        )),
        Loaded::Reported { .. } | Loaded::NotYet { .. } => None,
    }
}

#[cfg(test)]
mod tests;
