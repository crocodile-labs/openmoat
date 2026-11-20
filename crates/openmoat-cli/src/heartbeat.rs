//! Whether a host still runs OpenMoat: a plugin's report that its host loaded
//! it (ADR-042), and a hook host's calls (ADR-104).
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
//! the call.
//!
//! A host that runs a hook command stops running it as quietly (an update, a
//! setting, a lost entry), and has nothing to report but its calls: there
//! the last change is OpenMoat writing the hook, the host's settings changing
//! or a newer program, and the host's own session files since tell whether it
//! ran ([`hook`]). Nothing decides on either; it only says what OpenMoat can
//! tell.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use openmoat_hosts::{Heartbeat, Host};
use serde::{Deserialize, Serialize};

use crate::home::{Home, write_private};
use crate::install::HostConfig;

mod hook;
mod scan;
mod wording;

pub use wording::{Mark, fix, line, not_loaded};

/// The state directory's folder of reports.
const DIR: &str = "loaded";
/// A report is a few dozen bytes; anything longer is not one.
const MAX_BYTES: u64 = 4096;

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

/// The last change the plugin has to have loaded after, or the hook has to
/// have run after.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Change {
    /// OpenMoat wrote the plugin file (`openmoat init`).
    PluginWritten,
    /// The host's program on the search path is newer: an update.
    HostUpdated,
    /// OpenMoat wrote the hook file (`openmoat init`), as the lock pinned it.
    HookWritten,
    /// The hook file, or a settings file that can turn hooks off, changed
    /// after OpenMoat last pinned it.
    SettingsChanged,
}

/// A [`Change`] and when it happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Since {
    pub change: Change,
    pub at_ms: i64,
}

/// Whether the host has loaded OpenMoat's plugin, or run its hook, since it
/// last changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum Loaded {
    /// It reported, or sent a call the guard decided, at `at_ms`.
    Reported { since: Since, at_ms: i64 },
    /// Neither, and the host has not run since, as far as OpenMoat can tell.
    NotYet { since: Since },
    /// Neither, though the host wrote `sessions` of its sessions since, the
    /// last at `active_ms`: it ran without loading the plugin or running the
    /// hook, a process from before still runs, or (for a hook) those
    /// sessions made no tool call.
    Missing {
        since: Since,
        active_ms: i64,
        sessions: usize,
    },
}

/// The host's sessions written since the change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Active {
    /// The newest write.
    pub last_ms: i64,
    /// How many session files were written.
    pub sessions: usize,
}

/// What [`judge`] decides from.
#[derive(Debug, Clone, Copy)]
pub struct Facts {
    pub since: Since,
    /// The plugin's last report.
    pub reported_ms: Option<i64>,
    /// The newest decision the guard recorded for the host at or after `since`.
    pub decided_ms: Option<i64>,
    /// The host's sessions written at or after `since`; `None` when none, or
    /// when where it writes them is unknown.
    pub active: Option<Active>,
}

/// The state the facts show. A report or a decision since the change means
/// the plugin loaded (or the hook ran) after it; without either, the host's
/// own writes since the change mean it ran without them.
pub fn judge(facts: &Facts) -> Loaded {
    let since = facts.since;
    let sign = [facts.reported_ms, facts.decided_ms]
        .into_iter()
        .flatten()
        .filter(|at| *at >= since.at_ms)
        .max();
    match (sign, facts.active) {
        (Some(at_ms), _) => Loaded::Reported { since, at_ms },
        (None, Some(active)) if active.last_ms >= since.at_ms && active.sessions > 0 => {
            Loaded::Missing {
                since,
                active_ms: active.last_ms,
                sessions: active.sessions,
            }
        }
        (None, _) => Loaded::NotYet { since },
    }
}

/// The newest decision the guard recorded for `host` at or after `since_ms`.
fn decided_since(home: &Home, host: Host, since_ms: i64) -> Option<i64> {
    openmoat_audit::Store::open_read_only(&home.audit_path())
        .ok()
        .and_then(|store| store.host_seen_since(host.id(), since_ms).ok())
        .flatten()
}

/// Whether `config`'s host has loaded OpenMoat's plugin, or run its hook,
/// since it last changed; `None` for a host with neither fact in its spec,
/// or when the plugin or hook file cannot be read.
pub fn check(home: &Home, config: &HostConfig) -> Option<Loaded> {
    let Some(heartbeat) = spec(config.host) else {
        return hook::check(home, config);
    };
    let since = since(config, heartbeat)?;
    Some(judge(&Facts {
        since,
        reported_ms: last(home, config.host),
        decided_ms: decided_since(home, config.host, since.at_ms),
        // A plugin reports as it loads, so a session counts at once.
        active: scan::sessions(config.dir(), heartbeat.activity, since.at_ms, i64::MAX),
    }))
}

/// The last change `config`'s plugin has to have loaded after: OpenMoat
/// writing it, or a newer host program; `None` when the file cannot be read.
fn since(config: &HostConfig, heartbeat: &Heartbeat) -> Option<Since> {
    let written = scan::modified_ms(&fs::metadata(config.plugin_file()?).ok()?)?;
    Some(match scan::program_ms(heartbeat.program) {
        Some(at_ms) if at_ms > written => Since {
            change: Change::HostUpdated,
            at_ms,
        },
        _ => Since {
            change: Change::PluginWritten,
            at_ms: written,
        },
    })
}

/// Whether `init`'s plugin for `config`'s host has itself reported loading
/// (`guard --heartbeat`) since it last changed. Only its own report counts:
/// a decision recorded for the host may have come from a package of the
/// host's own plugin channel instead (ADR-099). `true` for a host that runs a
/// hook command, which has nothing to load.
pub fn reported_since_change(home: &Home, config: &HostConfig) -> bool {
    let Some(heartbeat) = spec(config.host) else {
        return true;
    };
    match (since(config, heartbeat), last(home, config.host)) {
        (Some(since), Some(reported_ms)) => reported_ms >= since.at_ms,
        _ => false,
    }
}

/// One host's [`Loaded`], for `openmoat status --format json` (`plugins`
/// and `hooks`).
#[derive(Debug, Clone, Serialize)]
pub struct HostLoaded {
    pub host: &'static str,
    #[serde(skip)]
    pub of: Host,
    #[serde(flatten)]
    pub loaded: Loaded,
}

/// [`check`] for every host whose hook or plugin OpenMoat installed for
/// `binary`.
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
                of: host,
                loaded: check(home, &config)?,
            })
        })
        .collect()
}

/// Whether `host` runs OpenMoat through a plugin that reports loading.
pub fn has_plugin(host: Host) -> bool {
    spec(host).is_some()
}

#[cfg(test)]
mod tests;
