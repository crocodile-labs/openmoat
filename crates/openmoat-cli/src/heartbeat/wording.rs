//! How a [`Loaded`] reads in `status`, `doctor` and `watch`.
//!
//! A hook host's warning says what OpenMoat saw, never more: the host wrote
//! sessions and no call of its reached the guard. A session that made no tool
//! call, or ran on another machine sharing the directory, looks the same, so
//! the line counts the sessions and says "if they used tools" rather than
//! that calls ran unchecked.

use openmoat_hosts::Host;

use super::{Change, Loaded, Since, has_plugin, hook};

/// How a [`Loaded`] reads in `status` and `doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// `·`: information, in `status` and `doctor`.
    Note,
    /// `·` in `doctor` only: a hook that runs, or has had no reason to yet.
    Detail,
    /// `!`: the plugin may not be loaded, or the hook may not run.
    Warning,
}

/// The line `status` and `doctor` print for `loaded` under `host`'s hook line.
pub fn line(host: Host, loaded: &Loaded) -> (Mark, String) {
    if has_plugin(host) {
        plugin_line(host.display_name(), loaded)
    } else {
        hook_line(host, loaded)
    }
}

fn what(name: &str, since: &Since) -> String {
    let at = crate::time::timestamp(since.at_ms);
    match since.change {
        Change::PluginWritten => format!("OpenMoat wrote it ({at})"),
        Change::HookWritten => format!("OpenMoat wrote its hook ({at})"),
        Change::SettingsChanged => format!("its settings changed ({at})"),
        Change::HostUpdated => format!("{name} was updated ({at})"),
    }
}

fn plugin_line(name: &str, loaded: &Loaded) -> (Mark, String) {
    let ts = crate::time::timestamp;
    match loaded {
        Loaded::Reported { at_ms, .. } => (
            Mark::Note,
            format!("plugin loaded: last report or call {}", ts(*at_ms)),
        ),
        Loaded::NotYet { since } => (
            Mark::Note,
            format!(
                "plugin not loaded yet since {}; {name} reports it the next time it starts",
                what(name, since)
            ),
        ),
        Loaded::Missing {
            since, active_ms, ..
        } => (
            Mark::Warning,
            format!(
                "plugin has not reported loading since {}, but {name} has run since (last {}): \
                 its tool calls may run unchecked. Restart {name}; if this stays, look for a \
                 plugin error in its log",
                what(name, since),
                ts(*active_ms)
            ),
        ),
    }
}

fn hook_line(host: Host, loaded: &Loaded) -> (Mark, String) {
    let name = host.display_name();
    let ts = crate::time::timestamp;
    match loaded {
        Loaded::Reported { at_ms, .. } => {
            (Mark::Detail, format!("hook runs: last call {}", ts(*at_ms)))
        }
        Loaded::NotYet { since } => (
            Mark::Detail,
            match hook::unknown_why(host) {
                Some(why) => format!(
                    "no call since {}; OpenMoat cannot tell whether {name} ran since ({why})",
                    what(name, since)
                ),
                None => format!(
                    "no call since {}; {name} has not run a session since, as far as \
                     OpenMoat can tell",
                    what(name, since)
                ),
            },
        ),
        Loaded::Missing {
            since,
            active_ms,
            sessions,
        } => (
            Mark::Warning,
            format!(
                "{name} ran {} since {} (last {}), and OpenMoat saw no call from it: if {} \
                 used tools, the hook did not run and the calls were not checked",
                if *sessions == 1 {
                    "1 session".to_owned()
                } else {
                    format!("{sessions} sessions")
                },
                what(name, since),
                ts(*active_ms),
                if *sessions == 1 { "it" } else { "they" },
            ),
        ),
    }
}

/// What to do about a [`Loaded::Missing`] hook host: restart it, set the hook
/// up again, look for what turns it off, and the host's own trust step;
/// `None` for anything else.
pub fn fix(host: Host, loaded: &Loaded) -> Option<String> {
    if has_plugin(host) || !matches!(loaded, Loaded::Missing { .. }) {
        return None;
    }
    let name = host.display_name();
    let mut fix = format!(
        "restart {name}: a session started before the change may not run the new hook. If \
         this stays, run `openmoat init`, and check that nothing turns the hook off: {}",
        host.spec().hook_failure.turned_off_by
    );
    if let Some(step) = crate::install::trust_note::step(host) {
        fix.push_str("; ");
        fix.push_str(step);
    }
    Some(fix)
}

/// Why a [`Loaded::Missing`] plugin host is not protected; `None` otherwise,
/// and for a hook host, whose sessions without a call may have needed no
/// tool: that is a warning, never a lower protection level.
pub fn not_loaded(host: Host, loaded: &Loaded) -> Option<String> {
    if !has_plugin(host) {
        return None;
    }
    match loaded {
        Loaded::Missing { since, .. } => Some(format!(
            "plugin not loaded since {} {}, though {} has run since",
            match since.change {
                Change::PluginWritten | Change::HookWritten => "it was written",
                Change::HostUpdated | Change::SettingsChanged => "the update",
            },
            crate::time::timestamp(since.at_ms),
            host.display_name()
        )),
        Loaded::Reported { .. } | Loaded::NotYet { .. } => None,
    }
}
