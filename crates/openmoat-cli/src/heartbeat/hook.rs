//! Whether a host that runs a hook command still runs OpenMoat's (ADR-104).
//!
//! Such a host has nothing that reports loading: an update that reads its
//! hooks elsewhere, a setting that turns hooks off or an entry lost in an
//! edit only shows as calls that stop reaching the guard. So the last change
//! that could have stopped the hook is the newest of OpenMoat writing the
//! hook file, the hook file or a settings file of the spec's changing after
//! that, and a newer program on the search path; a call the guard recorded
//! for the host since then shows the hook runs, and the host's own session
//! files written since without one show it ran without it.

use openmoat_hosts::{Liveness, Sessions};

use super::{Change, Facts, Loaded, Since, decided_since, judge, scan};
use crate::home::Home;
use crate::install::HostConfig;

/// How long a session may run before its first tool call: a session that
/// started less than this long ago is not counted yet, so one that has not
/// needed a tool so far is no warning.
const FIRST_CALL_MS: i64 = 10 * 60 * 1000;

/// The facts about `config`'s host's hook, for a host that runs a hook command.
fn spec(config: &HostConfig) -> Option<&'static Liveness> {
    config.host.spec().install.as_ref()?.liveness.as_ref()
}

/// [`super::check`] for a host that runs a hook command; `None` for one whose
/// spec names no [`Liveness`], or when its hook file cannot be read.
pub(super) fn check(home: &Home, config: &HostConfig) -> Option<Loaded> {
    let liveness = spec(config)?;
    let since = since(home, config, liveness)?;
    let active = match liveness.sessions {
        Sessions::Known(activity) => scan::sessions(
            config.dir(),
            activity,
            since.at_ms,
            crate::time::now_ms().saturating_sub(FIRST_CALL_MS),
        ),
        Sessions::Unknown(_) => None,
    };
    Some(judge(&Facts {
        since,
        reported_ms: None,
        decided_ms: decided_since(home, config.host, since.at_ms),
        active,
    }))
}

/// The newest change that could have stopped `config`'s hook running.
fn since(home: &Home, config: &HostConfig, liveness: &Liveness) -> Option<Since> {
    let hook = scan::file_ms(&config.settings_path)?;
    // `init` writes the hook file (and any settings it sets), then the lock
    // that pins it: a file newer than the lock was changed by someone else.
    let pinned = scan::file_ms(&home.lock_path());
    let written = |at: i64| {
        if pinned.is_some_and(|lock| at <= lock) {
            (Change::HookWritten, at)
        } else {
            (Change::SettingsChanged, at)
        }
    };
    let (change, at_ms) = written(hook);
    let mut since = Since { change, at_ms };
    let settings = liveness
        .settings
        .iter()
        .filter_map(|file| scan::file_ms(&config.dir().join(file)))
        .map(written);
    let program = config
        .host
        .spec()
        .process
        .names
        .first()
        .and_then(|program| scan::program_ms(program))
        .map(|at| (Change::HostUpdated, at));
    for (change, at_ms) in settings.chain(program) {
        if at_ms > since.at_ms {
            since = Since { change, at_ms };
        }
    }
    Some(since)
}

/// Why OpenMoat cannot tell whether `host` ran, for a hook host whose spec
/// knows no place it writes its sessions.
pub(super) fn unknown_why(host: openmoat_hosts::Host) -> Option<&'static str> {
    match host.spec().install.as_ref()?.liveness.as_ref()?.sessions {
        Sessions::Unknown(why) => Some(why),
        Sessions::Known(_) => None,
    }
}
