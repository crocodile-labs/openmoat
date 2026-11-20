//! Whether a host that runs a hook command still runs OpenMoat's (ADR-104).
//!
//! Such a host has nothing that reports loading: an update that reads its
//! hooks elsewhere, a setting that turns hooks off or an entry lost in an
//! edit only shows as calls that stop reaching the guard. So the last change
//! that could have stopped the hook is the newest of OpenMoat writing the
//! hook file, the hook file or a settings file of the spec's changing after
//! that, and a newer program on the search path; a call the guard recorded
//! for the host since then shows the hook runs, and the host's own session
//! files written since without one show it ran without it. Whether OpenMoat
//! or someone else last wrote a hook or settings file is told by the lock's
//! pin of it, not by the file's time ([`origin`]).

use std::path::Path;

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
    let lock = crate::integrity::Lock::load(&home.lock_path()).ok();
    let lock_ms = scan::file_ms(&home.lock_path());
    let written = |path: &Path| {
        let at = scan::file_ms(path)?;
        let pinned = match &lock {
            Some(lock) if lock.pins(path) => Pinned::Pinned {
                intact: lock.verify_one(path).is_none(),
            },
            _ => Pinned::Unpinned { lock_ms },
        };
        Some((origin(pinned, at), at))
    };
    let (change, at_ms) = written(&config.settings_path)?;
    let mut since = Since { change, at_ms };
    let settings = liveness
        .settings
        .iter()
        .filter_map(|file| written(&config.dir().join(file)));
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

/// What the lock says of a hook or settings file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Pinned {
    /// The lock pins it; `intact` when it still has the pinned contents.
    Pinned { intact: bool },
    /// The lock does not pin it (or there is no lock); `lock_ms` is when the
    /// lock was last written, if there is one.
    Unpinned { lock_ms: Option<i64> },
}

/// Who last changed a file written at `at_ms`. A file the lock pins is
/// OpenMoat's own write while it still has the pinned contents, whatever its
/// time says: `init` and the other commands that re-pin may write it after
/// the lock, in the same instant, or rewrite it unchanged, and the lock
/// leaves out keys its host rewrites for display alone. Only for a file the
/// lock does not pin is the time compared, with the lock's.
pub(super) fn origin(pinned: Pinned, at_ms: i64) -> Change {
    let own = match pinned {
        Pinned::Pinned { intact } => intact,
        Pinned::Unpinned { lock_ms } => lock_ms.is_some_and(|lock| at_ms <= lock),
    };
    if own {
        Change::HookWritten
    } else {
        Change::SettingsChanged
    }
}

/// Why OpenMoat cannot tell whether `host` ran, for a hook host whose spec
/// knows no place it writes its sessions.
pub(super) fn unknown_why(host: openmoat_hosts::Host) -> Option<&'static str> {
    match host.spec().install.as_ref()?.liveness.as_ref()?.sessions {
        Sessions::Unknown(why) => Some(why),
        Sessions::Known(_) => None,
    }
}
