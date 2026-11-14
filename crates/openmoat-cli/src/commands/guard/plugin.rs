//! `openmoat guard --plugin`: the guard run from an OpenMoat package
//! installed through an agent's own plugin channel (ADR-095).
//!
//! The package and `openmoat init`'s hook can both be installed for one
//! agent, and the agent then runs both for every call. Deciding twice would
//! record each call twice, fold its session twice and put a `review` to the
//! person twice, so one of them stands aside: the package's, and only where
//! `init`'s hook is sure to decide the same call, since `init`'s is the hook
//! the lock pins and the binary it names by its path. Everywhere else the
//! package's guard decides as `init`'s would, lock first: without a lock it
//! denies and names `openmoat init`.

use std::path::Path;
use std::time::Instant;

use openmoat_core::{Decision, Verdict};
use openmoat_hosts::{Host, StandAside};

use crate::cli::GuardArgs;
use crate::exit::Code;
use crate::heartbeat::Loaded;
use crate::home::Home;
use crate::install::{HookState, HostConfig};

/// What `--plugin` does before the call is decided: start the budget's deny
/// (for a call), record that the package ran, and answer for it when it
/// stands aside or only reports loading (`--heartbeat`, which never stands
/// for `init`'s plugin having loaded). `None`: decide the call as `init`'s
/// hook would, or, without `--plugin`, as before.
pub(super) fn answer(args: &GuardArgs) -> Option<Code> {
    if !args.plugin {
        return None;
    }
    let (host, heartbeat) = (args.host, args.heartbeat);
    if !heartbeat {
        super::deny_when_over_budget(host, Instant::now());
    }
    let home = Home::locate().ok();
    let aside = home
        .as_ref()
        .is_some_and(|home| init_hook_decides(home, host));
    if let Some(home) = &home
        && let Err(error) = crate::plugin_record::note(home, host, crate::time::now_ms(), aside)
    {
        // A note for `doctor` only: the call is decided all the same.
        eprintln!("moat: could not record that the {host} plugin ran: {error:#}");
    }
    if heartbeat {
        return Some(Code::Ok);
    }
    aside.then(|| stand_aside(host))
}

/// Whether `openmoat init`'s own hook for `host` decides this call: the lock
/// is intact (any drift, and the guard decides, which denies), it pins the
/// hook file the host reads in this environment (the agent's, which the hook
/// inherits), OpenMoat's entry there is the one `init` wrote for the binary
/// the lock names, and, for an agent that runs OpenMoat through a plugin of
/// `init`'s, that plugin has reported loading since it last changed.
fn init_hook_decides(home: &Home, host: Host) -> bool {
    let Ok(verified) = crate::integrity::check(home) else {
        return false;
    };
    if verified.checked.deny.is_some() {
        return false;
    }
    let home = &verified.home;
    let Ok(config) = HostConfig::for_init(home, host) else {
        return false;
    };
    if !verified.lock.pins(&config.settings_path)
        || config.state(Path::new(&verified.lock.binary)) != HookState::Installed
    {
        return false;
    }
    crate::heartbeat::check(home, &config)
        .is_none_or(|loaded| matches!(loaded, Loaded::Reported { .. }))
}

/// The answer that leaves the call to `init`'s hook: the host's own "no
/// decision", or `allow` where the host has none and takes the strictest
/// answer of all its hooks ([`StandAside`]). Nothing is recorded.
fn stand_aside(host: Host) -> Code {
    let payload = super::read_stdin(host).unwrap_or_default();
    let event = host.event_of_as(&payload, super::entry::event());
    let verdict = match openmoat_hosts::plugin::spec(host).map(|spec| spec.stand_aside) {
        Some(StandAside::Allow) => Verdict::Allow,
        Some(StandAside::NoDecision) | None => Verdict::Defer,
    };
    super::respond(host, &event, &Decision::new(verdict))
}
