//! `openmoat guard --plugin`: the guard run from an OpenMoat package
//! installed through an agent's own plugin channel (ADR-099).
//!
//! The package and `openmoat init`'s hook can both be installed for one
//! agent, and the agent then runs both for every call. Deciding twice would
//! record each call twice, fold its session twice and put a `review` to the
//! person twice, so one of them stands aside: the package's, and only where
//! `init`'s hook is sure to decide the same call, since `init`'s is the hook
//! the lock pins and the binary it names by its path. Everywhere else the
//! package's guard decides as `init`'s would, lock first: without a lock it
//! denies and names `openmoat init`.

use std::path::{Path, PathBuf};

use openmoat_core::{Decision, Verdict};
use openmoat_hosts::{HookEvent, Host, StandAside};

use crate::cli::GuardArgs;
use crate::exit::Code;
use crate::home::Home;
use crate::install::{HookState, HostConfig};

/// What `--plugin` does before the call is decided (`run` has started the
/// deadline's deny for a call already): refuse a state directory the agent's environment moved,
/// record that the package ran, and answer for it when it stands aside or
/// only reports loading (`--heartbeat`, which never stands for `init`'s
/// plugin having loaded). `None`: decide the call as `init`'s hook would, or,
/// without `--plugin`, as before.
pub(super) fn answer(args: &GuardArgs) -> Option<Code> {
    if !args.plugin {
        return None;
    }
    let (host, heartbeat) = (args.host, args.heartbeat);
    let payload = if heartbeat {
        None
    } else {
        match super::read_stdin(host) {
            Ok(payload) => Some(payload),
            Err(error) => {
                return Some(super::respond(
                    host,
                    &HookEvent::default(),
                    &super::kernel_error(&error),
                ));
            }
        }
    };
    let event = payload.as_deref().map_or_else(HookEvent::default, |p| {
        host.event_of_as(p, super::entry::event())
    });
    if payload.is_some() {
        super::deadline::saw(host, &event);
    }
    if let Some(why) = moved_state_dir() {
        if heartbeat {
            eprintln!("moat: {why}");
            return Some(Code::Deny);
        }
        let error = anyhow::Error::msg(why);
        return Some(super::respond(host, &event, &super::kernel_error(&error)));
    }
    let home = Home::locate().ok();
    let dirs = payload
        .as_deref()
        .map(|p| work_dirs(host, p))
        .unwrap_or_default();
    let aside = home
        .as_ref()
        .is_some_and(|home| init_hook_decides(home, host, &dirs));
    if let Some(home) = &home
        && let Err(error) = crate::plugin_record::note(home, host, crate::time::now_ms(), aside)
    {
        // A note for `doctor` only: the call is decided all the same.
        eprintln!("moat: could not record that the {host} plugin ran: {error:#}");
    }
    if heartbeat {
        return Some(Code::Ok);
    }
    if aside {
        return Some(stand_aside(host, &event));
    }
    // The guard's own read takes the payload read here.
    if let Some(payload) = payload {
        super::entry::keep_payload(payload);
    }
    None
}

/// Why the state directory the agent's environment names (`MOAT_HOME`) is
/// refused: a package has no `--home` of `init`'s, and a repository can set
/// an agent's environment (a project `.env`, settings `env`), so a package
/// decides only with the default `~/.moat`; `None` when that is the one.
fn moved_state_dir() -> Option<String> {
    let named = std::env::var_os(crate::home::ENV).filter(|v| !v.is_empty())?;
    let named = PathBuf::from(named);
    let default = crate::home::user_home()
        .ok()
        .map(|home| home.join(crate::home::DIR_NAME));
    if default
        .as_deref()
        .is_some_and(|default| same_dir(&named, default))
    {
        return None;
    }
    Some(format!(
        "{} names {}, but an OpenMoat package decides only with the default state directory \
         (`~/{}`); unset it in the agent's environment, or use `openmoat init`'s hook, which \
         names its state directory itself",
        crate::home::ENV,
        named.display(),
        crate::home::DIR_NAME
    ))
}

/// Whether `a` and `b` name one directory, through links where both exist.
fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a.components().eq(b.components()),
    }
}

/// The directories a project's settings for this call may be read from: the
/// payload's working directory, and the hook's own.
fn work_dirs(host: Host, payload: &str) -> Vec<PathBuf> {
    let from_payload = host
        .parse_request_as(payload, super::entry::event())
        .ok()
        .and_then(|request| request.cwd)
        .map(PathBuf::from);
    from_payload
        .into_iter()
        .chain(std::env::current_dir().ok())
        .collect()
}

/// Whether `openmoat init`'s own hook for `host` decides this call: the lock
/// is intact (any drift, and the guard decides, which denies), it pins the
/// hook file the host reads in this environment (the agent's, which the hook
/// inherits, never `hosts.json`), OpenMoat's entry there is the one `init`
/// wrote for the binary the lock names, no settings file the host reads for
/// `dirs` turns that hook off by name, and, for an agent that runs OpenMoat
/// through a plugin of `init`'s, that plugin has itself reported loading
/// since it last changed.
fn init_hook_decides(home: &Home, host: Host, dirs: &[PathBuf]) -> bool {
    let Ok(verified) = crate::integrity::check(home) else {
        return false;
    };
    if verified.checked.deny.is_some() {
        return false;
    }
    let home = &verified.home;
    // Where this agent reads its hook file, from the environment it gave the
    // hook alone: `hosts.json` names where `init` ran, perhaps for another
    // copy of the agent (another `CLAUDE_CONFIG_DIR`).
    let Ok(config) = HostConfig::for_environment(home, host) else {
        return false;
    };
    if !verified.lock.pins(&config.settings_path)
        || config.state(Path::new(&verified.lock.binary)) != HookState::Installed
    {
        return false;
    }
    let Ok(user_home) = crate::home::user_home() else {
        return false;
    };
    let off = |cwd: &PathBuf| {
        crate::project_settings::hook_switched_off(
            host,
            cwd,
            &user_home,
            config.dir(),
            &config.settings_path,
        )
    };
    if dirs.is_empty() || dirs.iter().any(off) {
        return false;
    }
    // `init`'s own report alone: a call this package decided is recorded for
    // the host too, and would otherwise make it stand aside for good.
    crate::heartbeat::reported_since_change(home, &config)
}

/// The answer that leaves the call to `init`'s hook: the host's own "no
/// decision", or `allow` where the host has none and takes the strictest
/// answer of all its hooks ([`StandAside`]). Nothing is recorded.
fn stand_aside(host: Host, event: &HookEvent) -> Code {
    let verdict = match openmoat_hosts::plugin::spec(host).map(|spec| spec.stand_aside) {
        Some(StandAside::Allow) => Verdict::Allow,
        Some(StandAside::NoDecision) | None => Verdict::Defer,
    };
    super::respond(host, event, &Decision::new(verdict))
}

#[cfg(test)]
mod tests {
    use super::same_dir;

    #[test]
    fn one_directory_by_two_spellings() {
        let dir = std::env::temp_dir();
        assert!(same_dir(&dir, &dir.join(".")));
        assert!(!same_dir(&dir, &dir.join("openmoat-not-there")));
    }
}
