//! Where a host whose spec gives its own location rules
//! ([`Location::Custom`], OpenClaw's) keeps its configuration directory and
//! hook file, as this shell's environment names them.

use std::path::Path;

use anyhow::Result;
use openmoat_hosts::{Host, Locate, Located, Location};

use crate::home::user_home;

/// `host`'s own location rules, when its spec has them.
pub fn custom(host: Host) -> Option<&'static dyn Locate> {
    match host.spec().install.as_ref()?.location {
        Location::Custom(locate) => Some(locate),
        Location::OneDir => None,
    }
}

/// The location this shell's environment names, when it sets one of the
/// rules' variables.
pub fn from_env(locate: &dyn Locate) -> Result<Option<Located>> {
    let get = |name: &str| std::env::var(name).ok();
    if !locate.moved(&get) {
        return Ok(None);
    }
    let absolute = |path: &Path| {
        crate::context::absolute(path).map_err(|e| std::io::Error::other(format!("{e:#}")))
    };
    Ok(Some(locate.resolve(&get, &user_home()?, &absolute)?))
}

/// What `moat doctor` says when this shell's environment names another
/// installation than `set_up`, the one `moat init` recorded; `None` when it
/// agrees or names none.
pub fn env_disagrees(locate: &dyn Locate, set_up: &Located) -> Result<Option<String>> {
    let variables = match locate.variables() {
        [first @ .., last] if !first.is_empty() => format!("{} or {last}", first.join(", ")),
        other => other.join(", "),
    };
    Ok(from_env(locate)?.filter(|env| env != set_up).map(|env| {
        format!(
            "{variables} name {} (state {}), \
             but `openmoat init` set up {} (state {}), which OpenMoat uses; run `openmoat init` with \
             them set to set up that one instead",
            env.config.display(),
            env.dir.display(),
            set_up.config.display(),
            set_up.dir.display()
        )
    }))
}
