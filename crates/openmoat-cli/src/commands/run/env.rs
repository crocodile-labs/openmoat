//! Which inherited environment variables reach what `openmoat run` starts
//! (ADR-077). Under `require.run: full-boundary` only an allowlist does: a
//! base every program needs, the host's own names from its spec, the names the
//! person's policy adds and the names given with `--env`. Otherwise everything
//! still does, as before, and one line says what looks like a credential.
//!
//! Names only, everywhere in this file: a value is never read, kept or shown.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};

use openmoat_core::Policy;
use openmoat_hosts::Host;

use crate::render::clean;

/// What every program needs, on every platform. A value `openmoat run` sets
/// itself (the proxy, the temp directory, the CA files) is kept without being
/// listed here, because the run's own settings are never withheld.
const BASE: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "PWD",
    "OLDPWD",
    "SHLVL",
    "_",
    "TERM",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "COLORTERM",
    "COLUMNS",
    "LINES",
    "NO_COLOR",
    "FORCE_COLOR",
    "CLICOLOR",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_ADDRESS",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_IDENTIFICATION",
    "LC_MEASUREMENT",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NAME",
    "LC_NUMERIC",
    "LC_PAPER",
    "LC_TELEPHONE",
    "LC_TIME",
    "TZ",
    "TMPDIR",
    "TEMP",
    "TMP",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_DIRS",
    "XDG_CONFIG_HOME",
    "XDG_DATA_DIRS",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_STATE_HOME",
    // Where OpenMoat's own state is: the hook is told the same on its command line.
    "MOAT_HOME",
];

/// How many credential-looking names the warning spells out.
const SHOWN: usize = 3;

/// Words that, as a whole `_`-separated part of a name, mean it probably holds
/// a credential. Whole parts, so `KEYBOARD_LAYOUT` and `MONKEY` are not one.
const CREDENTIAL_WORDS: &[&str] = &[
    "APIKEY",
    "AUTH",
    "COOKIE",
    "CREDENTIAL",
    "CREDENTIALS",
    "KEY",
    "PASS",
    "PASSPHRASE",
    "PASSWD",
    "PASSWORD",
    "PAT",
    "PRIVATE",
    "SECRET",
    "SECRETS",
    "TOKEN",
];

/// Whether `name` looks like it holds a credential, for the warning only:
/// whether a variable is withheld never depends on this.
fn looks_like_credential(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("AWS_")
        || upper
            .split('_')
            .any(|part| CREDENTIAL_WORDS.contains(&part))
}

/// The names that may reach what the run starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowed(BTreeSet<String>);

impl Allowed {
    /// The base, this `platform`'s own, `host`'s facts, the person's policy
    /// (`sandbox.env_allow`) and `flags` (`--env`).
    pub fn new(platform: &[&str], host: Option<Host>, policy: &Policy, flags: &[String]) -> Self {
        let mut names: BTreeSet<String> = BASE
            .iter()
            .chain(platform)
            .map(|n| (*n).to_owned())
            .collect();
        names.extend(policy.sandbox.iter().flat_map(|s| s.env_allow.clone()));
        names.extend(flags.iter().cloned());
        let mut allowed = Self(names);
        if let Some(host) = host {
            allowed.add_host(host);
        }
        allowed
    }

    /// Allow `host`'s own names too.
    pub fn add_host(&mut self, host: Host) {
        self.0
            .extend(host_names(host).into_iter().map(str::to_owned));
    }

    fn holds(&self, name: &OsStr) -> bool {
        name.to_str().is_some_and(|n| self.0.contains(n))
    }
}

/// `host`'s own names: its spec's facts and the variable that moves its
/// configuration directory.
pub fn host_names(host: Host) -> Vec<&'static str> {
    let spec = host.spec();
    let dir = spec
        .install
        .as_ref()
        .map(|i| i.dir_variable)
        .into_iter()
        .chain(spec.detect.as_ref().map(|d| d.dir_variable));
    spec.run_env
        .iter()
        .copied()
        .chain(dir)
        .filter(|n| !n.is_empty())
        .collect()
}

/// The names in `inherited` that are not `allowed`, sorted. `set_by_run` tells
/// the names the run sets or removes itself, which are never reported: its
/// own values reach the agent, and a brokered secret is already gone.
pub fn withheld(
    inherited: impl IntoIterator<Item = OsString>,
    allowed: &Allowed,
    set_by_run: &dyn Fn(&OsStr) -> bool,
) -> Vec<OsString> {
    let mut names: Vec<OsString> = inherited
        .into_iter()
        .filter(|name| !allowed.holds(name) && !set_by_run(name))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// The names as a person reads them, control characters taken out.
fn shown(names: &[OsString]) -> Vec<String> {
    names
        .iter()
        .map(|n| clean(&n.to_string_lossy()).to_string())
        .collect()
}

/// The one line `openmoat run` prints about `names`: what it withheld under
/// the requirement (`strict`), or else what looks like a credential and still
/// reaches the agent; `None` when there is nothing to say.
pub fn notice(names: &[OsString], strict: bool) -> Option<String> {
    if strict {
        return (!names.is_empty()).then(|| {
            format!(
                "moat run: {} inherited variables withheld from the agent (--verbose names them; \
                 `--env NAME` or `sandbox.env_allow` in your policy passes one on)",
                names.len()
            )
        });
    }
    let credentials: Vec<String> = shown(names)
        .into_iter()
        .filter(|n| looks_like_credential(n))
        .collect();
    let first = credentials.first()?;
    let more = credentials.len().saturating_sub(SHOWN);
    let listed = credentials
        .get(1..SHOWN.min(credentials.len()))
        .unwrap_or_default()
        .iter()
        .fold(first.clone(), |all, n| format!("{all}, {n}"));
    let tail = if more > 0 {
        format!(" and {more} more")
    } else {
        String::new()
    };
    Some(format!(
        "moat run: {} inherited variables that look like credentials reach the agent \
         ({listed}{tail}); `require.run: full-boundary` withholds them",
        credentials.len()
    ))
}

/// `openmoat doctor`'s row: the names the run withholds, or would.
pub fn doctor_line(names: &[OsString], strict: bool) -> String {
    let what = if strict {
        "withholds from the agent"
    } else {
        "would withhold under `require.run: full-boundary`"
    };
    if names.is_empty() {
        return format!("run environment  `openmoat run` {what}: nothing here");
    }
    format!(
        "run environment  `openmoat run` {what} (names only, each agent's own excepted): {}",
        shown(names).join(", ")
    )
}

/// `--verbose`'s line naming every withheld variable; `None` when none is.
pub fn list(names: &[OsString], strict: bool) -> Option<String> {
    let verb = if strict {
        "withheld"
    } else {
        "would be withheld"
    };
    (!names.is_empty()).then(|| format!("  {verb} (names only): {}", shown(names).join(", ")))
}

#[cfg(test)]
mod tests;
