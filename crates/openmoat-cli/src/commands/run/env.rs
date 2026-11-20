//! Which inherited environment variables reach what `openmoat run` starts
//! (ADR-077, ADR-105). A scrubbed environment passes only an allowlist: a
//! base every program needs, the host's own names from its spec, the names the
//! person's policy adds and the names given with `--env`. It is scrubbed under
//! `require.run: full-boundary`, `sandbox.env: scrubbed` or `--scrub-env`
//! ([`Mode::choose`]). Otherwise everything still does, as before, and one line
//! says what looks like a credential. Either way a brokered secret's variable
//! holds its placeholder, never the value ([`brokered`]).
//!
//! Names only, everywhere in this file: a value is never read, kept or shown.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};

use openmoat_core::boundary::RunEnvironment;
use openmoat_core::{Policy, RunEnv, SecretSource};
use openmoat_hosts::Host;

use crate::render::clean;

/// Whether the run scrubs the environment, and what chose that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mode {
    pub scrubbed: bool,
    /// In the words the run notice and the boundary record use.
    pub why: String,
}

impl Mode {
    /// The policy that requires the full boundary (`strict`, which scrubs
    /// whatever else says), then `--scrub-env` (`flag`, which only raises),
    /// then the person's `sandbox.env` (`choice`), then [`RunEnv::DEFAULT`].
    pub fn choose(choice: Option<RunEnv>, strict: Option<&str>, flag: bool) -> Self {
        let (scrubbed, why) = match (strict, flag, choice) {
            (Some(asks), _, _) => (
                true,
                format!("{asks} requires `require.run: full-boundary`"),
            ),
            (None, true, _) => (true, "`openmoat run --scrub-env`".to_owned()),
            (None, false, Some(env)) => (
                env == RunEnv::Scrubbed,
                format!("`sandbox.env: {}` in your policy", name(env)),
            ),
            (None, false, None) => (
                RunEnv::DEFAULT == RunEnv::Scrubbed,
                format!("the default (`sandbox.env: {}`)", name(RunEnv::DEFAULT)),
            ),
        };
        Self { scrubbed, why }
    }
}

fn name(env: RunEnv) -> &'static str {
    match env {
        RunEnv::Inherited => "inherited",
        RunEnv::Scrubbed => "scrubbed",
    }
}

/// Each variable a brokered secret of `policy` is read from (`source: env`)
/// and the placeholder the program gets in it instead (ADR-020): the run's
/// proxy reads the value from this process, and a tool that sends the
/// placeholder to the secret's host has it replaced there.
pub fn brokered(policy: &Policy) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = policy
        .secrets
        .iter()
        .filter_map(|s| match &s.source {
            SecretSource::Env(name) => Some((name.clone(), s.placeholder())),
            _ => None,
        })
        .collect();
    pairs.sort();
    pairs.dedup_by(|a, b| a.0 == b.0);
    pairs
}

/// Once the run has set everything of its own on `command`: remove what a
/// scrubbed `mode` withholds of this process's environment, say so (and with
/// `verbose` name it), and return the boundary record's part. What `command`
/// already sets or removes is the run's own and never withheld.
pub fn apply(
    command: &mut std::process::Command,
    (allowed, mode, brokered): (&Allowed, &Mode, &[(String, String)]),
    verbose: bool,
) -> RunEnvironment {
    let set_by_run: Vec<OsString> = command
        .get_envs()
        .map(|(name, _)| name.to_owned())
        .collect();
    let inherited = || std::env::vars_os().map(|(name, _)| name);
    let withheld = withheld(inherited(), allowed, &|name| {
        set_by_run.iter().any(|set| set == name)
    });
    if mode.scrubbed {
        for name in &withheld {
            command.env_remove(name);
        }
    }
    if let Some(line) = notice(&withheld, mode.scrubbed) {
        eprintln!("{line}");
    }
    if verbose && let Some(line) = list(&withheld, mode.scrubbed) {
        eprintln!("{line}");
    }
    record(mode, inherited(), &withheld, brokered)
}

/// The boundary record's part for this run (ADR-105): `inherited` names what
/// this process has, `withheld` what the run removes, `brokered` the
/// variables that hold a placeholder.
pub fn record(
    mode: &Mode,
    inherited: impl IntoIterator<Item = OsString>,
    withheld: &[OsString],
    brokered: &[(String, String)],
) -> RunEnvironment {
    let text = |names: &[OsString]| shown(names);
    let passed = if mode.scrubbed {
        let mut names: Vec<OsString> = inherited
            .into_iter()
            .filter(|n| !withheld.contains(n) && !brokered.iter().any(|(b, _)| n == b.as_str()))
            .collect();
        names.sort();
        names.dedup();
        text(&names)
    } else {
        Vec::new()
    };
    RunEnvironment {
        scrubbed: mode.scrubbed,
        why: mode.why.clone(),
        passed,
        withheld: if mode.scrubbed {
            text(withheld)
        } else {
            Vec::new()
        },
        brokered: brokered.iter().map(|(name, _)| name.clone()).collect(),
    }
}

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
    // Where common toolchains are, which a build reads and nothing secret is
    // in (ADR-105): without them a scrubbed run would break normal builds.
    "JAVA_HOME",
    "GOPATH",
    "GOROOT",
    "GOBIN",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "NVM_DIR",
    "NVM_BIN",
    "PYENV_ROOT",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "CONDA_DEFAULT_ENV",
    "HOMEBREW_PREFIX",
    "HOMEBREW_CELLAR",
    "HOMEBREW_REPOSITORY",
    "MANPATH",
    "INFOPATH",
    "LESS",
    "GPG_TTY",
    // Where OpenMoat's own state is: the hook is told the same on its command line.
    crate::home::ENV,
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

/// The one line `openmoat run` prints about `names`: what it withheld from a
/// `scrubbed` environment, or else what looks like a credential and still
/// reaches the agent; `None` when there is nothing to say.
pub fn notice(names: &[OsString], scrubbed: bool) -> Option<String> {
    if scrubbed {
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
         ({listed}{tail}); `sandbox.env: scrubbed` in your policy or `--scrub-env` withholds them",
        credentials.len()
    ))
}

/// `openmoat doctor`'s row: the names the run withholds from a `scrubbed`
/// environment, or would.
pub fn doctor_line(names: &[OsString], scrubbed: bool) -> String {
    let what = if scrubbed {
        "withholds from the agent"
    } else {
        "would withhold with `sandbox.env: scrubbed`"
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
pub fn list(names: &[OsString], scrubbed: bool) -> Option<String> {
    let verb = if scrubbed {
        "withheld"
    } else {
        "would be withheld"
    };
    (!names.is_empty()).then(|| format!("  {verb} (names only): {}", shown(names).join(", ")))
}

#[cfg(test)]
mod tests;
