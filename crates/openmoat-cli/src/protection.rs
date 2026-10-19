//! Each agent's protection level, as `moat status`, `moat doctor` and the home
//! screen report it. It is derived only from checks moat already makes: the
//! hook's state and, for the hosts OpenMoat configures a sandbox for, whether
//! that sandbox is in place and matches the policy.

use std::path::Path;

use anyhow::Result;
use openmoat_hosts::Host;
use serde::Serialize;

use crate::home::Home;
use crate::install::{HookState, HostConfig, Recorded};
use crate::integrity::Lock;
use crate::sandbox::{Plan, install as host_sandbox};

/// How much of the policy is enforced for one agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    /// The hook is installed and current, and the generated sandbox matches the policy.
    HookAndOsSandbox,
    /// The hook is installed and current, but no OS sandbox from OpenMoat is in force.
    HookOnly,
    /// The hook is missing, stale or unreadable.
    NotProtected,
    /// The agent is on this machine, but `moat init` left it out.
    NotSetUp,
    /// The agent's configuration directory does not exist.
    NotFound,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Self::HookAndOsSandbox => "hook + OS sandbox",
            Self::HookOnly => "hook only",
            Self::NotProtected => "not protected",
            Self::NotSetUp => "not set up",
            Self::NotFound => "host not found",
        }
    }

    /// Whether the hook applies the policy to the agent's calls.
    pub fn hooked(self) -> bool {
        matches!(self, Self::HookAndOsSandbox | Self::HookOnly)
    }
}

/// One agent's protection level, why it is not higher, and what it never covers.
#[derive(Debug, Serialize)]
pub struct Protection {
    pub host: &'static str,
    pub name: &'static str,
    pub level: Level,
    /// Why the level is `hook-only` or `not-protected`.
    pub reason: Option<String>,
    /// What the hook and sandbox do not cover for this agent
    /// ([`HostSpec::gaps`](openmoat_hosts::HostSpec::gaps)).
    pub gaps: &'static str,
}

impl Protection {
    /// `<level>[: <reason>]`, or `None` for an agent not set up or not found,
    /// which the hook lines already report.
    pub fn summary(&self) -> Option<String> {
        if matches!(self.level, Level::NotSetUp | Level::NotFound) {
            return None;
        }
        Some(match &self.reason {
            Some(reason) => format!("{}: {reason}", self.level.label()),
            None => self.level.label().to_owned(),
        })
    }
}

/// Every supported agent's protection, in [`Host::ALL`] order.
pub fn report(home: &Home, binary: &Path) -> Result<Vec<Protection>> {
    let plan = home
        .load_policy()
        .ok()
        .and_then(|p| Plan::new(home, &p).ok());
    let lock = Lock::load(&home.lock_path()).ok();
    let recorded = Recorded::load(home).unwrap_or_default();
    Host::ALL
        .into_iter()
        .map(|host| {
            let config = HostConfig::for_host(home, host)?;
            let (level, reason) = level(
                &config.state(binary),
                config.host_present(),
                recorded.skipped(host),
                || sandbox(home, host, plan.as_ref(), lock.as_ref()),
            );
            Ok(Protection {
                host: host.id(),
                name: host.display_name(),
                level,
                reason,
                gaps: host.spec().gaps,
            })
        })
        .collect()
}

/// The level from the hook's state, the agent's presence, whether `moat init`
/// skipped it, and (read only when the hook is installed) its sandbox check.
fn level(
    hook: &HookState,
    present: bool,
    skipped: bool,
    sandbox: impl FnOnce() -> Result<(), String>,
) -> (Level, Option<String>) {
    let not_protected = |why: &str| (Level::NotProtected, Some(why.to_owned()));
    match hook {
        HookState::Installed => match sandbox() {
            Ok(()) => (Level::HookAndOsSandbox, None),
            Err(why) => (Level::HookOnly, Some(why)),
        },
        HookState::Missing if !present => (Level::NotFound, None),
        HookState::Missing if skipped => (Level::NotSetUp, None),
        HookState::Missing => not_protected("hook missing"),
        HookState::Stale { .. } => not_protected("hook out of date"),
        HookState::Unreadable(_) => not_protected("hook file unreadable"),
    }
}

/// `Ok` when OpenMoat's sandbox for `host` is in place and matches the policy;
/// otherwise which of it is missing, off or drifted.
fn sandbox(
    home: &Home,
    host: Host,
    plan: Option<&Plan>,
    lock: Option<&Lock>,
) -> Result<(), String> {
    if host_sandbox::format(host).is_none() {
        return Err(format!(
            "no OS sandbox from OpenMoat; `moat run` covers the {} CLI (docs/SANDBOX.md)",
            host.display_name()
        ));
    }
    if let Some(note) = host_sandbox::unavailable(host) {
        return Err(note.to_owned());
    }
    let plan = plan.ok_or("the policy does not load, so the sandbox cannot be checked")?;
    match host_sandbox::problems(home, host, plan, lock) {
        Ok(Some(problems)) => match problems.as_slice() {
            [] => Ok(()),
            [only] => Err(format!("sandbox: {only}")),
            [first, rest @ ..] => Err(format!("sandbox: {first} (and {} more)", rest.len())),
        },
        Ok(None) => Err("sandbox settings missing".to_owned()),
        Err(error) => Err(format!("sandbox: {error:#}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_installed_hook_with_a_matching_sandbox_is_hook_and_os_sandbox() {
        let got = level(&HookState::Installed, true, false, || Ok(()));
        assert_eq!(got, (Level::HookAndOsSandbox, None));
    }

    #[test]
    fn an_installed_hook_without_the_sandbox_is_hook_only_and_says_why() {
        let got = level(&HookState::Installed, true, false, || {
            Err("sandbox: drifted".to_owned())
        });
        assert_eq!(got, (Level::HookOnly, Some("sandbox: drifted".to_owned())));
    }

    #[test]
    fn a_missing_stale_or_unreadable_hook_is_not_protected() {
        let stale = HookState::Stale {
            command: "/gone/moat".to_owned(),
        };
        let unreadable = HookState::Unreadable("bad json".to_owned());
        for (hook, why) in [
            (HookState::Missing, "hook missing"),
            (stale, "hook out of date"),
            (unreadable, "hook file unreadable"),
        ] {
            let got = level(&hook, true, false, || panic!("sandbox read without a hook"));
            assert_eq!(got, (Level::NotProtected, Some(why.to_owned())));
        }
    }

    #[test]
    fn an_agent_left_out_or_absent_keeps_its_own_line() {
        assert_eq!(
            level(&HookState::Missing, true, true, || Ok(())),
            (Level::NotSetUp, None)
        );
        assert_eq!(
            level(&HookState::Missing, false, false, || Ok(())),
            (Level::NotFound, None)
        );
    }

    #[test]
    fn summary_skips_agents_with_their_own_line() {
        let protection = |level, reason: Option<&str>| Protection {
            host: "codex",
            name: "Codex",
            level,
            reason: reason.map(str::to_owned),
            gaps: "",
        };
        assert_eq!(
            protection(Level::HookOnly, Some("why"))
                .summary()
                .as_deref(),
            Some("hook only: why")
        );
        assert_eq!(protection(Level::NotSetUp, None).summary(), None);
    }
}
