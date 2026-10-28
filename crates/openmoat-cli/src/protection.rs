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
            // A version that does not load OpenMoat's hook (OpenCode 2).
            let unsupported = config
                .host_present()
                .then(|| crate::install::host_version::unsupported(host))
                .flatten();
            let (level, reason) = match unsupported {
                Some(why) => (Level::NotProtected, Some(why)),
                None => level(
                    &config.state(binary),
                    config.host_present(),
                    recorded.skipped(host),
                    || {
                        crate::project_settings::switched_off(
                            host,
                            config.dir(),
                            &config.settings_path,
                        )
                    },
                    || sandbox(home, host, plan.as_ref(), lock.as_ref()),
                ),
            };
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
/// skipped it, and (read only when the hook is installed) whether the agent's
/// own settings turn the hook off and its sandbox check.
fn level(
    hook: &HookState,
    present: bool,
    skipped: bool,
    switched_off: impl FnOnce() -> Option<String>,
    sandbox: impl FnOnce() -> Result<(), String>,
) -> (Level, Option<String>) {
    let not_protected = |why: &str| (Level::NotProtected, Some(why.to_owned()));
    match hook {
        HookState::Installed => match switched_off() {
            Some(off) => (
                Level::NotProtected,
                Some(format!("hook turned off by {off}")),
            ),
            None => match sandbox() {
                Ok(()) => (Level::HookAndOsSandbox, None),
                Err(why) => (Level::HookOnly, Some(why)),
            },
        },
        HookState::Missing if !present => (Level::NotFound, None),
        HookState::Missing if skipped => (Level::NotSetUp, None),
        HookState::Missing => not_protected("hook missing"),
        HookState::Stale { .. } => not_protected("hook out of date"),
        HookState::Unreadable(_) => not_protected("hook file unreadable"),
        HookState::Unapproved(_) => not_protected("hook not approved by the agent"),
    }
}

/// [`os_sandboxed`] as the guard reads it: kept in `sandboxed.json` in the
/// state directory under the digest of `policy.lock`. The lock pins the policy
/// and every host's sandbox settings, and the guard has verified them against
/// it before deciding (a drifted pin denies the call), so while the lock is the
/// same the answer is too; a changed policy or sandbox re-pins the lock, which
/// makes the next call work it out again. Working it out compiles the policy's
/// sandbox plan (tens of milliseconds), which a session that runs many scripts
/// it wrote would otherwise pay on every call. The agent cannot write the state
/// directory (`kernel-self`); a file that cannot be read or written only means
/// the answer is worked out again.
pub fn os_sandboxed_by_lock(home: &Home, host: Host) -> bool {
    if host_sandbox::format(host).is_none() || host_sandbox::unavailable(host).is_some() {
        return false;
    }
    let Ok(lock) = std::fs::read(home.lock_path()) else {
        return os_sandboxed(home, host);
    };
    let digest = crate::integrity::sha256_hex(&lock);
    let path = home.root().join("sandboxed.json");
    let mut kept: SandboxedByLock = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .filter(|k: &SandboxedByLock| k.lock == digest)
        .unwrap_or_else(|| SandboxedByLock {
            lock: digest,
            hosts: std::collections::BTreeMap::new(),
        });
    if let Some(known) = kept.hosts.get(host.id()) {
        return *known;
    }
    let answer = os_sandboxed(home, host);
    kept.hosts.insert(host.id().to_owned(), answer);
    if let Ok(bytes) = serde_json::to_vec(&kept) {
        let _ = crate::home::write_private(&path, &bytes);
    }
    answer
}

/// `sandboxed.json`: [`os_sandboxed`] per host id, for the lock whose digest
/// it names.
#[derive(serde::Serialize, serde::Deserialize)]
struct SandboxedByLock {
    lock: String,
    hosts: std::collections::BTreeMap<String, bool>,
}

/// Whether OpenMoat's OS sandbox runs `host`'s shell commands here: the host
/// has one (its spec), it applies on this OS, and its settings are in place
/// and match the policy and the lock, as `status` reports `hook + OS sandbox`.
/// The guard reads it through [`os_sandboxed_by_lock`], only for a call that
/// runs code its session wrote (`session_code.rs`).
pub fn os_sandboxed(home: &Home, host: Host) -> bool {
    if host_sandbox::format(host).is_none() || host_sandbox::unavailable(host).is_some() {
        return false;
    }
    let plan = home
        .load_policy()
        .ok()
        .and_then(|p| Plan::new(home, &p).ok());
    let lock = Lock::load(&home.lock_path()).ok();
    sandbox(home, host, plan.as_ref(), lock.as_ref()).is_ok()
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
            "no OS sandbox from OpenMoat; `openmoat run` puts {} in one (docs/SANDBOX.md)",
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

    /// The answer kept under the lock's digest is used while the lock is the
    /// same, and worked out again once the lock changes.
    #[test]
    fn the_sandbox_answer_is_kept_by_the_lock_digest() {
        let host = Host::ClaudeCode;
        if host_sandbox::format(host).is_none() || host_sandbox::unavailable(host).is_some() {
            return; // no OpenMoat sandbox for this host on this OS: always false
        }
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("state"));
        std::fs::create_dir_all(home.root()).unwrap();
        std::fs::write(home.lock_path(), b"lock one").unwrap();
        // An empty home has no sandbox settings in place.
        assert!(!os_sandboxed_by_lock(&home, host));
        let kept = home.root().join("sandboxed.json");
        let text = std::fs::read_to_string(&kept).unwrap();
        assert!(
            text.contains(&crate::integrity::sha256_hex(b"lock one")),
            "{text}"
        );
        // A kept answer is read back as it is while the lock is unchanged.
        std::fs::write(&kept, text.replace("false", "true")).unwrap();
        assert!(os_sandboxed_by_lock(&home, host));
        // A new lock makes the answer be worked out again.
        std::fs::write(home.lock_path(), b"lock two").unwrap();
        assert!(!os_sandboxed_by_lock(&home, host));
    }

    #[test]
    fn hosts_without_an_openmoat_sandbox_are_never_sandboxed() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("state"));
        // decided from the spec alone, before any host file is read
        for host in Host::ALL.into_iter().filter(|h| h.spec().sandbox.is_none()) {
            assert!(!os_sandboxed(&home, host), "{}", host.id());
        }
    }

    #[test]
    fn an_installed_hook_with_a_matching_sandbox_is_hook_and_os_sandbox() {
        let got = level(&HookState::Installed, true, false, || None, || Ok(()));
        assert_eq!(got, (Level::HookAndOsSandbox, None));
    }

    #[test]
    fn an_installed_hook_without_the_sandbox_is_hook_only_and_says_why() {
        let got = level(
            &HookState::Installed,
            true,
            false,
            || None,
            || Err("sandbox: drifted".to_owned()),
        );
        assert_eq!(got, (Level::HookOnly, Some("sandbox: drifted".to_owned())));
    }

    #[test]
    fn an_installed_hook_the_agent_settings_turn_off_is_not_protected() {
        let got = level(
            &HookState::Installed,
            true,
            false,
            || Some("settings.json: `disableAllHooks`".to_owned()),
            || panic!("sandbox read for a hook that is off"),
        );
        assert_eq!(got.0, Level::NotProtected);
        assert_eq!(
            got.1.as_deref(),
            Some("hook turned off by settings.json: `disableAllHooks`")
        );
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
            let got = level(
                &hook,
                true,
                false,
                || panic!("settings read without a hook"),
                || panic!("sandbox read without a hook"),
            );
            assert_eq!(got, (Level::NotProtected, Some(why.to_owned())));
        }
    }

    #[test]
    fn an_agent_left_out_or_absent_keeps_its_own_line() {
        assert_eq!(
            level(&HookState::Missing, true, true, || None, || Ok(())),
            (Level::NotSetUp, None)
        );
        assert_eq!(
            level(&HookState::Missing, false, false, || None, || Ok(())),
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
