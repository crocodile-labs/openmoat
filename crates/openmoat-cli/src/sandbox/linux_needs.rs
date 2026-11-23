//! Whether each agent's own Linux sandbox, which `openmoat init` turns on, can
//! start a command on this machine (#784): the programs it needs on the search
//! path and unprivileged user namespaces, as each host's spec states them
//! ([`openmoat_hosts::SandboxSpec::linux_needs`]). `openmoat doctor` and
//! `openmoat status` report what is missing; nothing decides differently.
//!
//! The facts come from reading settings, the search path and the `AppArmor`
//! profiles for bubblewrap ([`apparmor`]), and from the probe `openmoat run`
//! already makes to choose its tier: the system's bubblewrap asked to create
//! its namespaces, as the user. Nothing here needs root, creates a namespace of
//! its own or changes the machine. Off Linux there are no facts and nothing to
//! report.

use std::path::{Path, PathBuf};

use openmoat_hosts::{Host, LinuxProgram, LinuxSandboxNeeds, UsernsProfileFix};
use serde::Serialize;

pub use apparmor::{BwrapProfile, BwrapProfileSeen, Seen};

mod apparmor;

/// Ubuntu's `AppArmor` restriction (23.10 and later): `1` lets only programs
/// with an `AppArmor` profile that allows it create a user namespace.
const APPARMOR: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
/// Ubuntu's restriction on unconfined programs changing to a profile that
/// allows user namespaces; reported beside a `bwrap-userns-restrict` finding.
const APPARMOR_UNCONFINED: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined";
/// The `bwrap` both Ubuntu's profile and Claude Code's documented one attach to.
const USR_BIN_BWRAP: &str = "/usr/bin/bwrap";
/// How many user namespaces each user may create; `0` allows none.
const MAX_USER_NAMESPACES: &str = "/proc/sys/user/max_user_namespaces";
/// Debian's own switch (older Debian kernels): `0` refuses them to every user
/// but root.
const UNPRIVILEGED_CLONE: &str = "/proc/sys/kernel/unprivileged_userns_clone";

/// What this machine says about user namespaces and the programs the hosts'
/// sandboxes start, read without privileges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// [`APPARMOR`], trimmed; `None` where the kernel has no such setting.
    pub apparmor_restrict: Option<String>,
    /// [`APPARMOR_UNCONFINED`], trimmed; `None` where the kernel has none.
    pub apparmor_restrict_unconfined: Option<String>,
    /// The `AppArmor` profile for `/usr/bin/bwrap`; `None` where it cannot be
    /// read.
    pub bwrap_apparmor: Option<BwrapProfileSeen>,
    /// The first `bwrap` on the search path, its links resolved.
    pub bwrap_path: Option<PathBuf>,
    /// [`MAX_USER_NAMESPACES`], trimmed; `None` where it cannot be read.
    pub max_user_namespaces: Option<String>,
    /// [`UNPRIVILEGED_CLONE`], trimmed; `None` where the kernel has none.
    pub unprivileged_clone: Option<String>,
    /// The programs some host's sandbox needs that are on the search path.
    pub on_path: Vec<&'static str>,
    /// What the system's bubblewrap did when asked to create its namespaces:
    /// `Err` holds its message; `None` where it is not installed.
    pub bwrap: Option<Result<(), String>>,
}

impl Facts {
    /// This machine's facts on Linux; `None` elsewhere.
    pub fn here() -> Option<Self> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        let dirs: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default();
        let on_path = needed_programs()
            .filter(|p| crate::environment::find_in(&dirs, &[], p.name).is_some())
            .map(|p| p.name)
            .collect();
        let bwrap_path = crate::environment::find_in(&dirs, &[], "bwrap")
            .map(|p| std::fs::canonicalize(&p).unwrap_or(p));
        Some(Self {
            apparmor_restrict: setting(APPARMOR),
            apparmor_restrict_unconfined: setting(APPARMOR_UNCONFINED),
            bwrap_apparmor: BwrapProfileSeen::here(),
            bwrap_path,
            max_user_namespaces: setting(MAX_USER_NAMESPACES),
            unprivileged_clone: setting(UNPRIVILEGED_CLONE),
            on_path,
            bwrap: crate::commands::run_bubblewrap_userns(),
        })
    }
}

fn setting(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_owned())
}

/// Every program a host's Linux sandbox starts, from the specs.
fn needed_programs() -> impl Iterator<Item = &'static LinuxProgram> {
    Host::ALL
        .into_iter()
        .filter_map(needs)
        .flat_map(|n| n.programs.iter())
}

/// What `host`'s own Linux sandbox needs; `None` when it has none.
fn needs(host: Host) -> Option<&'static LinuxSandboxNeeds> {
    host.spec().sandbox.as_ref()?.linux_needs.as_ref()
}

/// The machine setting that forbids unprivileged user namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Setting {
    /// `user.max_user_namespaces` is 0.
    MaxUserNamespaces,
    /// Debian's `kernel.unprivileged_userns_clone` is 0.
    UnprivilegedClone,
    /// Ubuntu's `kernel.apparmor_restrict_unprivileged_userns` is 1.
    #[serde(rename = "apparmor")]
    AppArmor,
}

/// Why user namespaces cannot be created here: the setting that says so, and
/// bubblewrap's own message where it was asked. At least one is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Blocked {
    /// The setting that forbids them, if one does.
    pub setting: Option<Setting>,
    /// bubblewrap's message, where it was asked and failed.
    pub bwrap: Option<String>,
}

/// Whether `facts` say this user cannot create a user namespace. A bubblewrap
/// that created its namespaces settles it: it has what the hosts' sandboxes
/// use, an `AppArmor` profile of its own or a setuid bit included. Otherwise the
/// first setting that forbids them, with bubblewrap's message when it failed.
pub fn user_namespaces(facts: &Facts) -> Option<Blocked> {
    let is = |value: &Option<String>, want: &str| value.as_deref() == Some(want);
    let setting = if is(&facts.max_user_namespaces, "0") {
        Some(Setting::MaxUserNamespaces)
    } else if is(&facts.unprivileged_clone, "0") {
        Some(Setting::UnprivilegedClone)
    } else if is(&facts.apparmor_restrict, "1") {
        Some(Setting::AppArmor)
    } else {
        None
    };
    let bwrap = match &facts.bwrap {
        Some(Ok(())) => return None,
        Some(Err(why)) => Some(why.clone()),
        None => None,
    };
    (setting.is_some() || bwrap.is_some()).then_some(Blocked { setting, bwrap })
}

/// One agent whose own sandbox cannot start commands here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The host's id.
    pub host: &'static str,
    /// Its name, as rows are labelled.
    pub agent: &'static str,
    /// Programs it needs that are not on the search path.
    pub missing: Vec<&'static str>,
    /// Why it cannot create a user namespace, when it needs one.
    pub user_namespaces: Option<Blocked>,
    /// Where Ubuntu's `bwrap-userns-restrict` profile was seen, when it
    /// applies to the `bwrap` this agent runs and its sandbox fails under it.
    pub bwrap_userns_restrict: Option<Restricted>,
    /// What the agent does then, from its spec.
    pub outcome: &'static str,
    /// The fixes, each a choice on its own.
    pub fixes: Vec<String>,
}

/// The agents among `hosts` (those whose own sandbox OpenMoat wrote) whose
/// sandbox `facts` say cannot start a command.
pub fn findings(hosts: &[Host], facts: &Facts) -> Vec<Finding> {
    let blocked = user_namespaces(facts);
    hosts
        .iter()
        .filter_map(|host| finding(*host, needs(*host)?, facts, blocked.as_ref()))
        .collect()
}

fn finding(
    host: Host,
    needs: &LinuxSandboxNeeds,
    facts: &Facts,
    blocked: Option<&Blocked>,
) -> Option<Finding> {
    let missing: Vec<&LinuxProgram> = needs
        .programs
        .iter()
        .filter(|p| !facts.on_path.contains(&p.name))
        .collect();
    let user_namespaces = blocked.filter(|_| needs.user_namespaces).cloned();
    let usr_bin_bwrap = facts.bwrap_path.as_deref() == Some(Path::new(USR_BIN_BWRAP));
    let bwrap_userns_restrict = restricted_bwrap(needs, facts, usr_bin_bwrap);
    if missing.is_empty() && user_namespaces.is_none() && bwrap_userns_restrict.is_none() {
        return None;
    }
    let mut fixes = Vec::new();
    if !missing.is_empty() {
        let packages: Vec<&str> = missing.iter().map(|p| p.package).collect();
        fixes.push(format!(
            "install {} (`sudo apt-get install {}` on Debian and Ubuntu)",
            packages.join(" and "),
            packages.join(" ")
        ));
    }
    if bwrap_userns_restrict.is_some() {
        fixes.push(REPLACE_USERNS_RESTRICT.to_owned());
    }
    if let Some(blocked) = &user_namespaces {
        // Under `bwrap-userns-restrict` the `AppArmor` setting's fixes do not
        // help: the profile applies whatever the setting says.
        if bwrap_userns_restrict.is_none() || blocked.setting != Some(Setting::AppArmor) {
            fixes.extend(namespace_fixes(blocked, needs.apparmor, usr_bin_bwrap));
        }
    }
    Some(Finding {
        host: host.id(),
        agent: host.display_name(),
        missing: missing.iter().map(|p| p.name).collect(),
        user_namespaces,
        bwrap_userns_restrict,
        outcome: needs.without,
        fixes,
    })
}

/// Where Ubuntu's `bwrap-userns-restrict` was seen, when the host's
/// documentation gives its own unconfined profile for `/usr/bin/bwrap` (its
/// sandbox needs capabilities inside bubblewrap's namespace, which
/// `unpriv_bwrap` denies) and that is the `bwrap` it runs. bubblewrap creating
/// its own namespaces says nothing here: it still does under the profile.
fn restricted_bwrap(
    needs: &LinuxSandboxNeeds,
    facts: &Facts,
    usr_bin_bwrap: bool,
) -> Option<Restricted> {
    let profile = facts.bwrap_apparmor?;
    (needs.apparmor == UsernsProfileFix::UnconfinedBwrapProfile
        && usr_bin_bwrap
        && profile.profile == BwrapProfile::UsernsRestrict)
        .then(|| Restricted {
            seen: profile.seen,
            restrict_unconfined: facts.apparmor_restrict_unconfined.clone(),
        })
}

/// Ubuntu's `bwrap-userns-restrict` applies to the `bwrap` a host runs, and
/// its sandbox fails under it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Restricted {
    /// Where the profile was seen.
    pub seen: Seen,
    /// `kernel.apparmor_restrict_unprivileged_unconfined`, where the kernel
    /// has it.
    pub restrict_unconfined: Option<String>,
}

/// Claude Code's sandboxing documentation, "Add an `AppArmor` profile for
/// bubblewrap", after Ubuntu's profile is disabled the way Ubuntu's `AppArmor`
/// documentation disables one (a link in `disable/`, then `apparmor_parser -R`).
const REPLACE_USERNS_RESTRICT: &str = "disable Ubuntu's bwrap-userns-restrict \
     (`sudo ln -s /etc/apparmor.d/bwrap-userns-restrict /etc/apparmor.d/disable/` and \
     `sudo apparmor_parser -R /etc/apparmor.d/bwrap-userns-restrict`), write the profile \
     the agent's sandboxing documentation gives to /etc/apparmor.d/bwrap \
     (`profile bwrap /usr/bin/bwrap flags=(unconfined) { userns, }`, with its `abi` and \
     `include` lines), run `sudo systemctl reload apparmor`, then restart the agent; \
     `kernel.apparmor_restrict_unprivileged_userns=0` alone does not help";

/// How a person lets user namespaces be created again: what the agents'
/// own documentation and the kernel's settings say, never run by OpenMoat.
fn namespace_fixes(
    blocked: &Blocked,
    apparmor: UsernsProfileFix,
    usr_bin_bwrap: bool,
) -> Vec<String> {
    const KEEP: &str = "the same line in a file under /etc/sysctl.d/ keeps it after a reboot";
    match blocked.setting {
        Some(Setting::AppArmor) => {
            let profile = match apparmor {
                // Its documentation: the profile only where it runs
                // `/usr/bin/bwrap`; otherwise the `sysctl`.
                UsernsProfileFix::UnconfinedBwrapProfile if !usr_bin_bwrap => None,
                UsernsProfileFix::UnconfinedBwrapProfile => Some(
                    "the AppArmor profile the agent's sandboxing documentation gives for \
                     /usr/bin/bwrap, in /etc/apparmor.d/bwrap (`profile bwrap /usr/bin/bwrap \
                     flags=(unconfined) { userns, }`, with its `abi` and `include` lines), then \
                     `sudo systemctl reload apparmor` and restart the agent"
                        .to_owned(),
                ),
                UsernsProfileFix::BwrapUsernsRestrict => Some(
                    "load Ubuntu's bwrap-userns-restrict profile, as the agent's sandboxing \
                     documentation says (Ubuntu 24.04: `sudo apt install apparmor-profiles \
                     apparmor-utils`, `sudo install -m 0644 \
                     /usr/share/apparmor/extra-profiles/bwrap-userns-restrict \
                     /etc/apparmor.d/bwrap-userns-restrict`, `sudo apparmor_parser -r \
                     /etc/apparmor.d/bwrap-userns-restrict`), then restart the agent"
                        .to_owned(),
                ),
                UsernsProfileFix::OwnPackage(package) => Some(format!(
                    "install the agent's own AppArmor package, {package}, as its sandboxing \
                     documentation gives it, then restart the agent"
                )),
                _ => None,
            };
            profile
                .into_iter()
                .chain(std::iter::once(format!(
                    "`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, which \
                     lifts the restriction for every program until the next reboot; {KEEP}"
                )))
                .collect()
        }
        Some(Setting::UnprivilegedClone) => vec![format!(
            "`sudo sysctl -w kernel.unprivileged_userns_clone=1`; {KEEP}"
        )],
        Some(Setting::MaxUserNamespaces) => vec![format!(
            "set user.max_user_namespaces above 0 with `sudo sysctl -w`; {KEEP}"
        )],
        None => vec![
            "in a container or virtual machine, let its runtime allow user namespaces inside it"
                .to_owned(),
        ],
    }
}

impl Finding {
    /// Why, in a few words, for `openmoat status`.
    pub fn short(&self) -> String {
        let mut why = Vec::new();
        if !self.missing.is_empty() {
            why.push(format!("{} not on PATH", self.missing.join(", ")));
        }
        if self.user_namespaces.is_some() {
            why.push("user namespaces are blocked".to_owned());
        }
        if self.bwrap_userns_restrict.is_some() {
            why.push("Ubuntu's bwrap-userns-restrict AppArmor profile applies to bwrap".to_owned());
        }
        format!("own sandbox cannot start commands here: {}", why.join("; "))
    }

    /// The whole reason, the outcome and the fixes, for `openmoat doctor`.
    pub fn line(&self) -> String {
        let mut why = Vec::new();
        if !self.missing.is_empty() {
            why.push(format!("{} is not on PATH", self.missing.join(" and ")));
        }
        if let Some(blocked) = &self.user_namespaces {
            why.push(blocked.describe());
        }
        if let Some(restricted) = &self.bwrap_userns_restrict {
            why.push(restricted.describe());
        }
        format!(
            "{:<16} the agent's own sandbox cannot start commands on this machine: {}, so {}. \
             To fix it: {}. OpenMoat has no setting that leaves this agent's sandbox off; its \
             hook still decides each call",
            self.agent,
            why.join("; "),
            self.outcome,
            self.fixes.join("; or ")
        )
    }
}

impl Restricted {
    /// Why the sandbox fails under the profile, in words.
    fn describe(&self) -> String {
        let seen = match self.seen {
            Seen::Loaded => "is loaded",
            Seen::Installed => "is in /etc/apparmor.d/, which AppArmor loads at boot",
        };
        let unconfined = if self.restrict_unconfined.as_deref() == Some("1") {
            ", with kernel.apparmor_restrict_unprivileged_unconfined at 1"
        } else {
            ""
        };
        format!(
            "Ubuntu's bwrap-userns-restrict AppArmor profile {seen}{unconfined}: its \
             unpriv_bwrap takes every capability from what /usr/bin/bwrap starts, so the \
             sandbox cannot make the user namespace it needs inside bubblewrap's \
             (`apply-seccomp: write /proc/self/setgroups`)"
        )
    }
}

impl Blocked {
    /// What forbids user namespaces, in words.
    fn describe(&self) -> String {
        let setting = self.setting.map(|s| match s {
            Setting::MaxUserNamespaces => "user.max_user_namespaces is 0",
            Setting::UnprivilegedClone => "kernel.unprivileged_userns_clone is 0",
            Setting::AppArmor => {
                "kernel.apparmor_restrict_unprivileged_userns is 1 (Ubuntu's AppArmor \
                 restriction on user namespaces)"
            }
        });
        match (setting, &self.bwrap) {
            (Some(setting), Some(why)) => format!("{setting}; {why}"),
            (Some(setting), None) => setting.to_owned(),
            (None, Some(why)) => why.clone(),
            (None, None) => "user namespaces are not allowed".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests;
