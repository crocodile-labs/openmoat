//! Whether each agent's own Linux sandbox, which `openmoat init` turns on, can
//! start a command on this machine (#784): the programs it needs on the search
//! path and unprivileged user namespaces, as each host's spec states them
//! ([`openmoat_hosts::SandboxSpec::linux_needs`]). `openmoat doctor` and
//! `openmoat status` report what is missing; nothing decides differently.
//!
//! The facts come from reading settings and the search path, and from the probe
//! `openmoat run` already makes to choose its tier: the system's bubblewrap
//! asked to create its namespaces, as the user. Nothing here needs root or
//! changes the machine. Off Linux there are no facts and nothing to report.

use std::path::PathBuf;

use openmoat_hosts::{Host, LinuxProgram, LinuxSandboxNeeds};
use serde::Serialize;

/// Ubuntu's `AppArmor` restriction (23.10 and later): `1` lets only programs
/// with an `AppArmor` profile that allows it create a user namespace.
const APPARMOR: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
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
        Some(Self {
            apparmor_restrict: setting(APPARMOR),
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
    if missing.is_empty() && user_namespaces.is_none() {
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
    if let Some(blocked) = &user_namespaces {
        fixes.extend(namespace_fixes(blocked));
    }
    Some(Finding {
        host: host.id(),
        agent: host.display_name(),
        missing: missing.iter().map(|p| p.name).collect(),
        user_namespaces,
        outcome: needs.without,
        fixes,
    })
}

/// How a person lets user namespaces be created again: what the agents'
/// own documentation and the kernel's settings say, never run by OpenMoat.
fn namespace_fixes(blocked: &Blocked) -> Vec<String> {
    const KEEP: &str = "the same line in a file under /etc/sysctl.d/ keeps it after a reboot";
    match blocked.setting {
        Some(Setting::AppArmor) => vec![
            "an AppArmor profile that lets bwrap create user namespaces, as the agent's \
             sandboxing documentation gives one (Ubuntu's apparmor-profiles package has \
             bwrap-userns-restrict), then restart the agent"
                .to_owned(),
            format!(
                "`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, which lifts \
                 the restriction for every program until the next reboot; {KEEP}"
            ),
        ],
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
