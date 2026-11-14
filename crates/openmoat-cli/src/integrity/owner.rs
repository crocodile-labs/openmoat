//! Which host's hook file each pinned file is, as the lock records it
//! ([`Lock::hook_owners`]), and what that host's spec says about drift in it:
//! the keys left out of its digest ([`openmoat_hosts::InstallSpec::unpinned_keys`])
//! and the keys that may drift while the guard keeps deciding
//! ([`openmoat_hosts::InstallSpec::relaxed_keys`]).
//!
//! The owner is never told by the file's name: two hosts may name their hook
//! file alike, and a file of a host whose spec lists no such keys drifts on
//! any change to its bytes. A lock written before the owners were recorded
//! has no [`Lock::hook_owners`]; for it, a pinned file is read as the hook
//! file of the one host with such keys that the spec places there (its
//! `<dir_name>/<config_file>` ending, else the only one whose variable may put
//! its `config_file` in any directory), so an unchanged install keeps
//! verifying; any other file is pinned by its bytes until a re-pin records
//! its owner.

use std::path::Path;

use openmoat_hosts::{Host, InstallSpec};

use super::Lock;

/// `host`'s install spec, for a host OpenMoat installs a hook for.
fn install(host: Host) -> Option<&'static InstallSpec> {
    host.spec().install.as_ref()
}

/// Whether `install`'s spec says anything about drift in its hook file.
fn shapes_drift(install: &InstallSpec) -> bool {
    !install.relaxed_keys.is_empty() || !install.unpinned_keys.is_empty()
}

/// The host whose hook file a lock from before [`Lock::hook_owners`] pinned
/// under `stored`, among the hosts whose spec shapes drift in it.
fn legacy_owner(stored: &Path) -> Option<Host> {
    let name = stored.file_name()?;
    let named: Vec<Host> = Host::ALL
        .into_iter()
        .filter(|host| install(*host).is_some_and(|i| shapes_drift(i) && name == i.config_file))
        .collect();
    let placed = |host: &&Host| {
        install(**host).is_some_and(|i| stored.ends_with(Path::new(i.dir_name).join(i.config_file)))
    };
    if let Some(host) = named.iter().find(placed) {
        return Some(*host);
    }
    // A variable that names the directory itself puts the file anywhere.
    let anywhere: Vec<&Host> = named
        .iter()
        .filter(|host| install(**host).is_some_and(|i| !i.variable_names_home()))
        .collect();
    match anywhere.as_slice() {
        [host] => Some(**host),
        _ => None,
    }
}

impl Lock {
    /// The host whose hook file is pinned under `stored`; `None` for a state
    /// file, a file of no host, or one a recorded lock does not name.
    pub(super) fn hook_owner(&self, stored: &str) -> Option<Host> {
        match &self.hook_owners {
            Some(owners) => owners.get(stored)?.parse().ok(),
            None => self
                .form_host(stored)
                .or_else(|| legacy_owner(Path::new(stored))),
        }
    }

    /// The top-level keys left out of the digest of the file pinned under
    /// `stored`: its owner's [`InstallSpec::unpinned_keys`].
    pub(super) fn unpinned(&self, stored: &str) -> &'static [&'static str] {
        unpinned_of(self.hook_owner(stored))
    }

    /// The install spec of the owner of the file pinned under `stored`, when
    /// it lists keys that may drift.
    pub(super) fn relaxing(&self, stored: &str) -> Option<&'static InstallSpec> {
        install(self.hook_owner(stored)?).filter(|i| !i.relaxed_keys.is_empty())
    }
}

/// [`InstallSpec::unpinned_keys`] of `owner`; none without one.
pub(super) fn unpinned_of(owner: Option<Host>) -> &'static [&'static str] {
    owner.and_then(install).map_or(&[], |i| i.unpinned_keys)
}

/// The owner a test pins `path` for: the one a lock from before the owners
/// were recorded reads it as.
#[cfg(test)]
pub(super) fn assumed(path: &Path) -> Option<Host> {
    legacy_owner(path)
}

#[cfg(test)]
mod tests;
