//! Which pinned files are digested in a host's pinned form
//! ([`openmoat_hosts::InstallSpec::pinned_form`]) rather than by their bytes.
//!
//! The host that owns the file decides, never what the file contains: the lock
//! records it per file ([`Lock::pinned_forms`]) when the file is pinned as that
//! host's hook file. Any other file, whatever it holds, is pinned by its bytes,
//! so a JSON file of another host that looks like OpenClaw's `openclaw.json`
//! still drifts when its `mcp.servers` change.
//!
//! A lock written before the owner was recorded has no [`Lock::pinned_forms`].
//! Its pins were chosen by content, which only ever picked OpenClaw's form for
//! a file holding OpenMoat's plugin entry. For such a lock, a file whose name is
//! a host's `config_file` (`openclaw.json`) is read as that host's, so an
//! unchanged default install keeps verifying; every other file is read by its
//! bytes, and one pinned in the relaxed form under another name shows drift
//! until a re-pin, which records the owner.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use openmoat_hosts::Host;

use super::Lock;

/// A host's pinned form of its hook file, and how the file is read.
#[derive(Clone, Copy)]
pub(super) struct Form {
    /// The form of the parsed file.
    pub shape: fn(serde_json::Value) -> Option<serde_json::Value>,
    /// Whether the file is YAML ([`openmoat_hosts::HookLayout::Yaml`]); else JSON5.
    pub yaml: bool,
}

/// `host`'s pinned form; `None` for a host whose file is pinned by its bytes.
pub(super) fn form_of(host: Host) -> Option<Form> {
    let install = host.spec().install.as_ref()?;
    Some(Form {
        shape: install.pinned_form?,
        yaml: install.hook_file.is_yaml(),
    })
}

/// The host a lock from before [`Lock::pinned_forms`] digested `stored` for:
/// the host with a pinned form whose `config_file` is the file's name.
fn legacy_owner(stored: &Path) -> Option<Host> {
    let name = stored.file_name()?;
    Host::ALL.into_iter().find(|host| {
        host.spec()
            .install
            .as_ref()
            .is_some_and(|install| install.pinned_form.is_some() && name == install.config_file)
    })
}

impl Lock {
    /// The host whose pinned form the file pinned under `stored` is digested
    /// in; `None` for a file pinned by its bytes.
    pub(super) fn form_host(&self, stored: &str) -> Option<Host> {
        let host = match &self.pinned_forms {
            Some(forms) => forms.get(stored)?.parse().ok()?,
            None => legacy_owner(Path::new(stored))?,
        };
        form_of(host).map(|_| host)
    }

    /// The pinned form the file pinned under `stored` is digested in.
    pub(super) fn form(&self, stored: &str) -> Option<Form> {
        form_of(self.form_host(stored)?)
    }

    /// Each pinned file digested in a host's pinned form, with that host.
    pub(super) fn owners(&self) -> Vec<(PathBuf, Host)> {
        self.entries
            .keys()
            .filter_map(|stored| Some((PathBuf::from(stored), self.form_host(stored)?)))
            .collect()
    }

    /// [`Self::owners`] as [`Lock::pinned_forms`] records them.
    pub(super) fn owner_ids(&self) -> BTreeMap<String, String> {
        self.owners()
            .into_iter()
            .map(|(path, host)| (path.to_string_lossy().into_owned(), host.id().to_owned()))
            .collect()
    }
}

#[cfg(test)]
mod tests;
