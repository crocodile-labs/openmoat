//! Refresh opted-in existing hooks during person-authorised upgrades and syncs.

use std::path::Path;

use anyhow::Result;
use openmoat_hosts::Host;

use super::{HostConfig, Outcome};
use crate::home::Home;

/// Replace existing hooks that opt into refresh, preserving unrelated entries and backups.
/// Call only after checking the terminal and the existing policy lock.
pub fn update(home: &Home, binary: &Path) -> Result<bool> {
    let mut changed = false;
    for config in pending(home, binary)? {
        changed |= config.install(home, binary, false)? != Outcome::Unchanged;
    }
    Ok(changed)
}

/// Whether an opted-in existing hook needs rewriting; does not install new hosts.
pub fn needed(home: &Home, binary: &Path) -> Result<bool> {
    Ok(!pending(home, binary)?.is_empty())
}

fn pending(home: &Home, binary: &Path) -> Result<Vec<HostConfig>> {
    let mut configs = Vec::new();
    for host in Host::ALL {
        let config = HostConfig::for_host(home, host)?;
        if config
            .layout
            .entries()
            .is_some_and(openmoat_hosts::HookFile::refresh_on_upgrade)
            && needs_update(&config, binary)?
        {
            configs.push(config);
        }
    }
    Ok(configs)
}

fn needs_update(config: &HostConfig, binary: &Path) -> Result<bool> {
    let root = config.read()?;
    let Some(layout) = config.layout.entries() else {
        return Ok(false);
    };
    let ours = config.hooks.iter().any(|spec| {
        root.pointer(&format!("/hooks/{}", spec.event))
            .and_then(serde_json::Value::as_array)
            .is_some_and(|entries| {
                entries
                    .iter()
                    .any(|entry| layout.is_ours(entry, config.host.id()))
            })
    });
    if !ours {
        return Ok(false);
    }
    Ok(config
        .render(binary, &serde_json::to_string(&root)?)?
        .is_some())
}
