//! A hook that is a plugin file OpenMoat owns, loaded by the host's configuration
//! file ([`HookLayout::Plugin`]): writes and removes the plugin, and asks the
//! host's [`PluginConfig`] to edit the parsed configuration.
//!
//! The configuration is JSON5 to the host. It is read as JSON5
//! ([`super::json5_file::read`]) and written back as plain JSON, which keeps every
//! value; a file with comments is not written, since that would drop them.
//!
//! [`HookLayout::Plugin`]: openmoat_hosts::HookLayout::Plugin

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use openmoat_hosts::{OwnedFile, PluginConfig};
use serde_json::Value;

use super::{HookState, HostConfig, Outcome, owned};
use crate::home::write_private;

/// Where `init` writes the plugin for `config`.
pub fn plugin_path(config: &HostConfig, layout: &dyn PluginConfig) -> PathBuf {
    layout
        .plugin_path()
        .iter()
        .fold(config.dir().to_path_buf(), |path, part| path.join(part))
}

/// Whether the plugin file holds `layout`'s plugin as `init` writes it for `binary`.
pub fn plugin_current(config: &HostConfig, layout: &dyn PluginConfig, binary: &Path) -> bool {
    let wanted = owned::text(config, layout.plugin(), binary).ok();
    fs::read_to_string(plugin_path(config, layout)).ok() == wanted
}

pub fn write_plugin(config: &HostConfig, layout: &dyn PluginConfig, binary: &Path) -> Result<()> {
    write_private(
        &plugin_path(config, layout),
        owned::text(config, layout.plugin(), binary)?.as_bytes(),
    )
}

/// The binary an installed plugin file runs, for "points at another binary".
fn plugin_binary(plugin: &OwnedFile, path: &Path) -> Option<String> {
    plugin.binary(&fs::read_to_string(path).ok()?)
}

/// Add OpenMoat's plugin to the parsed configuration `root`.
pub fn upsert(root: &mut Value, config: &HostConfig, layout: &dyn PluginConfig) -> Result<Outcome> {
    let file = config.settings_path.display().to_string();
    let ours = crate::context::path_string(&plugin_path(config, layout));
    layout
        .upsert(root, &file, &ours, config.hooks)
        .map_err(anyhow::Error::msg)
}

/// Whether OpenMoat's plugin for `binary` is in the parsed configuration
/// `root` and on disk as `init` writes it.
pub fn state(
    config: &HostConfig,
    layout: &dyn PluginConfig,
    binary: &Path,
    root: &Value,
) -> HookState {
    if !layout.lists_ours(root) {
        return HookState::Missing;
    }
    let mut desired = root.clone();
    let current = matches!(upsert(&mut desired, config, layout), Ok(Outcome::Unchanged));
    if current && plugin_current(config, layout, binary) {
        return HookState::Installed;
    }
    HookState::Stale {
        command: plugin_binary(layout.plugin(), &plugin_path(config, layout))
            .unwrap_or_else(|| "?".to_owned()),
    }
}

/// Delete the plugin file `init` wrote and its directory when that leaves it
/// empty. Returns the file when there was one.
pub fn remove_plugin(config: &HostConfig, layout: &dyn PluginConfig) -> Result<Option<PathBuf>> {
    let path = plugin_path(config, layout);
    if !path.is_file() {
        return Ok(None);
    }
    fs::remove_file(&path)?;
    if let Some(dir) = path.parent() {
        // Only an empty directory goes; one holding anything else stays.
        fs::remove_dir(dir).ok();
    }
    Ok(Some(path))
}

#[cfg(test)]
mod tests;
