//! OpenMoat's entries in `openclaw.json`.
//!
//! OpenClaw has no command hook, so `moat init` writes a standalone plugin
//! (`<state dir>/openmoat/openmoat.mjs`, the `moat` path filled in) and adds to
//! `openclaw.json`:
//!
//! - the file to `plugins.load.paths`; a standalone file's plugin id is its
//!   name, `openmoat` (<https://docs.openclaw.ai/plugins/hooks/tool-policy>);
//! - `plugins.entries.openmoat`: enabled, with a `before_tool_call` timeout
//!   above the plugin's wait for `moat guard`;
//! - `openmoat` to `plugins.allow` when the file has that allowlist, and out
//!   of `plugins.deny`, since either would keep the plugin from loading.

use std::fmt;

use serde_json::{Map, Value, json};

use super::{PLUGIN, PLUGIN_ID};
use crate::contract::HookSpec;
use crate::wire::hook_file::HookOutcome;
use crate::wire::owned_file::OwnedFile;
use crate::wire::plugin_config::PluginConfig;

const PLUGIN_DIR: &str = "openmoat";
const PLUGIN_FILE: &str = "openmoat.mjs";
/// Where `init` writes the plugin, below the state directory.
pub(super) const PLUGIN_PATH: &[&str] = &[PLUGIN_DIR, PLUGIN_FILE];

/// The layout of `openclaw.json`.
pub(super) struct OpenClawConfig;

impl fmt::Debug for OpenClawConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&PLUGIN, f)
    }
}

fn desired_entry(hooks: &[HookSpec]) -> Value {
    let timeout = hooks.first().map_or(0, |spec| spec.timeout) * 1000;
    json!({ "enabled": true, "hooks": { "timeouts": { "before_tool_call": timeout } } })
}

/// A `plugins.load.paths` entry for an OpenMoat plugin file, this one or one
/// an earlier `init` wrote under another state directory.
fn is_our_path(value: &Value) -> bool {
    value.as_str().is_some_and(|p| {
        let p = p.replace('\\', "/");
        p.ends_with(&format!("/{PLUGIN_DIR}/{PLUGIN_FILE}"))
    })
}

fn object<'a>(
    parent: &'a mut Map<String, Value>,
    key: &str,
    file: &str,
) -> Result<&'a mut Map<String, Value>, String> {
    match parent
        .entry(key)
        .or_insert_with(|| Value::Object(Map::new()))
    {
        Value::Object(map) => Ok(map),
        _ => Err(format!("`{key}` in {file} is not an object")),
    }
}

fn is_empty_object(value: Option<&Value>) -> bool {
    value.and_then(Value::as_object).is_some_and(Map::is_empty)
}

impl PluginConfig for OpenClawConfig {
    fn plugin(&self) -> &'static OwnedFile {
        &PLUGIN
    }

    fn plugin_path(&self) -> &'static [&'static str] {
        PLUGIN_PATH
    }

    fn upsert(
        &self,
        root: &mut Value,
        file: &str,
        plugin_path: &str,
        hooks: &[HookSpec],
    ) -> Result<HookOutcome, String> {
        let Value::Object(top) = root else {
            return Err(format!("{file} is not a JSON object"));
        };
        let plugins = object(top, "plugins", file)?;
        if plugins.get("enabled") == Some(&Value::Bool(false)) {
            return Err(format!(
                "{file} turns every plugin off (`plugins.enabled: false`), so OpenMoat's plugin \
                 cannot load; turn plugins on, then run `openmoat init` again"
            ));
        }
        let before = plugins.clone();
        let Value::Array(paths) = object(plugins, "load", file)?
            .entry("paths")
            .or_insert_with(|| Value::Array(Vec::new()))
        else {
            return Err(format!("`plugins.load.paths` in {file} is not a list"));
        };
        let had_ours = paths.iter().any(is_our_path);
        paths.retain(|p| !is_our_path(p) || p.as_str() == Some(plugin_path));
        if !paths.iter().any(|p| p.as_str() == Some(plugin_path)) {
            paths.push(Value::String(plugin_path.to_owned()));
        }
        let entries = object(plugins, "entries", file)?;
        let had_entry = entries.contains_key(PLUGIN_ID);
        entries.insert(PLUGIN_ID.to_owned(), desired_entry(hooks));
        if let Some(Value::Array(allow)) = plugins.get_mut("allow")
            && !allow.iter().any(|id| id.as_str() == Some(PLUGIN_ID))
        {
            allow.push(Value::String(PLUGIN_ID.to_owned()));
        }
        if let Some(Value::Array(deny)) = plugins.get_mut("deny") {
            deny.retain(|id| id.as_str() != Some(PLUGIN_ID));
        }
        Ok(if *plugins == before {
            HookOutcome::Unchanged
        } else if had_ours || had_entry {
            HookOutcome::Updated
        } else {
            HookOutcome::Installed
        })
    }

    fn lists_ours(&self, root: &Value) -> bool {
        let plugins = root.get("plugins");
        let entry = plugins.and_then(|p| p.pointer(&format!("/entries/{PLUGIN_ID}")));
        let paths = plugins
            .and_then(|p| p.pointer("/load/paths"))
            .and_then(Value::as_array);
        entry.is_some() || paths.is_some_and(|list| list.iter().any(is_our_path))
    }

    /// OpenMoat's entry, its plugin paths and its id in `plugins.allow`, then
    /// the objects that leaves empty.
    fn remove(&self, root: &mut Value) -> bool {
        let Some(Value::Object(plugins)) = root.get_mut("plugins") else {
            return false;
        };
        let entry = match plugins.get_mut("entries") {
            Some(Value::Object(entries)) => entries.remove(PLUGIN_ID).is_some(),
            _ => false,
        };
        if entry && is_empty_object(plugins.get("entries")) {
            plugins.remove("entries");
        }
        let path = match plugins.get_mut("load") {
            Some(Value::Object(load)) => {
                let gone = match load.get_mut("paths") {
                    Some(Value::Array(paths)) => {
                        let before = paths.len();
                        paths.retain(|p| !is_our_path(p));
                        paths.len() != before
                    }
                    _ => false,
                };
                if gone
                    && load
                        .get("paths")
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty)
                {
                    load.remove("paths");
                }
                gone
            }
            _ => false,
        };
        if path && is_empty_object(plugins.get("load")) {
            plugins.remove("load");
        }
        let removed = entry || path;
        if removed && let Some(Value::Array(allow)) = plugins.get_mut("allow") {
            allow.retain(|id| id.as_str() != Some(PLUGIN_ID));
        }
        let now_empty = plugins.is_empty();
        if removed
            && now_empty
            && let Value::Object(top) = root
        {
            top.remove("plugins");
        }
        removed
    }
}
