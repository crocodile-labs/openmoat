//! OpenClaw: OpenMoat's plugin file and its entries in `openclaw.json`.
//!
//! OpenClaw has no command hook, so `moat init` writes a standalone plugin
//! (`integrations/openclaw/openmoat.mjs`, the `moat` path filled in) to
//! `<state dir>/openmoat/openmoat.mjs` and adds to `openclaw.json`:
//!
//! - the file to `plugins.load.paths`; a standalone file's plugin id is its
//!   name, `openmoat` (<https://docs.openclaw.ai/plugins/hooks/tool-policy>);
//! - `plugins.entries.openmoat`: enabled, with a `before_tool_call` timeout
//!   above the plugin's wait for `moat guard`;
//! - `openmoat` to `plugins.allow` when the file has that allowlist, and out
//!   of `plugins.deny`, since either would keep the plugin from loading.
//!
//! `openclaw.json` is JSON5 to OpenClaw (the hosts crate says where it is). It is
//! read as JSON5 ([`read`]) and written back as plain JSON, which keeps every
//! value; a file with comments is not written, since that would drop them.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde_json::{Map, Value, json};

use super::{HookState, HostConfig, Outcome};
use crate::home::write_private;

/// The parsed `openclaw.json` at `path`, an empty object when there is none.
pub fn read(path: &Path) -> Result<Value> {
    Ok(read_parsed(path)?.value)
}

fn read_parsed(path: &Path) -> Result<crate::json5::Parsed> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    parse(&text).with_context(|| format!("parsing {}", path.display()))
}

/// `text` (an `openclaw.json`, empty when there is none) as JSON5.
pub fn parse(text: &str) -> Result<crate::json5::Parsed> {
    if text.trim().is_empty() {
        return Ok(crate::json5::Parsed {
            value: Value::Object(Map::new()),
            comments: false,
        });
    }
    crate::json5::parse(text)
}

/// Refuse to write `file` back when `parsed` has comments: plain JSON has
/// none, so writing it would drop them.
pub fn refuse_comments(parsed: &crate::json5::Parsed, file: &Path) -> Result<()> {
    if parsed.comments {
        bail!(
            "{} has comments (JSON5), and OpenMoat writes it back as plain JSON, which would \
             drop them; move the comments out of the file (or delete them), then run the \
             command again. No file was changed",
            file.display()
        );
    }
    Ok(())
}

/// The parsed `openclaw.json` at `path` for an edit: refused when writing it
/// back would drop comments.
pub fn read_for_edit(path: &Path) -> Result<Value> {
    let parsed = read_parsed(path)?;
    refuse_comments(&parsed, path)?;
    Ok(parsed.value)
}

use openmoat_hosts::OPENCLAW_PLUGIN_ID as PLUGIN_ID;
const PLUGIN_DIR: &str = "openmoat";
const PLUGIN_FILE: &str = "openmoat.mjs";
const SOURCE: &str = include_str!("../../integrations/openclaw/openmoat.mjs");
/// The line `init` fills in with the binary's path.
const BINARY_LINE: &str = "const MOAT = __MOAT_BINARY__;";

/// Where `init` writes the plugin for `config`'s OpenClaw.
pub fn plugin_path(config: &HostConfig) -> PathBuf {
    config.dir().join(PLUGIN_DIR).join(PLUGIN_FILE)
}

/// The plugin as `init` writes it for `binary`.
pub fn plugin_text(binary: &Path) -> Result<String> {
    let quoted = serde_json::to_string(&binary.to_string_lossy())?;
    if SOURCE.matches(BINARY_LINE).count() != 1 {
        bail!("the OpenClaw plugin source has no single `{BINARY_LINE}` line");
    }
    Ok(SOURCE.replacen(BINARY_LINE, &format!("const MOAT = {quoted};"), 1))
}

/// Whether the plugin file holds what `init` writes for `binary`.
pub fn plugin_current(config: &HostConfig, binary: &Path) -> bool {
    let wanted = plugin_text(binary).ok();
    fs::read_to_string(plugin_path(config)).ok() == wanted
}

pub fn write_plugin(config: &HostConfig, binary: &Path) -> Result<()> {
    write_private(&plugin_path(config), plugin_text(binary)?.as_bytes())
}

/// The binary an installed plugin file runs, for "points at another binary".
fn plugin_binary(config: &HostConfig) -> Option<String> {
    let text = fs::read_to_string(plugin_path(config)).ok()?;
    let line = text.lines().find(|l| l.starts_with("const MOAT = "))?;
    let literal = line.strip_prefix("const MOAT = ")?.strip_suffix(';')?;
    serde_json::from_str(literal).ok()
}

fn desired_entry(config: &HostConfig) -> Value {
    let timeout = config.hooks.first().map_or(0, |spec| spec.timeout) * 1000;
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
    file: &Path,
) -> Result<&'a mut Map<String, Value>> {
    match parent
        .entry(key)
        .or_insert_with(|| Value::Object(Map::new()))
    {
        Value::Object(map) => Ok(map),
        _ => bail!("`{key}` in {} is not an object", file.display()),
    }
}

/// Add OpenMoat's plugin to the parsed `openclaw.json` `root`.
pub fn upsert(root: &mut Value, config: &HostConfig) -> Result<Outcome> {
    let file = &config.settings_path;
    let Value::Object(top) = root else {
        bail!("{} is not a JSON object", file.display());
    };
    let plugins = object(top, "plugins", file)?;
    if plugins.get("enabled") == Some(&Value::Bool(false)) {
        bail!(
            "{} turns every plugin off (`plugins.enabled: false`), so OpenMoat's plugin \
             cannot load; turn plugins on, then run `openmoat init` again",
            file.display()
        );
    }
    let ours = path_string(&plugin_path(config));
    let before = plugins.clone();
    let Value::Array(paths) = object(plugins, "load", file)?
        .entry("paths")
        .or_insert_with(|| Value::Array(Vec::new()))
    else {
        bail!("`plugins.load.paths` in {} is not a list", file.display());
    };
    let had_ours = paths.iter().any(is_our_path);
    paths.retain(|p| !is_our_path(p) || p.as_str() == Some(ours.as_str()));
    if !paths.iter().any(|p| p.as_str() == Some(ours.as_str())) {
        paths.push(Value::String(ours));
    }
    let entries = object(plugins, "entries", file)?;
    let had_entry = entries.contains_key(PLUGIN_ID);
    entries.insert(PLUGIN_ID.to_owned(), desired_entry(config));
    if let Some(Value::Array(allow)) = plugins.get_mut("allow")
        && !allow.iter().any(|id| id.as_str() == Some(PLUGIN_ID))
    {
        allow.push(Value::String(PLUGIN_ID.to_owned()));
    }
    if let Some(Value::Array(deny)) = plugins.get_mut("deny") {
        deny.retain(|id| id.as_str() != Some(PLUGIN_ID));
    }
    Ok(if *plugins == before {
        Outcome::Unchanged
    } else if had_ours || had_entry {
        Outcome::Updated
    } else {
        Outcome::Installed
    })
}

/// Whether OpenMoat's plugin for `binary` is in the parsed `openclaw.json`
/// `root` and on disk as `init` writes it.
pub fn state(config: &HostConfig, binary: &Path, root: &Value) -> HookState {
    let plugins = root.get("plugins");
    let entry = plugins.and_then(|p| p.pointer(&format!("/entries/{PLUGIN_ID}")));
    let paths = plugins
        .and_then(|p| p.pointer("/load/paths"))
        .and_then(Value::as_array);
    let listed = paths.is_some_and(|list| list.iter().any(is_our_path));
    if entry.is_none() && !listed {
        return HookState::Missing;
    }
    let mut desired = root.clone();
    let current = matches!(upsert(&mut desired, config), Ok(Outcome::Unchanged));
    if current && plugin_current(config, binary) {
        return HookState::Installed;
    }
    HookState::Stale {
        command: plugin_binary(config).unwrap_or_else(|| "?".to_owned()),
    }
}

/// The inverse of [`upsert`] on a parsed `openclaw.json`: OpenMoat's entry,
/// its plugin paths and its id in `plugins.allow`, then the objects that
/// leaves empty. Returns whether anything was removed.
pub fn remove(root: &mut Value) -> bool {
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

fn is_empty_object(value: Option<&Value>) -> bool {
    value.and_then(Value::as_object).is_some_and(Map::is_empty)
}

/// Delete the plugin file `init` wrote and its directory when that leaves it
/// empty. Returns the file when there was one.
pub fn remove_plugin(config: &HostConfig) -> Result<Option<PathBuf>> {
    let path = plugin_path(config);
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

fn path_string(path: &Path) -> String {
    crate::context::path_string(path)
}

#[cfg(test)]
mod tests;
