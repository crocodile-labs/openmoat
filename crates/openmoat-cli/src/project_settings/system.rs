//! What an agent's system-wide settings set that keeps OpenMoat's installed
//! hook from running ([`openmoat_hosts::SystemSettingsSpec`]): Claude Code's
//! managed settings (`disableAllHooks`, `allowManagedHooksOnly`), Gemini CLI's
//! system settings and defaults (`hooksConfig`), Codex's `requirements.toml`
//! (`[features] hooks`, `allow_managed_hooks_only`). An administrator deploys
//! them and they outrank the person's own files, so a hook that is installed,
//! pinned and current may still never run.
//!
//! Read only, for `moat status` and `moat doctor`: nothing here writes, creates
//! or locks a file. A file that is missing, cannot be read (one only root may
//! read, which the agent running as this user cannot read either) or does not
//! parse says nothing, so the report never fails on them.

use std::path::{Path, PathBuf};

use openmoat_hosts::{Host, Platform, SettingsFile, SystemSettingsSpec};
use serde_json::{Map, Value};

/// What `host`'s system settings on this machine set that turns OpenMoat's
/// hook off, with the file named; `None` when they turn nothing off or the
/// host has none.
pub fn switched_off(host: Host, hook_file: &Path) -> Option<String> {
    let spec = host.spec().system_settings.as_ref()?;
    let files = files(spec, crate::os_version::platform(), &|name| {
        std::env::var_os(name)
    });
    switched_off_in(host, spec, &files, hook_file)
}

/// The system files of `spec` read on `platform`, each where its variable
/// moves it (`variable` looks one up), then the drop-ins beside each in name
/// order, as the host merges them.
fn files(
    spec: &SystemSettingsSpec,
    platform: Platform,
    variable: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for file in spec
        .files
        .iter()
        .filter(|f| f.platforms.contains(&platform))
    {
        let path = file
            .variable
            .and_then(variable)
            .filter(|v| !v.is_empty())
            .map_or_else(|| PathBuf::from(file.path), PathBuf::from);
        found.extend(with_drop_ins(path, spec.drop_ins));
    }
    found
}

/// `path`, then the `*.json` files of the drop-in directory `dir` beside it
/// in name order; a directory that cannot be listed adds none.
fn with_drop_ins(path: PathBuf, dir: Option<&str>) -> Vec<PathBuf> {
    let mut drop_ins: Vec<PathBuf> = match (dir, path.parent()) {
        (Some(dir), Some(parent)) => std::fs::read_dir(parent.join(dir))
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect(),
        _ => Vec::new(),
    };
    drop_ins.sort();
    std::iter::once(path).chain(drop_ins).collect()
}

/// [`switched_off`] over `files`, the system files to read in order.
fn switched_off_in(
    host: Host,
    spec: &SystemSettingsSpec,
    files: &[PathBuf],
    hook_file: &Path,
) -> Option<String> {
    let read: Vec<(&PathBuf, Map<String, Value>)> = files
        .iter()
        .filter_map(|path| Some((path, read(path)?)))
        .collect();
    let home = crate::home::user_home().ok();
    let reader = host.spec().project_settings.as_ref().map(|s| s.reader);
    let mut rows: Vec<String> = read
        .iter()
        .filter_map(|(path, root)| {
            let base = path.parent().unwrap_or(path);
            let file = SettingsFile::new(root, base, hook_file, home.as_deref());
            let found = reader.map(|r| r.switched_off(&file)).unwrap_or_default();
            (!found.is_empty()).then(|| format!("{}: {}", path.display(), found.join("; ")))
        })
        .collect();
    let roots: Vec<&Map<String, Value>> = read.iter().map(|(_, root)| root).collect();
    if let Some(why) = spec.managed_only_without_openmoat(&roots) {
        let named = read
            .iter()
            .rev()
            .find(|(_, root)| spec.managed_only.is_some_and(|k| root.contains_key(k)))
            .map_or_else(String::new, |(path, _)| format!("{}: ", path.display()));
        rows.push(format!("{named}{why}"));
    }
    (!rows.is_empty()).then(|| rows.join("; "))
}

/// The settings object at `path`, or `None` for a file that is missing,
/// unreadable or not one object.
fn read(path: &Path) -> Option<Map<String, Value>> {
    let bytes = super::read_bytes(path).ok()??;
    super::parse(path, &bytes, false).ok()
}

#[cfg(test)]
mod tests;
