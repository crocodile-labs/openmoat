//! Where the ledger finds the hook commands, plugins and program-running
//! settings an agent loads besides OpenMoat's own hook (ADR-109). Every place
//! comes from a host's spec: its hook file and layout, its project settings,
//! hook and plugin directories, its other hook files, its plugin folders
//! ([`openmoat_hosts::Ledger`]) and the helper commands its settings reader
//! names; and, for every host, the repository's git configuration. Files are
//! read, never run.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use openmoat_hosts::{
    Activity, ForeignEntry, HookFile, Host, PluginHooks, ProjectSettingsSpec, SettingsFile,
};
use serde_json::Value;

use super::{Found, Scan};
use crate::home::Home;
use crate::install::HostConfig;
use crate::integrity::sha256_hex;

/// A file larger than this is pinned by its bytes, unread.
const MAX_BYTES: u64 = 1024 * 1024;
/// How many directories one [`Activity::ANY`] level expands to.
const MAX_DIRS: usize = 256;
/// How many files of a plugin directory a digest covers.
const MAX_FILES: usize = 512;

/// What `hosts` load for a session in `cwd` (the current directory when
/// `None`) besides OpenMoat's hook, and the repository's git programs.
pub(super) fn scan(home: &Home, hosts: &[Host], cwd: Option<&Path>) -> Scan {
    let mut scan = Collect::default();
    let cwd = cwd
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok());
    let user_home = crate::home::user_home().ok();
    for host in hosts {
        let Ok(config) = HostConfig::for_host(home, *host) else {
            continue;
        };
        user_level(&mut scan, &config, user_home.as_deref());
        if let (Some(cwd), Some(user_home)) = (&cwd, &user_home) {
            project_level(&mut scan, &config, cwd, user_home);
            let others = crate::project_settings::other_hooks::found(
                *host,
                config.dir(),
                &config.settings_path,
                cwd,
                user_home,
            );
            for path in others {
                scan.whole(
                    Some(*host),
                    &path,
                    "hook file the agent runs beside OpenMoat's",
                );
            }
        }
    }
    if let (Some(cwd), Some(user_home)) = (&cwd, &user_home) {
        git(&mut scan, cwd, user_home);
    }
    Scan {
        found: scan.found.into_values().collect(),
        scanned: scan.scanned,
    }
}

#[derive(Default)]
struct Collect {
    found: BTreeMap<String, Found>,
    scanned: std::collections::BTreeSet<String>,
}

impl Collect {
    fn add(&mut self, found: Found) {
        self.scanned.insert(found.file.display().to_string());
        self.found.entry(found.id.clone()).or_insert(found);
    }

    /// The hook entries of `layout` in the file at `path`, which holds the
    /// hooks object at its top (or, `inline`, is the event map itself); a
    /// file that cannot be read as JSON is pinned by its bytes.
    fn entries(&mut self, host: Host, layout: &'static dyn HookFile, path: &Path, what: &str) {
        self.scanned.insert(path.display().to_string());
        match read_json(path) {
            Some(Ok(root)) => self.entries_of(host, layout, path, what, &root, false),
            Some(Err(())) => {
                self.whole(Some(host), path, "hook file OpenMoat cannot read as JSON");
            }
            None => {}
        }
    }

    fn entries_of(
        &mut self,
        host: Host,
        layout: &'static dyn HookFile,
        path: &Path,
        what: &str,
        root: &Value,
        inline: bool,
    ) {
        let entries = if inline {
            layout.foreign_entries_of_map(root, host.id())
        } else {
            layout.foreign_entries(root, host.id())
        };
        for entry in entries {
            self.add(entry_found(host, path, what, &entry));
        }
    }

    /// A file (or a directory, by every file in it) the host loads and runs,
    /// pinned by its bytes, with nothing the classifier can read.
    fn whole(&mut self, host: Option<Host>, path: &Path, what: &str) {
        let Some(digest) = digest_path(path) else {
            return;
        };
        self.add(Found {
            id: path.display().to_string(),
            host,
            file: path.to_path_buf(),
            what: what.to_owned(),
            commands: Vec::new(),
            digest,
        });
    }

    /// The helper commands `config`'s settings reader names in `root`.
    fn programs(&mut self, host: Host, path: &Path, root: &Value, user_home: Option<&Path>) {
        let (Some(spec), Some(object)) = (host.spec().project_settings.as_ref(), root.as_object())
        else {
            return;
        };
        let base = path.parent().unwrap_or(path);
        let file = SettingsFile::new(object, base, path, user_home);
        for (key, command) in spec.reader.programs(&file) {
            self.add(Found {
                id: format!("{}#{key}", path.display()),
                host: Some(host),
                file: path.to_path_buf(),
                what: format!("`{key}` command"),
                digest: sha256_hex(command.as_bytes()),
                commands: vec![command],
            });
        }
    }
}

fn entry_found(host: Host, path: &Path, what: &str, entry: &ForeignEntry) -> Found {
    let digest = sha256_hex(openmoat_hosts::canonical_json(&entry.entry).as_bytes());
    Found {
        id: format!("{}#{}@{}", path.display(), entry.event, &digest[..16]),
        host: Some(host),
        file: path.to_path_buf(),
        what: format!("{what} `{}`", entry.event),
        commands: entry.commands.clone(),
        digest,
    }
}

/// The person's own files: the hook file's other entries, its helper
/// commands, and the hooks of every installed plugin.
fn user_level(scan: &mut Collect, config: &HostConfig, user_home: Option<&Path>) {
    let host = config.host;
    let Some(install) = host.spec().install.as_ref() else {
        return;
    };
    if let Some(layout) = install.hook_file.entries() {
        scan.scanned
            .insert(config.settings_path.display().to_string());
        // The lock pins this file; a file it cannot read denies every call.
        if let Ok(root) = config.read() {
            scan.entries_of(host, layout, &config.settings_path, "hook", &root, false);
            scan.programs(host, &config.settings_path, &root, user_home);
        }
        for plugins in host.spec().ledger.plugin_hooks {
            plugin_hooks(scan, host, layout, config.dir(), plugins);
        }
    }
}

/// Every installed plugin's hook file and the hooks its manifest names.
fn plugin_hooks(
    scan: &mut Collect,
    host: Host,
    layout: &'static dyn HookFile,
    dir: &Path,
    plugins: &PluginHooks,
) {
    for plugin in expand(dir, plugins.dirs) {
        let file = joined(&plugin, plugins.file);
        if file.is_file() {
            scan.entries(host, layout, &file, "plugin hook");
        }
        let Some((manifest, key)) = plugins.manifest else {
            continue;
        };
        let manifest = joined(&plugin, manifest);
        let Some(Ok(root)) = read_json(&manifest) else {
            continue;
        };
        let named = match root.get(key) {
            Some(Value::Array(list)) => list.clone(),
            Some(other) => vec![other.clone()],
            None => Vec::new(),
        };
        for item in named {
            match item {
                Value::String(path) => {
                    let Some(file) = inside(&plugin, &path) else {
                        continue;
                    };
                    if file.is_file() {
                        scan.entries(host, layout, &file, "plugin hook");
                    }
                }
                Value::Object(_) => {
                    scan.scanned.insert(manifest.display().to_string());
                    scan.entries_of(host, layout, &manifest, "plugin manifest hook", &item, true);
                }
                _ => {}
            }
        }
    }
}

/// A project's files: settings in the hook file's layout, the hook and plugin
/// directories, in the working directory and each one up to the project root.
fn project_level(scan: &mut Collect, config: &HostConfig, cwd: &Path, user_home: &Path) {
    let host = config.host;
    let (Some(spec), Some(install)) = (
        host.spec().project_settings.as_ref(),
        host.spec().install.as_ref(),
    ) else {
        return;
    };
    let layout = install.hook_file.entries();
    for root in crate::project_settings::project_dirs(cwd, user_home) {
        for name in host.spec().ledger.project_hook_files {
            let path = root.join(spec.dir).join(name);
            // The person's own file, read at the user level.
            if path == config.settings_path || !path.is_file() {
                continue;
            }
            if let Some(layout) = layout {
                scan.entries(host, layout, &path, "project hook");
            }
            if let Some(Ok(value)) = read_json(&path) {
                scan.programs(host, &path, &value, Some(user_home));
            }
        }
        project_dirs_of(scan, host, layout, spec, &root);
    }
}

/// The project's hook directory files and plugin hook files.
fn project_dirs_of(
    scan: &mut Collect,
    host: Host,
    layout: Option<&'static dyn HookFile>,
    spec: &ProjectSettingsSpec,
    root: &Path,
) {
    if let Some(dir) = &spec.hook_dir {
        for path in dir.paths() {
            for file in files_in(&root.join(path)) {
                let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");
                if !dir.extensions.contains(&ext) {
                    continue;
                }
                match layout {
                    Some(layout) if ext == "json" => {
                        scan.entries(host, layout, &file, "project hook");
                    }
                    _ => scan.whole(Some(host), &file, "project file the agent loads and runs"),
                }
            }
        }
    }
    if let Some(plugins) = &spec.plugin_dir {
        for plugin in dirs_in(&root.join(plugins.path)) {
            let file = plugin.join(plugins.hook_file);
            if let Some(layout) = layout
                && file.is_file()
            {
                scan.entries(host, layout, &file, "project plugin hook");
            }
        }
    }
}

/// Each git configuration key that runs a program, for every host.
fn git(scan: &mut Collect, cwd: &Path, user_home: &Path) {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for (file, key, value) in crate::project_settings::git_config::programs(cwd, user_home) {
        let base = format!("{}#{key}", file.display());
        let count = seen.entry(base.clone()).or_insert(0);
        *count += 1;
        let id = if *count == 1 {
            base
        } else {
            format!("{base}#{count}")
        };
        // An alias runs what follows its `!` with the shell.
        let command = value.strip_prefix('!').unwrap_or(&value).to_owned();
        scan.add(Found {
            id,
            host: None,
            file,
            what: format!("git config `{key}`"),
            digest: sha256_hex(value.as_bytes()),
            commands: vec![command],
        });
    }
}

/// The file's JSON (JSON5 accepted); `None` when it is missing, `Err` when it
/// is too large or not JSON.
fn read_json(path: &Path) -> Option<Result<Value, ()>> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    if meta.len() > MAX_BYTES {
        return Some(Err(()));
    }
    let text = fs::read_to_string(path).ok()?;
    Some(crate::json5::parse(&text).map(|p| p.value).map_err(|_| ()))
}

/// The SHA-256 of a file's bytes, or of a directory's files by their paths
/// and bytes, at most [`MAX_FILES`] of them; `None` when nothing is there.
fn digest_path(path: &Path) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if meta.is_file() {
        return Some(sha256_hex(&fs::read(path).ok()?));
    }
    let mut files = Vec::new();
    walk(path, path, &mut files);
    files.sort();
    let mut text = Vec::new();
    for (rel, bytes) in files {
        text.extend_from_slice(rel.as_bytes());
        text.push(0);
        text.extend_from_slice(sha256_hex(&bytes).as_bytes());
        text.push(b'\n');
    }
    Some(sha256_hex(&text))
}

fn walk(root: &Path, dir: &Path, files: &mut Vec<(String, Vec<u8>)>) {
    let Ok(read) = fs::read_dir(dir) else {
        return;
    };
    for entry in read.filter_map(Result::ok) {
        if files.len() >= MAX_FILES {
            return;
        }
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            walk(root, &path, files);
        } else if kind.is_file()
            && let Ok(bytes) = fs::read(&path)
        {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            files.push((rel.to_string_lossy().into_owned(), bytes));
        }
    }
}

/// `parts` under `dir`, each [`Activity::ANY`] every directory at its level.
fn expand(dir: &Path, parts: &[&str]) -> Vec<PathBuf> {
    let mut dirs = vec![dir.to_path_buf()];
    for part in parts {
        dirs = if *part == Activity::ANY {
            dirs.iter()
                .flat_map(|d| dirs_in(d))
                .take(MAX_DIRS)
                .collect()
        } else {
            dirs.iter().map(|d| d.join(part)).collect()
        };
    }
    dirs
}

fn joined(dir: &Path, parts: &[&str]) -> PathBuf {
    parts
        .iter()
        .fold(dir.to_path_buf(), |path, part| path.join(part))
}

/// `rel` (`./config/hooks.json`) under `plugin`; `None` for a path that
/// climbs out or is absolute, which the host refuses to load.
fn inside(plugin: &Path, rel: &str) -> Option<PathBuf> {
    let rel = rel.strip_prefix("./").unwrap_or(rel);
    let climbs = Path::new(rel)
        .components()
        .any(|c| !matches!(c, std::path::Component::Normal(_)));
    (!climbs && !rel.is_empty()).then(|| plugin.join(rel))
}

/// The directories in `dir` but hidden ones, sorted; links are not followed.
fn dirs_in(dir: &Path) -> Vec<PathBuf> {
    entries(dir, fs::FileType::is_dir, false)
}

/// The files in `dir`, hidden ones too (a host's glob may load them), sorted.
fn files_in(dir: &Path) -> Vec<PathBuf> {
    entries(dir, fs::FileType::is_file, true)
}

fn entries(dir: &Path, keep: fn(&fs::FileType) -> bool, hidden: bool) -> Vec<PathBuf> {
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = read
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|k| keep(&k)))
        .filter(|e| hidden || !e.file_name().to_string_lossy().starts_with('.'))
        .map(|e| e.path())
        .collect();
    paths.sort();
    paths
}

#[cfg(test)]
mod tests;
