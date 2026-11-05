//! Other hook files a host runs for the event OpenMoat's hook answers
//! (`HostSpec::other_hooks`): Cline runs every `PreToolUse` file of its hook
//! directories, the person's and the workspace's, and its plugins, and any of
//! them can rewrite a call's input after OpenMoat checked it. OpenMoat pins
//! only its own file, so `moat status` and `moat doctor` name the others.

use std::fs;
use std::path::{Path, PathBuf};

use openmoat_hosts::{Host, OtherHooks};

use super::Warning;
use crate::home::Home;
use crate::install::HostConfig;

/// Every hook file and plugin `host` runs beside OpenMoat's `hook_file` for a
/// session in `cwd`, sorted within each directory; none for a host whose spec
/// names no other hooks.
#[must_use]
pub fn found(
    host: Host,
    config_dir: &Path,
    hook_file: &Path,
    cwd: &Path,
    user_home: &Path,
) -> Vec<PathBuf> {
    let Some(spec) = host.spec().other_hooks.as_ref() else {
        return Vec::new();
    };
    let ours = fs::canonicalize(hook_file).unwrap_or_else(|_| hook_file.to_path_buf());
    let dirs = spec
        .home_dirs
        .iter()
        .map(|dir| user_home.join(dir))
        .chain(spec.config_dirs.iter().map(|dir| config_dir.join(dir)))
        .chain(
            super::project_dirs(cwd, user_home)
                .into_iter()
                .flat_map(|root| spec.project_dirs.iter().map(move |dir| root.join(dir))),
        );
    let mut files: Vec<PathBuf> = dirs
        .flat_map(|dir| hook_files(&dir, spec))
        .filter(|path| fs::canonicalize(path).unwrap_or_else(|_| path.clone()) != ours)
        .collect();
    for dir in spec.plugin_dirs {
        files.extend(entries(&config_dir.join(dir)));
    }
    files
}

/// The files in `dir` named [`OtherHooks::stem`], with or without an
/// extension, sorted; none when `dir` cannot be read.
fn hook_files(dir: &Path, spec: &OtherHooks) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = entries(dir)
        .into_iter()
        .filter(|path| path.is_file() && path.file_stem().is_some_and(|stem| stem == spec.stem))
        .collect();
    files.sort();
    files
}

/// Every entry of `dir` but hidden ones, sorted; none when it cannot be read.
fn entries(dir: &Path) -> Vec<PathBuf> {
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = read
        .filter_map(|entry| Some(entry.ok()?.path()))
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| !name.to_string_lossy().starts_with('.'))
        })
        .collect();
    paths.sort();
    paths
}

/// One warning per [`found`] file of every host on this machine whose spec
/// names other hooks, for the current directory; empty when it or the home
/// directory cannot be found.
#[must_use]
pub fn warnings_here(home: &Home) -> Vec<Warning> {
    let (Ok(cwd), Ok(user_home)) = (std::env::current_dir(), crate::home::user_home()) else {
        return Vec::new();
    };
    Host::ALL
        .into_iter()
        .filter_map(|host| Some((host, host.spec().other_hooks.as_ref()?)))
        .filter_map(|(host, spec)| {
            let config = HostConfig::for_host(home, host).ok()?;
            config.host_present().then_some((host, spec, config))
        })
        .flat_map(|(host, spec, config)| {
            found(host, config.dir(), &config.settings_path, &cwd, &user_home)
                .into_iter()
                .map(move |path| Warning {
                    host,
                    text: format!(
                        "{}: {}; review it and remove what you did not add",
                        path.display(),
                        spec.effect
                    ),
                })
        })
        .collect()
}

#[cfg(test)]
mod tests;
