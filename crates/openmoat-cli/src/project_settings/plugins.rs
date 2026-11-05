//! A project's directory of plugins (`ProjectSettingsSpec::plugin_dir`,
//! goose's `.agents/plugins`). The host loads each plugin there beside the
//! person's, and one named as OpenMoat's in place of it: unless that plugin's
//! hook file is OpenMoat's byte for byte, a session started in that directory
//! runs every call without OpenMoat's hook. Repository content is the
//! attacker's (`docs/THREAT_MODEL.md` §2), so `moat status` and `moat doctor`
//! report the host not protected there ([`replaced`]) and warn about the other
//! plugins' hooks ([`others`]).

use std::fs;
use std::path::{Path, PathBuf};

use openmoat_hosts::{Host, PluginDir};

/// Why `host` runs no OpenMoat hook in a session started in `cwd`: `cwd`'s
/// plugin directory holds a plugin named as OpenMoat's whose hook file is not
/// OpenMoat's `hook_file`. The path and the fix are in the text; `None` when
/// the host reads no project plugins or nothing replaces OpenMoat's.
#[must_use]
pub fn replaced(cwd: &Path, user_home: &Path, host: Host, hook_file: &Path) -> Option<String> {
    let dir = host.spec().project_settings.as_ref()?.plugin_dir.as_ref()?;
    if !crate::project::trusted(cwd, user_home) {
        return None;
    }
    let found = replacing(cwd, dir, hook_file)?;
    Some(format!(
        "{} replaces OpenMoat's plugin for a {} session started in this directory, which runs \
         every call without OpenMoat; remove that directory",
        found.display(),
        host.display_name()
    ))
}

/// The plugin under `root`'s `dir` that replaces OpenMoat's, unless its hook
/// file is OpenMoat's own (the same file, or the same bytes).
pub(super) fn replacing(root: &Path, dir: &PluginDir, hook_file: &Path) -> Option<PathBuf> {
    let plugin = root.join(dir.path).join(dir.own);
    // A link or a file under the name is loaded or skipped by the host as it
    // sees fit; anything there is reported.
    fs::symlink_metadata(&plugin).ok()?;
    let theirs = plugin.join(dir.hook_file);
    let same_file = matches!(
        (fs::canonicalize(&theirs), fs::canonicalize(hook_file)),
        (Ok(a), Ok(b)) if a == b
    );
    let same_bytes = matches!(
        (super::read_bytes(&theirs), super::read_bytes(hook_file)),
        (Ok(Some(a)), Ok(Some(b))) if a == b
    );
    (!same_file && !same_bytes).then_some(plugin)
}

/// The hook files of every plugin under `root`'s `dir` other than OpenMoat's
/// name, sorted; none when the directory cannot be read.
pub(super) fn others(root: &Path, dir: &PluginDir) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(root.join(dir.path)) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| Some(entry.ok()?.path()))
        .filter(|path| path.file_name().is_some_and(|name| name != dir.own))
        .map(|path| path.join(dir.hook_file))
        .filter(|file| file.is_file())
        .collect();
    files.sort();
    files
}

/// [`replaced`] for the current directory; `None` when it or the home
/// directory cannot be found.
#[must_use]
pub fn replaced_here(host: Host, hook_file: &Path) -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    let user_home = crate::home::user_home().ok()?;
    replaced(&cwd, &user_home, host, hook_file)
}
