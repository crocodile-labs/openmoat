//! What a project holds that turns a host's OpenMoat hook off when a session
//! starts there, for `openmoat run`'s check before it starts the agent
//! (ADR-098).
//!
//! The same reading as `openmoat status` and the guard's write check: each
//! project settings file of the host's spec (`HostSpec::project_settings`) in
//! the working directory and at its project root, read as the host reads it
//! and handed to the host's own reader (`SettingsReader::project_switched_off`),
//! and a plugin of the project's plugin directory that replaces OpenMoat's.
//! A file that cannot be read counts: what the host loads from it is unknown.

use std::path::{Path, PathBuf};

use openmoat_hosts::{Host, SettingsFile};
use serde_json::{Map, Value};

/// One project file that turns the hook off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Off {
    /// The file (or the plugin's directory).
    pub path: PathBuf,
    /// What in it turns the hook off, one sentence each.
    pub what: Vec<String>,
    /// Whether it does so only through the top-level keys a session
    /// override replaces (`SessionOverride::keys`).
    pub overridden: bool,
}

/// Every file of `host`'s project settings for a session in `cwd` that turns
/// OpenMoat's hook off, `hook_file` being OpenMoat's own (pi's entries name
/// it) and `keys` the top-level keys a session override of the host replaces.
#[must_use]
pub fn turned_off(
    cwd: &Path,
    user_home: &Path,
    host: Host,
    hook_file: &Path,
    keys: &[&str],
) -> Vec<Off> {
    let Some(spec) = host.spec().project_settings.as_ref() else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for name in spec.files() {
        for path in super::candidates(cwd, user_home, spec, name) {
            let bytes = match super::read_bytes(&path) {
                Ok(None) => continue,
                Ok(Some(bytes)) => bytes,
                Err(e) => {
                    found.push(Off {
                        path,
                        what: vec![format!("cannot be checked: {e:#}")],
                        overridden: false,
                    });
                    continue;
                }
            };
            // Text the host replaces before parsing may become anything,
            // a switch that turns the hook off included (ADR-098).
            let text = String::from_utf8_lossy(&bytes);
            if let Some(marker) = spec
                .reader
                .substitutions()
                .iter()
                .find(|marker| text.contains(**marker))
            {
                found.push(Off {
                    path,
                    what: vec![format!(
                        "holds `{marker}…}}`, which the agent replaces with text OpenMoat cannot \
                         read before it loads the file"
                    )],
                    overridden: false,
                });
                continue;
            }
            // Text the host cannot parse loads nothing: it refuses the file.
            let Ok(root) = super::parse(&path, &bytes, spec.reader.reads_comments()) else {
                continue;
            };
            let base = path.parent().unwrap_or(&path).to_path_buf();
            let off = |root: &Map<String, Value>| {
                let file = SettingsFile::new(root, &base, hook_file, Some(user_home));
                spec.reader.project_switched_off(&file)
            };
            let what = off(&root);
            if what.is_empty() {
                continue;
            }
            let mut rest = root.clone();
            rest.retain(|key, _| !keys.contains(&key.as_str()));
            let overridden = !keys.is_empty() && off(&rest).is_empty();
            found.push(Off {
                path,
                what,
                overridden,
            });
        }
    }
    if let Some(dir) = &spec.plugin_dir {
        for root in super::project_dirs(cwd, user_home) {
            if let Some(plugin) = super::plugins::replacing(&root, dir, hook_file) {
                found.push(Off {
                    path: plugin,
                    what: vec![format!(
                        "replaces OpenMoat's plugin with one of the project's (`{}`)",
                        dir.own
                    )],
                    overridden: false,
                });
            }
        }
    }
    found
}

#[cfg(test)]
mod tests;
