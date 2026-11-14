//! Whether a settings file the host reads turns OpenMoat's own hook off by
//! name (Gemini CLI's `hooksConfig.disabled`, pi's `extensions` entry, a
//! project's `.agents/hooks.json` entry set to `enabled: false`), in the
//! person's own settings or a project's, for a package from the host's own
//! plugin channel to decide itself rather than stand aside (ADR-099).

use std::path::Path;

use openmoat_hosts::Host;

use super::{Reading, candidates, check_as, switched_off};

/// Whether `host`'s own settings file in `config_dir`, or a project settings
/// file for `cwd`, turns OpenMoat's hook in `hook_file` off, or cannot be
/// read to tell: either way `init`'s hook may not run here.
#[must_use]
pub fn hook_switched_off(
    host: Host,
    cwd: &Path,
    user_home: &Path,
    config_dir: &Path,
    hook_file: &Path,
) -> bool {
    if switched_off(host, config_dir, hook_file).is_some() {
        return true;
    }
    let Some(spec) = host.spec().project_settings.as_ref() else {
        return false;
    };
    spec.files().into_iter().any(|name| {
        candidates(cwd, user_home, spec, name)
            .into_iter()
            .any(|path| {
                let base = path.parent().unwrap_or(&path).to_path_buf();
                let reading = Reading {
                    reader: spec.reader,
                    base: &base,
                    hook_file,
                };
                check_as(&path, spec.reader.reads_comments(), |root| {
                    reading.switched_off(root)
                })
                .is_some()
            })
    })
}
