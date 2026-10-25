//! The file in which a host records the person's consent to run a hook
//! command ([`openmoat_hosts::InstallSpec::consent`]: Hermes Agent's
//! `shell-hooks-allowlist.json`, without which its gateway, cron and ACP
//! sessions skip OpenMoat's hook).
//!
//! `moat init` is the person's consent: it writes OpenMoat's commands there,
//! the lock pins the file with the hook file ([`HostConfig::extra_files`]),
//! `moat status` and `doctor` report a hook the file does not approve, and
//! `moat uninstall` takes OpenMoat's commands out again.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use openmoat_hosts::ConsentFile;
use serde_json::Value;

use super::HostConfig;
use crate::sandbox::install::{parse_json, read_text};

/// `config`'s consent file and how it is laid out; `None` for a host that
/// keeps none.
pub fn of(config: &HostConfig) -> Option<(PathBuf, &'static dyn ConsentFile)> {
    let consent = config.host.spec().install.as_ref()?.consent?;
    Some((config.dir.join(consent.name()), consent))
}

/// The consent file parsed, an empty object when there is none.
fn read(path: &Path) -> Result<Value> {
    parse_json(&read_text(path)?).map_err(|e| e.context(format!("reading {}", path.display())))
}

/// The consent file and the text `moat init` writes to it for `binary`;
/// `None` when it already approves OpenMoat's commands, or the host keeps no
/// such file.
pub fn planned(config: &HostConfig, binary: &Path) -> Result<Option<(PathBuf, String)>> {
    let Some((path, consent)) = of(config) else {
        return Ok(None);
    };
    let current = read_text(&path)?;
    match render(config, consent, &path, binary, &current)? {
        Some(text) => Ok(Some((path, text))),
        None => Ok(None),
    }
}

/// `current`, the consent file's text, as `moat init` would write it for
/// `binary`; `None` when it would not change.
pub fn render(
    config: &HostConfig,
    consent: &dyn ConsentFile,
    path: &Path,
    binary: &Path,
    current: &str,
) -> Result<Option<String>> {
    let mut doc =
        parse_json(current).map_err(|e| e.context(format!("reading {}", path.display())))?;
    let now = crate::time::rfc3339(crate::time::now_ms());
    let changed = match consent.upsert(
        &mut doc,
        config.host.id(),
        config.hooks,
        &binary.to_string_lossy(),
        &now,
    ) {
        Ok(changed) => changed,
        Err(why) => bail!(
            "{}: {why}; fix or remove it, then run `openmoat init` again",
            path.display()
        ),
    };
    Ok(changed.then(|| serde_json::to_string_pretty(&doc).unwrap_or_default() + "\n"))
}

/// Why `config`'s consent file does not approve OpenMoat's commands for
/// `binary`; `None` when it does or the host keeps none.
pub fn missing(config: &HostConfig, binary: &Path) -> Option<String> {
    let (path, consent) = of(config)?;
    let approved = read(&path).is_ok_and(|doc| {
        consent.holds(
            &doc,
            config.host.id(),
            config.hooks,
            &binary.to_string_lossy(),
        )
    });
    (!approved).then(|| {
        format!(
            "hook not approved in {}: {}; run `openmoat init`",
            path.display(),
            consent.without()
        )
    })
}
