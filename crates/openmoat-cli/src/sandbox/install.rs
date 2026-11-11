//! Writing and reading back the host sandbox settings (the only file I/O of
//! the Standard tier).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use openmoat_hosts::{Host, SandboxFormat};
use toml_edit::DocumentMut;

use super::backend::{Pin, SandboxBackend};
use super::{Plan, Report};
use crate::home::{Home, write_private};
use crate::install::{HostConfig, Recorded, SANDBOX_BACKUP};
use crate::integrity::Lock;

/// Hosts with a sandbox backend ([`openmoat_hosts::HostSpec::sandbox`]), in
/// the order OpenMoat writes them.
pub fn hosts() -> impl Iterator<Item = Host> {
    Host::ALL.into_iter().filter(|h| format(*h).is_some())
}

/// The format of `host`'s sandbox settings, which names its backend; `None`
/// for a host OpenMoat writes no sandbox for.
pub fn format(host: Host) -> Option<SandboxFormat> {
    host.spec().sandbox.as_ref().map(|s| s.format)
}

/// `host`'s sandbox backend; `None` for a host OpenMoat writes no sandbox for.
pub fn backend(host: Host) -> Option<&'static dyn SandboxBackend> {
    format(host).map(super::backend::backend)
}

/// The host whose sandbox settings are in `format`.
pub fn host_with(format: SandboxFormat) -> Result<Host> {
    hosts()
        .find(|h| self::format(*h) == Some(format))
        .with_context(|| format!("no host keeps its sandbox as {format:?}"))
}

/// Why `host`'s sandbox is not written on this OS, as `init`, `sandbox`,
/// `doctor` and `status` print it; `None` when it is written
/// ([`openmoat_hosts::SandboxSpec::unavailable_on_windows`]).
pub fn unavailable(host: Host) -> Option<&'static str> {
    unavailable_on(host, cfg!(windows))
}

/// What `init` and `sandbox sync` print when [`write()`] changed the settings
/// of a host whose sandbox is [`unavailable`]: Claude Code's deny rules are
/// written there, and the sandbox settings of an older version removed.
pub const OLD_SANDBOX_REMOVED: &str = "deny rules written for Claude Code's file tools, without \
     sandbox settings (an older OpenMoat's are removed), so Claude Code can start";

fn unavailable_on(host: Host, windows: bool) -> Option<&'static str> {
    let sandbox = host.spec().sandbox.as_ref()?;
    sandbox.unavailable_on_windows.filter(|_| windows)
}

/// The file `host`'s sandbox settings live in, beside its hook file.
pub fn settings_path(home: &Home, host: Host) -> Result<PathBuf> {
    let hooks = HostConfig::for_host(home, host)?.settings_path;
    Ok(match &host.spec().sandbox {
        Some(sandbox) => hooks.with_file_name(sandbox.file),
        None => hooks,
    })
}

/// Merge the plan's settings for `host` into its file, or, where the host's
/// sandbox is [`unavailable`], remove what an older version wrote (Cursor's
/// file is left alone: no version wrote it there). Returns whether the file
/// changed (or would, with `dry_run`). `home`'s `hosts.json` records the
/// backup and the Claude Code rules OpenMoat owns.
pub fn write(home: &Home, host: Host, plan: &Plan, dry_run: bool) -> Result<bool> {
    let path = settings_path(home, host)?;
    let current = read_text(&path)?;
    let Some(rendered) = render(home, host, plan, &current)
        .with_context(|| format!("updating {}", path.display()))?
    else {
        return Ok(false);
    };
    if dry_run {
        return Ok(true);
    }
    if let Some(owned) = rendered.claude_rules {
        let mut recorded = Recorded::load(home)?;
        if owned != recorded.claude_rules {
            recorded.claude_rules = owned;
            recorded.save(home)?;
        }
    }
    crate::install::back_up(home, &path, SANDBOX_BACKUP)?;
    write_private(&path, rendered.text.as_bytes())?;
    Ok(true)
}

/// What [`render`] makes of a host's sandbox settings file.
pub struct Rendered {
    /// The whole file as it would be written.
    pub text: String,
    /// For Claude Code, the rules OpenMoat owns in it afterwards.
    pub claude_rules: Option<Vec<String>>,
}

/// `current` (the text of `host`'s sandbox settings file, empty when there is
/// none) with the plan merged in, as [`write()`] would write it; `None` when it
/// would not change. Reads `hosts.json` for the Claude Code rules OpenMoat
/// owns, writes nothing.
pub fn render(home: &Home, host: Host, plan: &Plan, current: &str) -> Result<Option<Rendered>> {
    match backend(host) {
        Some(backend) => backend.render(home, host, plan, current),
        None => Ok(None),
    }
}

/// A file's text, or empty when it does not exist.
pub fn read_text(path: &Path) -> Result<String> {
    if !path.exists() {
        return Ok(String::new());
    }
    fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// A JSON settings text, an empty one being an empty object.
pub fn parse_json(text: &str) -> Result<serde_json::Value> {
    if text.trim().is_empty() {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    serde_json::from_str(text).context("parsing the settings")
}

/// The backend report for `host`; an empty one for a host without a sandbox.
pub fn report(host: Host, plan: &Plan) -> &Report {
    static NONE: Report = Report {
        losses: Vec::new(),
        allowances: Vec::new(),
    };
    backend(host).map_or(&NONE, |b| b.report(plan))
}

/// Whether any host's backend that masks the policy's secrets is
/// [`unavailable`] on this OS, so it masks nothing.
pub fn masks_unavailable() -> bool {
    hosts()
        .filter(|h| backend(*h).is_some_and(SandboxBackend::masks_secrets))
        .any(|h| unavailable(h).is_some())
}

/// Settings files under this shell's environment that the lock pins by the
/// part OpenMoat owns ([`Pin::Part`]) and that carry that part.
pub fn part_pinned_settings(home: &Home) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for host in hosts() {
        if let Some(Pin::Part { carries, .. }) = backend(host).map(SandboxBackend::pin) {
            files.extend(carrying(home, host, carries)?);
        }
    }
    Ok(files)
}

/// Settings files under this shell's environment that the lock pins whole
/// ([`Pin::Whole`]) and that carry OpenMoat's keys.
pub fn whole_pinned_settings(home: &Home) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for host in hosts() {
        if let Some(Pin::Whole(carries)) = backend(host).map(SandboxBackend::pin) {
            files.extend(carrying(home, host, carries)?);
        }
    }
    Ok(files)
}

/// `host`'s settings file when it exists and `carries` finds OpenMoat's part in it.
fn carrying(
    home: &Home,
    host: Host,
    carries: fn(&Path) -> Result<bool>,
) -> Result<Option<PathBuf>> {
    let path = settings_path(home, host)?;
    Ok((path.is_file() && carries(&path)?).then_some(path))
}

/// SHA-256 of the part of the settings file at `path` OpenMoat owns, as the
/// lock pins it: the digest of the backend of the host whose sandbox settings
/// file has `path`'s name. A file no backend pins by part is an error, which
/// the lock check reports as drift.
pub fn part_digest(path: &Path) -> Result<String> {
    let digest = hosts()
        .filter(|host| {
            host.spec()
                .sandbox
                .as_ref()
                .is_some_and(|s| path.file_name() == Some(std::ffi::OsStr::new(s.file)))
        })
        .filter_map(backend)
        .find_map(|b| match b.pin() {
            Pin::Part { digest, .. } => Some(digest),
            Pin::WithHooks | Pin::Whole(_) => None,
        })
        .with_context(|| format!("no sandbox backend pins {} by part", path.display()))?;
    digest(path)
}

/// Problems with `host`'s sandbox settings for `moat doctor` and `moat status`;
/// `None` when the host is not on this machine.
pub fn problems(
    home: &Home,
    host: Host,
    plan: &Plan,
    lock: Option<&Lock>,
) -> Result<Option<Vec<String>>> {
    let Some(backend) = backend(host) else {
        return Ok(None);
    };
    let path = settings_path(home, host)?;
    if !path.parent().is_some_and(Path::is_dir) {
        return Ok(None);
    }
    let mut problems = backend.problems(home, &path, plan, lock)?;
    problems.dedup();
    Ok(Some(problems))
}

pub fn read_toml(path: &Path) -> Result<DocumentMut> {
    if !path.exists() {
        return Ok(DocumentMut::new());
    }
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    text.parse()
        .with_context(|| format!("parsing {}", path.display()))
}

#[cfg(test)]
mod tests;
