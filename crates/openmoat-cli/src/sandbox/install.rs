//! Writing and reading back the host sandbox settings (the only file I/O of
//! the Standard tier).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use openmoat_hosts::Host;
use toml_edit::DocumentMut;

use super::{Plan, Report, claude, codex, codex_config_path, cursor};
use crate::home::{Home, write_private};
use crate::install::{HostConfig, Recorded, SANDBOX_BACKUP, read_or_empty};
use crate::integrity::Lock;

/// Hosts with a sandbox backend, in the order OpenMoat writes them.
pub const HOSTS: [Host; 3] = [Host::ClaudeCode, Host::Codex, Host::Cursor];

/// Why `host`'s sandbox is not written on this OS, as `init`, `sandbox`,
/// `doctor` and `status` print it; `None` when it is written. Claude Code's
/// sandbox runs on macOS, Linux and WSL2 only, and with `failIfUnavailable`
/// Claude Code exits at startup where it cannot run: native Windows (#327).
/// Cursor documents its sandbox for macOS and Linux only.
pub fn unavailable(host: Host) -> Option<&'static str> {
    unavailable_on(host, cfg!(windows))
}

/// Whether Claude Code runs on macOS here, where it applies a `file` mask entry
/// as a read deny (the sandboxing docs, "Mask credential files").
pub const MASK_FILES_DENIED: bool = cfg!(target_os = "macos");

/// Claude Code's user settings under this shell's environment, an empty
/// object when the file does not exist.
pub fn claude_settings(home: &Home) -> Result<serde_json::Value> {
    read_or_empty(&settings_path(home, Host::ClaudeCode)?)
}

/// What `init` and `sandbox sync` print when [`write()`] changed the settings
/// of a host whose sandbox is [`unavailable`]: Claude Code's deny rules are
/// written there, and the sandbox settings of an older version removed.
pub const OLD_SANDBOX_REMOVED: &str = "deny rules written for Claude Code's file tools, without \
     sandbox settings (an older moat's are removed), so Claude Code can start";

fn unavailable_on(host: Host, windows: bool) -> Option<&'static str> {
    match host {
        Host::ClaudeCode if windows => Some(
            "sandbox not available on native Windows; the hook still applies the policy \
             (use WSL2 for OS confinement)",
        ),
        Host::Cursor if windows => {
            Some("Cursor's sandbox runs on macOS and Linux only; the hook still applies the policy")
        }
        _ => None,
    }
}

/// The file `host`'s sandbox settings live in.
pub fn settings_path(home: &Home, host: Host) -> Result<PathBuf> {
    match host {
        Host::Codex => codex_config_path(home),
        Host::Cursor => Ok(HostConfig::for_host(home, host)?
            .settings_path
            .with_file_name("sandbox.json")),
        _ => Ok(HostConfig::for_host(home, host)?.settings_path),
    }
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
    let (changed, text, claude_rules) = if host == Host::Codex {
        let mut doc: DocumentMut = current.parse().context("parsing the settings")?;
        let changed = codex::apply(&mut doc, &plan.codex)?;
        (changed, doc.to_string(), None)
    } else if host == Host::Cursor {
        if unavailable(host).is_some() {
            return Ok(None);
        }
        let mut root = parse_json(current)?;
        let changed = cursor::apply(&mut root, &plan.cursor)?;
        (changed, serde_json::to_string_pretty(&root)? + "\n", None)
    } else {
        let mut owned = Recorded::load(home)?.claude_rules;
        let mut root = parse_json(current)?;
        let changed = if unavailable(host).is_some() {
            claude::apply_rules(&mut root, &plan.claude, &mut owned)
        } else {
            claude::apply(&mut root, &plan.claude, &mut owned)
        }?;
        (
            changed,
            serde_json::to_string_pretty(&root)? + "\n",
            Some(owned),
        )
    };
    Ok(changed.then_some(Rendered { text, claude_rules }))
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

/// The backend report for `host`.
pub fn report(host: Host, plan: &Plan) -> &Report {
    match host {
        Host::Codex => &plan.codex.report,
        Host::Cursor => &plan.cursor.report,
        _ => &plan.claude.report,
    }
}

/// Codex config files under this shell's environment that carry OpenMoat's
/// profile, which the lock pins by their owned part.
pub fn codex_profile_files(home: &Home) -> Result<Vec<PathBuf>> {
    let path = codex_config_path(home)?;
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let doc = read_toml(&path)?;
    let ours = doc.get("permissions").and_then(|p| p.get(codex::PROFILE));
    Ok(ours.map(|_| path).into_iter().collect())
}

/// Cursor's `sandbox.json` under this shell's environment when it carries
/// OpenMoat's keys, which the lock pins whole.
pub fn cursor_sandbox_files(home: &Home) -> Result<Vec<PathBuf>> {
    let path = settings_path(home, Host::Cursor)?;
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let ours = cursor::remove(&mut read_or_empty(&path)?);
    Ok(ours.then_some(path).into_iter().collect())
}

/// SHA-256 of the part of a Codex config OpenMoat owns ([`codex::owned_part`]).
pub fn codex_part_digest(path: &Path) -> Result<String> {
    Ok(crate::integrity::sha256_hex(
        codex::owned_part(&read_toml(path)?).as_bytes(),
    ))
}

/// Problems with `host`'s sandbox settings for `moat doctor` and `moat status`;
/// `None` when the host is not on this machine.
pub fn problems(
    home: &Home,
    host: Host,
    plan: &Plan,
    lock: Option<&Lock>,
) -> Result<Option<Vec<String>>> {
    let path = settings_path(home, host)?;
    if !path.parent().is_some_and(Path::is_dir) {
        return Ok(None);
    }
    let out_of_date = "differs from the policy; run `moat sandbox sync`".to_owned();
    let mut problems = if host == Host::Codex {
        let doc = read_toml(&path)?;
        let mut found = codex::weaknesses(&doc, plan.proxy_port.is_some());
        if !codex::in_sync(&doc, &plan.codex) {
            found.push(out_of_date);
        }
        if lock.is_some_and(|l| !l.pins_codex_profile(&path)) {
            found.push("not pinned by the lock; run `moat sandbox sync`".to_owned());
        }
        found
    } else if host == Host::Cursor {
        let root = read_or_empty(&path)?;
        let mut found = cursor::weaknesses(&root);
        if !cursor::in_sync(&root, &plan.cursor) {
            found.push(out_of_date);
        }
        if lock.is_some_and(|l| path.is_file() && !l.pins(&path)) {
            found.push("not pinned by the lock; run `moat sandbox sync`".to_owned());
        }
        found
    } else {
        let root = read_or_empty(&path)?;
        let mut found = claude::weaknesses(&root, plan.claude.block_reads, plan.proxy_port);
        found.extend(claude::mask::weaknesses(&root, &plan.claude));
        let owned = Recorded::load(home)?.claude_rules;
        if !claude::in_sync(&root, &plan.claude, &owned) {
            found.push(out_of_date);
        }
        found
    };
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
mod tests {
    use super::*;

    #[test]
    fn claude_code_and_cursor_on_native_windows_go_without_a_sandbox() {
        assert!(unavailable_on(Host::ClaudeCode, true).is_some_and(|n| n.contains("WSL2")));
        assert_eq!(unavailable_on(Host::Codex, true), None);
        assert_eq!(unavailable_on(Host::ClaudeCode, false), None);
        assert!(unavailable_on(Host::Cursor, true).is_some());
        assert_eq!(unavailable_on(Host::Cursor, false), None);
        assert_eq!(unavailable(Host::ClaudeCode).is_some(), cfg!(windows));
    }
}
