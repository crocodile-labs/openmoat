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
pub fn settings_path(host: Host) -> Result<PathBuf> {
    match host {
        Host::Codex => codex_config_path(),
        Host::Cursor => Ok(HostConfig::for_host(host)?
            .settings_path
            .with_file_name("sandbox.json")),
        _ => Ok(HostConfig::for_host(host)?.settings_path),
    }
}

/// Merge the plan's settings for `host` into its file, or, where the host's
/// sandbox is [`unavailable`], remove what an older version wrote (Cursor's
/// file is left alone: no version wrote it there). Returns whether the file
/// changed (or would, with `dry_run`).
pub fn write(host: Host, plan: &Plan, dry_run: bool) -> Result<bool> {
    let path = settings_path(host)?;
    let changed;
    let text = if host == Host::Codex {
        let mut doc = read_toml(&path)?;
        changed = codex::apply(&mut doc, &plan.codex)?;
        doc.to_string()
    } else if host == Host::Cursor {
        if unavailable(host).is_some() {
            return Ok(false);
        }
        let mut root = read_or_empty(&path)?;
        changed = cursor::apply(&mut root, &plan.cursor)
            .with_context(|| format!("updating {}", path.display()))?;
        serde_json::to_string_pretty(&root)? + "\n"
    } else {
        let home = Home::locate()?;
        let mut recorded = Recorded::load(&home)?;
        let mut owned = recorded.claude_rules.clone();
        let mut root = read_or_empty(&path)?;
        changed = if unavailable(host).is_some() {
            claude::apply_rules(&mut root, &plan.claude, &mut owned)
        } else {
            claude::apply(&mut root, &plan.claude, &mut owned)
        }
        .with_context(|| format!("updating {}", path.display()))?;
        if !dry_run && owned != recorded.claude_rules {
            recorded.claude_rules = owned;
            recorded.save(&home)?;
        }
        serde_json::to_string_pretty(&root)? + "\n"
    };
    if !changed {
        return Ok(false);
    }
    if dry_run {
        return Ok(true);
    }
    crate::install::back_up(&path, SANDBOX_BACKUP)?;
    write_private(&path, text.as_bytes())?;
    Ok(true)
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
pub fn codex_profile_files() -> Result<Vec<PathBuf>> {
    let path = codex_config_path()?;
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let doc = read_toml(&path)?;
    let ours = doc.get("permissions").and_then(|p| p.get(codex::PROFILE));
    Ok(ours.map(|_| path).into_iter().collect())
}

/// Cursor's `sandbox.json` under this shell's environment when it carries
/// OpenMoat's keys, which the lock pins whole.
pub fn cursor_sandbox_files() -> Result<Vec<PathBuf>> {
    let path = settings_path(Host::Cursor)?;
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
pub fn problems(host: Host, plan: &Plan, lock: Option<&Lock>) -> Result<Option<Vec<String>>> {
    let path = settings_path(host)?;
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
        let owned = Recorded::load(&Home::locate()?)?.claude_rules;
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
