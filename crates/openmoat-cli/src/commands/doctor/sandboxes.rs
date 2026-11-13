//! `moat doctor`'s Standard-tier rows: each present host's sandbox settings
//! against the policy.

use std::path::Path;

use anyhow::{Context as _, Result};
use serde_json::{Map, Value};

use openmoat_core::Policy;
use openmoat_hosts::{Host, Platform, WindowsSandboxLevel};

use super::human::Place;
use super::{Area, Report};
use crate::commands::sandbox::write_report;
use crate::home::Home;
use crate::install::{HostConfig, read_or_empty};
use crate::integrity::Lock;
use crate::report::{Mark, Row};
use crate::sandbox::backend::{MaskLevel, SandboxBackend};
use crate::sandbox::{Plan, install as host_sandbox};

/// The Standard tier: each present host's sandbox settings against the policy,
/// then how many places the translation loses or widens (each one with `verbose`).
pub(super) fn sandboxes(
    report: &mut Report,
    home: &Home,
    policy: &Policy,
    lock: Option<&Lock>,
    binary: &Path,
    verbose: bool,
) {
    let plan = match Plan::new(home, policy) {
        Ok(plan) => plan,
        Err(e) => {
            report.line(Area::Sandbox, false, format!("sandbox          {e:#}"));
            return;
        }
    };
    let mut present = false;
    let mut with_sandbox = Vec::new();
    for host in host_sandbox::hosts()
        .filter(|h| HostConfig::for_host(home, *h).is_ok_and(|c| c.set_up(binary)))
    {
        let name = host.display_name();
        let problems = host_sandbox::problems(home, host, &plan, lock);
        if let (Ok(Some(_)), Some(note)) = (&problems, host_sandbox::unavailable(host)) {
            report.note(&format!("{name:<16} {note}"));
            continue;
        }
        present |= !matches!(problems, Ok(None));
        if !matches!(problems, Ok(None)) {
            with_sandbox.push(host);
        }
        let translation = host_sandbox::report(host, &plan);
        windows_mode(report, home, host);
        match problems {
            Ok(None) => continue,
            Ok(Some(problems)) if problems.is_empty() => {
                let details = if verbose {
                    ""
                } else {
                    "; --verbose for details"
                };
                report.line(
                    Area::Sandbox,
                    true,
                    format!(
                        "{name:<16} sandbox matches the policy ({} stricter, {} wider{details})",
                        translation.losses.len(),
                        translation.allowances.len()
                    ),
                );
            }
            Ok(Some(problems)) => {
                for problem in problems {
                    report.line(
                        Area::Sandbox,
                        false,
                        format!("{name:<16} sandbox: {problem}"),
                    );
                }
            }
            Err(e) => report.line(Area::Sandbox, false, format!("{name:<16} sandbox: {e:#}")),
        }
        if let Some(backend) = host_sandbox::backend(host).filter(|b| b.masks_secrets()) {
            masks(report, home, (host, backend), policy, &plan);
        }
        if verbose {
            let mut text = Vec::new();
            let _ = write_report(&mut text, translation);
            for line in String::from_utf8_lossy(&text).lines() {
                report.human(Place::Details, Row::new(Mark::Info, name, line.trim()));
            }
        }
    }
    if let Some(port) = plan.proxy_port.filter(|_| present) {
        // A warning, not a problem: a stopped proxy fails closed.
        let (ok, text) = crate::commands::proxy::listening_line(port);
        let line = format!("openmoat proxy   {text}");
        if ok {
            report.line(Area::Service, true, line);
        } else {
            report.warn(&line);
        }
        let lines =
            crate::commands::proxy::session_lines(&with_sandbox, plan.serve_without_credential);
        for (ok, label, text) in lines {
            let line = format!("{label:<16} {text}");
            if ok {
                report.line(Area::Service, true, line);
            } else {
                report.warn(&line);
            }
        }
    }
}

/// One row per policy secret: whether the host's own broker masks it in the
/// settings on disk (#363). A secret it does not mask keeps the hook's and
/// `moat proxy`'s handling, so none of these is a problem: a missing entry is
/// already the "differs from the policy" problem above.
fn masks(
    report: &mut Report,
    home: &Home,
    (host, backend): (Host, &dyn SandboxBackend),
    policy: &Policy,
    plan: &Plan,
) {
    if policy.secrets.is_empty() {
        return;
    }
    let name = host.display_name();
    let settings = host_sandbox::settings_path(home, host).and_then(|p| read_or_empty(&p));
    let root = match settings {
        Ok(root) => root,
        Err(e) => {
            report.warn(&format!("{name:<16} secrets: {e:#}"));
            return;
        }
    };
    for mask in backend.secret_masks(&root, &policy.secrets, plan) {
        let text = format!(
            "{name:<16} secret `{}` ({}): {}",
            mask.secret.id, mask.secret.host, mask.text
        );
        match mask.level {
            MaskLevel::Masked => report.line(Area::Sandbox, true, text),
            MaskLevel::NotWritten => report.warn(&text),
            MaskLevel::Unmasked => report.note(&text),
        }
    }
}

/// On Windows, which mode of its own sandbox the host's settings select, and
/// whether that mode holds OpenMoat's read denies (Codex, ADR-083).
fn windows_mode(report: &mut Report, home: &Home, host: Host) {
    let Some(reader) = host.spec().sandbox.as_ref().and_then(|s| s.windows_modes) else {
        return;
    };
    if crate::os_version::platform() != Platform::Windows {
        return;
    }
    let name = host.display_name();
    let root = host_sandbox::settings_path(home, host).and_then(|p| read_settings(&p));
    let mode = match root {
        Ok(root) => reader.mode(&root),
        Err(e) => {
            report.warn(&format!("{name:<16} Windows sandbox mode not read: {e:#}"));
            return;
        }
    };
    let text = format!("{name:<16} Windows sandbox: {}", mode.text);
    match mode.level {
        WindowsSandboxLevel::Holds => report.line(Area::Sandbox, true, text),
        WindowsSandboxLevel::ReadsOpen => report.warn(&text),
        _ => report.note(&text),
    }
}

/// A host's settings file as one object: TOML read as JSON (`*.toml`), JSON
/// otherwise; empty when the file is missing or blank.
fn read_settings(path: &Path) -> Result<Map<String, Value>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let value = if path.extension().is_some_and(|e| e == "toml") {
        let doc: toml_edit::DocumentMut = text
            .parse()
            .with_context(|| format!("parsing {}", path.display()))?;
        crate::mcp::servers::toml_to_json(doc.as_item())
    } else if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?
    };
    Ok(match value {
        Value::Object(map) => map,
        _ => Map::new(),
    })
}
