//! `moat doctor`'s Standard-tier rows: each present host's sandbox settings
//! against the policy.

use std::path::Path;

use openmoat_core::Policy;
use openmoat_hosts::Host;

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
