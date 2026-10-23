//! `moat doctor`'s Standard-tier rows: each present host's sandbox settings
//! against the policy.

use std::path::Path;

use openmoat_core::Policy;
use openmoat_hosts::Host;

use super::{Area, Report};
use crate::commands::sandbox::write_report;
use crate::home::Home;
use crate::install::{HostConfig, read_or_empty};
use crate::integrity::Lock;
use crate::sandbox::backend::SandboxBackend;
use crate::sandbox::claude::mask::{self, Mask};
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
        if host_sandbox::backend(host).is_some_and(SandboxBackend::masks_secrets) {
            masks(report, home, host, policy, &plan);
        }
        if verbose {
            let _ = write_report(&mut report.out, translation);
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
    }
}

/// One row per policy secret: whether Claude Code's own broker masks it in
/// the settings on disk (#363). A secret it does not mask keeps the hook's
/// and `moat proxy`'s handling, so none of these is a problem: a missing
/// entry is already the "differs from the policy" problem above.
fn masks(report: &mut Report, home: &Home, host: Host, policy: &Policy, plan: &Plan) {
    if policy.secrets.is_empty() {
        return;
    }
    let settings = host_sandbox::settings_path(home, host).and_then(|p| read_or_empty(&p));
    let root = match settings {
        Ok(root) => root,
        Err(e) => {
            report.warn(&format!("Claude Code      secrets: {e:#}"));
            return;
        }
    };
    let states = mask::states(
        &root,
        &policy.secrets,
        &plan.claude.report,
        host_sandbox::MASK_FILES_DENIED,
    );
    for (secret, state) in states {
        let text = format!(
            "Claude Code      secret `{}` ({}): {}",
            secret.id,
            secret.host,
            state.describe()
        );
        match state {
            Mask::Active => report.line(Area::Sandbox, true, text),
            Mask::NotWritten => report.warn(&text),
            Mask::FileDenied | Mask::Skipped(_) => report.note(&text),
        }
    }
}
