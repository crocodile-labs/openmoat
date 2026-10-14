//! `moat doctor`'s Standard-tier rows: each present host's sandbox settings
//! against the policy.

use std::io::Write as _;
use std::path::Path;

use openmoat_core::Policy;

use super::{Area, Report};
use crate::commands::sandbox::write_report;
use crate::home::Home;
use crate::install::HostConfig;
use crate::integrity::Lock;
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
    for host in host_sandbox::HOSTS
        .into_iter()
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
        if verbose {
            let _ = write_report(&mut report.out, translation);
        }
    }
    if let Some(port) = plan.proxy_port.filter(|_| present) {
        // A warning, not a problem: a stopped proxy fails closed.
        let (ok, text) = crate::commands::proxy::listening_line(port);
        let _ = writeln!(
            report.out,
            "{} moat proxy       {text}",
            if ok { "✔" } else { "!" }
        );
    }
}
