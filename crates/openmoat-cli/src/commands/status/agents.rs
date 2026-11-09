//! `moat status`'s checks of each agent: its hook and its sandbox. A fine
//! agent shows only as its row in the `Agents` section (`report::agent_table`);
//! what is wrong, or needs a look, goes to `Needs your attention`.

use std::path::Path;

use anyhow::Result;
use openmoat_hosts::Host;

use super::Shown;
use crate::home::Home;
use crate::install::{HookState, HostConfig, Recorded};
use crate::integrity::Lock;
use crate::report::{Mark, Row};
use crate::sandbox::{Plan, install as host_sandbox};

/// Each host's hook, then the agents OpenMoat finds but cannot hook; `false`
/// on any problem.
pub(super) fn hooks(shown: &mut Shown, home: &Home, binary: &Path) -> Result<bool> {
    let recorded = Recorded::load(home).unwrap_or_default();
    let mut healthy = true;
    crate::install::host_version::prefetch_present(home);
    for host in Host::ALL {
        let config = HostConfig::for_host(home, host)?;
        let name = host.display_name();
        // A version with a published advisory, a flaw no hook sees: a warning,
        // which does not make the status unhealthy.
        let advisories = if config.host_present() {
            crate::install::host_version::advisories(host)
        } else {
            Vec::new()
        };
        // A version that does not load OpenMoat's hook (OpenCode before
        // 1.3.4), whatever the hook file says.
        let unsupported = config
            .host_present()
            .then(|| crate::install::host_version::unsupported(host))
            .flatten();
        let state = config.state(binary);
        let installed = state == HookState::Installed && unsupported.is_none();
        let problem = match (state, unsupported) {
            (_, Some(why)) => Some(Row::new(
                Mark::Broken,
                name,
                format!("not protected: {why}"),
            )),
            (HookState::Installed, None) => None,
            (HookState::Missing, None) if recorded.skipped(host) || !config.host_present() => None,
            (HookState::Missing, None) => {
                Some(Row::new(Mark::Broken, name, "hook missing").fix("openmoat init"))
            }
            (HookState::Stale { command }, None) => Some(Row::new(
                Mark::Broken,
                name,
                crate::install::stale_hint(&command),
            )),
            (
                HookState::Unreadable(error)
                | HookState::Unapproved(error)
                | HookState::FailsOpen(error)
                | HookState::TurnedOff(error),
                None,
            ) => Some(Row::new(Mark::Broken, name, error)),
        };
        if let Some(row) = problem {
            healthy = false;
            shown.attention.push(row);
        }
        for advisory in advisories {
            shown.needs(Mark::Attention, name, advisory);
        }
        // The copies editor extensions bundle, which read the same hook file.
        for (fine, line) in crate::install::host_version::bundled_lines(host) {
            if fine {
                shown.agents.push(Row::new(Mark::Info, name, line));
            } else {
                shown.needs(Mark::Attention, name, line);
            }
        }
        if installed && let Some(warning) = config.trust_warning() {
            let row = Row::new(Mark::Attention, name, warning);
            let row = match crate::install::trust_note::step(host) {
                Some(step) => row.fix(step),
                None => row,
            };
            shown.attention.push(row);
        }
        // Whether the host loaded the plugin (ADR-042): a warning, like the
        // protection level it changes, that leaves `healthy` alone.
        if let Some(loaded) = installed
            .then(|| crate::heartbeat::check(home, &config))
            .flatten()
        {
            let (mark, text) = crate::heartbeat::line(name, &loaded);
            match mark {
                crate::heartbeat::Mark::Note => shown.agents.push(Row::new(Mark::Info, name, text)),
                crate::heartbeat::Mark::Warning => shown.needs(Mark::Attention, name, text),
            }
        }
    }
    for (host, found) in crate::install::detected()? {
        let text = format!("found at {}; {}", found.display(), host.spec().gaps);
        shown
            .agents
            .push(Row::new(Mark::Attention, host.display_name(), text));
    }
    Ok(healthy)
}

/// Each set-up host's sandbox against the policy, and the proxy its sandbox
/// sends traffic to; `false` on any problem.
pub(super) fn sandboxes(shown: &mut Shown, home: &Home, plan: &Plan, binary: &Path) -> bool {
    let lock = Lock::load(&home.lock_path()).ok();
    let mut healthy = true;
    let mut with_sandbox = Vec::new();
    for host in host_sandbox::hosts()
        .filter(|h| HostConfig::for_host(home, *h).is_ok_and(|c| c.set_up(binary)))
    {
        let name = host.display_name();
        let problems = host_sandbox::problems(home, host, plan, lock.as_ref());
        if let (Ok(Some(_)), Some(_)) = (&problems, host_sandbox::unavailable(host)) {
            // Its agent row says so.
            continue;
        }
        if !matches!(problems, Ok(None)) {
            with_sandbox.push(host);
        }
        match problems {
            Ok(None) => {}
            Ok(Some(problems)) if problems.is_empty() => {}
            Ok(Some(problems)) => {
                healthy = false;
                for problem in problems {
                    shown.needs(Mark::Broken, name, format!("sandbox: {problem}"));
                }
            }
            Err(error) => {
                healthy = false;
                shown.needs(Mark::Broken, name, format!("sandbox: {error:#}"));
            }
        }
    }
    if let Some(port) = plan.proxy_port.filter(|_| !with_sandbox.is_empty()) {
        // A warning that leaves `healthy` alone: a stopped proxy fails closed.
        let (ok, text) = crate::commands::proxy::listening_line(port);
        proxy_row(shown, ok, "openmoat proxy", text);
        // Warnings too: a request without a credential fails closed.
        let lines =
            crate::commands::proxy::session_lines(&with_sandbox, plan.serve_without_credential);
        for (ok, label, text) in lines {
            proxy_row(shown, ok, label, text);
        }
    }
    for (ok, text) in crate::commands::proxy::service_lines(home) {
        // `service          <state>` and `service file     <finding>`, as
        // `doctor` prints them.
        let (label, rest) = match text.strip_prefix("service file") {
            Some(rest) => ("Service file", rest),
            None => ("Service", text.strip_prefix("service").unwrap_or(&text)),
        };
        proxy_row(shown, ok, label, rest.trim().to_owned());
        healthy &= ok;
    }
    healthy
}

/// A proxy row: in the `OpenMoat` section when fine, else a warning.
fn proxy_row(shown: &mut Shown, ok: bool, label: &str, text: String) {
    if ok {
        shown.state(Mark::Ok, label, text);
    } else {
        shown.needs(Mark::Attention, label, text);
    }
}
