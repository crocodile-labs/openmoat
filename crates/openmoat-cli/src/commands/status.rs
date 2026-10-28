//! `moat status`: is the kernel installed, current and active?

use std::fs;
use std::io::{self, Write as _};
use std::path::Path;

use anyhow::Result;
use openmoat_audit::Store;
use openmoat_hosts::Host;

use crate::approvals::{self, GRANT_TTL_MS, Grants};
use crate::cli::{Format, StatusArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::install::{HookState, HostConfig, Recorded};
use crate::integrity::{self, HookPinGap, Lock};
use crate::sandbox::{Plan, install as host_sandbox};
use crate::{protection, render, time};

/// How many of the newest audit events `status` lists.
const RECENT_EVENTS: usize = 5;

pub fn run(args: &StatusArgs) -> Result<Code> {
    let home = Home::locate()?;
    let binary = crate::install::hook_binary()?;
    // A newer default policy's changes reach a person only through `moat policy
    // upgrade`; say so wherever the installation is looked at.
    let update = crate::upgrade::available(&home);
    if args.format == Format::Json {
        let drift: Vec<String> = Lock::load(&home.lock_path())
            .map(|lock| lock.verify().iter().map(ToString::to_string).collect())
            .unwrap_or_default();
        render::json(&serde_json::json!({
            "agents": protection::report(&home, &binary)?,
            "plugins": crate::heartbeat::all(&home, &binary),
            "policy_update": update,
            "lock_drift": drift,
            "mcp_changes": mcp_changes(&home, &binary).unwrap_or_default(),
            "project_settings": crate::project_settings::warnings_here(&home)
                .into_iter()
                .map(|warning| warning.text)
                .collect::<Vec<_>>(),
        }))?;
        return Ok(Code::Ok);
    }
    let mut out = io::stdout().lock();

    writeln!(out, "state directory  {}", home.root().display())?;
    let mut healthy = policies(&mut out, &home)?;
    if let Some(update) = &update {
        writeln!(
            out,
            "policy update    · {update}: `openmoat policy upgrade` shows them and asks"
        )?;
    }
    healthy &= lock(&mut out, &home, &binary)?;
    healthy &= mcp_line(&mut out, &home, &binary)?;
    healthy &= approvals(&mut out, &home)?;
    let recorded = Recorded::load(&home).unwrap_or_default();
    healthy &= hooks(&mut out, &home, &binary, &recorded)?;
    // A warning that leaves `healthy` alone: OpenMoat is installed as it should
    // be, and only the person can judge a project's own settings.
    for warning in crate::project_settings::warnings_here(&home) {
        let name = warning.host.display_name();
        writeln!(out, "{name:<16} ! project settings {}", warning.text)?;
    }
    if let Ok(policy) = home.load_policy() {
        healthy &= sandboxes(&mut out, &home, &Plan::new(&home, &policy)?, &binary)?;
    }
    // Derived from the hook and sandbox lines above, so it leaves `healthy` alone.
    protection_lines(&mut out, &home, &binary)?;
    healthy &= audit(&mut out, &home)?;

    Ok(if healthy { Code::Ok } else { Code::Usage })
}

/// One line per MCP server definition or held tool that waits for `moat mcp
/// accept` (ADR-026); empty when there is no lock, or nothing waits.
fn mcp_changes(home: &Home, binary: &Path) -> Result<Vec<String>> {
    let path = home.lock_path();
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let lock = Lock::load(&path)?;
    let cwd = std::env::current_dir().ok();
    let found = crate::mcp::review(
        home,
        &lock,
        &crate::mcp::set_up_hosts(home, binary),
        cwd.as_deref(),
    )?;
    let mut lines = Vec::new();
    if found.pinned {
        lines.extend(
            found
                .changes
                .iter()
                .map(|c| c.describe().lines().next().unwrap_or_default().to_owned()),
        );
    }
    lines.extend(
        found
            .unreadable
            .iter()
            .map(|(p, why)| format!("{} cannot be read: {why}", p.display())),
    );
    for (_, pins) in crate::mcp::tools::all(home)? {
        if !pins.held.is_empty() {
            lines.push(format!(
                "MCP server `{}` lists {}",
                pins.server,
                pins.held_summary()
            ));
        }
    }
    Ok(lines)
}

/// The MCP line; `false` when something waits for `moat mcp accept`.
fn mcp_line(out: &mut impl io::Write, home: &Home, binary: &Path) -> Result<bool> {
    match mcp_changes(home, binary) {
        Ok(lines) if lines.is_empty() => {
            writeln!(
                out,
                "mcp servers      ✔ nothing waits for `openmoat mcp accept`"
            )?;
            Ok(true)
        }
        Ok(lines) => {
            for line in lines {
                writeln!(
                    out,
                    "mcp servers      ✗ {line}; `openmoat mcp accept` shows it and asks"
                )?;
            }
            Ok(false)
        }
        Err(error) => {
            writeln!(out, "mcp servers      ✗ {error:#}")?;
            Ok(false)
        }
    }
}

/// The policy line and, in a project with one, the repository policy line;
/// `false` on any problem.
fn policies(out: &mut impl io::Write, home: &Home) -> Result<bool> {
    let mut healthy = true;
    let policy_path = home.policy_path();
    match home.load_policy() {
        Ok(policy) => {
            let bytes = fs::read(&policy_path)?;
            let digest = crate::integrity::sha256_hex(&bytes);
            let (deny, allow, ask) = policy.rule_count();
            writeln!(
                out,
                "policy           {}  sha256:{digest}  ({deny} deny, {allow} allow, {ask} ask)",
                policy_path.display()
            )?;
        }
        Err(error) => {
            healthy = false;
            writeln!(out, "policy           ✗ {error:#}")?;
        }
    }
    match crate::repo::summary(home) {
        Ok(Some(line)) => writeln!(out, "repo policy      {line}")?,
        Ok(None) => {}
        Err(error) => {
            healthy = false;
            writeln!(
                out,
                "repo policy      ✗ {error:#}; every call in this project is denied"
            )?;
        }
    }
    Ok(healthy)
}

/// The lock lines: drift, and hook files the lock does not pin; `false` on any
/// problem.
fn lock(out: &mut impl io::Write, home: &Home, binary: &Path) -> Result<bool> {
    let lock_path = home.lock_path();
    let lock = match Lock::load(&lock_path) {
        Ok(lock) => lock,
        Err(_) if !lock_path.exists() => {
            writeln!(out, "lock             ✗ missing (run `openmoat init`)")?;
            return Ok(false);
        }
        Err(error) => {
            writeln!(out, "lock             ✗ {error:#}")?;
            return Ok(false);
        }
    };
    let mut healthy = true;
    let drift = lock.verify();
    if drift.is_empty() {
        writeln!(
            out,
            "lock             ✔ {} files pinned, intact",
            lock.entries.len()
        )?;
    } else {
        healthy = false;
        for d in drift {
            writeln!(out, "lock             ✗ {d} (run `openmoat doctor`)")?;
        }
    }
    let installed = integrity::installed_hook_files(home, binary)?;
    let gap = HookPinGap::new(&lock, home, &installed);
    for path in gap.unpinned {
        healthy = false;
        writeln!(
            out,
            "lock             ✗ {} is not pinned (run `openmoat init` to pin it)",
            path.display()
        )?;
    }
    for path in gap.elsewhere {
        writeln!(
            out,
            "lock             · {} is pinned but not this shell's hook file ({})",
            path.display(),
            HookPinGap::moved_by()
        )?;
    }
    Ok(healthy)
}

/// The session grants line; `false` when the grants file is unreadable.
fn approvals(out: &mut impl io::Write, home: &Home) -> Result<bool> {
    let grants = match Grants::load(&home.grants_path()) {
        Ok(grants) => grants,
        Err(error) => {
            writeln!(out, "approvals        ✗ {error:#}")?;
            return Ok(false);
        }
    };
    let now = time::now_ms();
    let ages: Vec<i64> = grants.active(now).map(|g| now - g.granted_at_ms).collect();
    match ages.iter().max() {
        Some(oldest) => writeln!(
            out,
            "approvals        {} active session grant(s), oldest {} old (each expires after {})",
            ages.len(),
            time::duration(*oldest),
            time::duration(GRANT_TTL_MS)
        )?,
        None => writeln!(out, "approvals        no active session grants")?,
    }
    // Written before grants named their project: they apply nowhere now.
    for grant in grants.active(now).filter(|g| g.unbound()) {
        render::line(
            out,
            &format!(
                "approvals        ! {} session {}: {} needs approving again: it names no \
                 project, so it no longer applies (`openmoat allow --last` after its next ask)",
                grant.host,
                grant.session_id,
                approvals::describe(&grant.action)
            ),
        )?;
    }
    Ok(true)
}

/// One line per host's hook, then the Continue CLI warning; `false` on any
/// problem.
fn hooks(
    out: &mut impl io::Write,
    home: &Home,
    binary: &Path,
    recorded: &Recorded,
) -> Result<bool> {
    let mut healthy = true;
    // Agents with no folder on this machine share one line at the end.
    let mut not_found = Vec::new();
    crate::install::host_version::prefetch_present(home);
    for host in Host::ALL {
        let config = HostConfig::for_host(home, host)?;
        // A version with a published advisory, a flaw no hook sees: a warning
        // under the host's line, which does not make the status unhealthy.
        let advisory = config
            .host_present()
            .then(|| crate::install::host_version::advisory(host))
            .flatten();
        // A version that does not load OpenMoat's hook (OpenCode before
        // 1.3.4), whatever the hook file says.
        let unsupported = config
            .host_present()
            .then(|| crate::install::host_version::unsupported(host))
            .flatten();
        let state = config.state(binary);
        let installed = state == HookState::Installed && unsupported.is_none();
        let line = match (state, unsupported) {
            (_, Some(why)) => {
                healthy = false;
                format!("✗ not protected: {why}")
            }
            // The hook a version runs OpenMoat through, where versions differ
            // (OpenCode 1's and 2's).
            (HookState::Installed, None) => match crate::install::host_version::hook_api(host) {
                Some(through) => format!("✔ installed ({through})"),
                None => "✔ installed".to_owned(),
            },
            (HookState::Missing, None) if recorded.skipped(host) && config.host_present() => {
                format!(
                    "· not set up (`openmoat init --hosts {}` adds it)",
                    host.id()
                )
            }
            (HookState::Missing, None) if !config.host_present() => {
                not_found.push(host.display_name());
                continue;
            }
            (HookState::Missing, None) => {
                healthy = false;
                "✗ hook missing (run `openmoat init`)".to_owned()
            }
            (HookState::Stale { command }, None) => {
                healthy = false;
                format!("✗ {}", crate::install::stale_hint(&command))
            }
            (
                HookState::Unreadable(error)
                | HookState::Unapproved(error)
                | HookState::FailsOpen(error),
                None,
            ) => {
                healthy = false;
                format!("✗ {error}")
            }
        };
        writeln!(
            out,
            "{:<16} {line}  {}",
            host.display_name(),
            config.settings_path.display()
        )?;
        if let Some(advisory) = advisory {
            writeln!(out, "{:<16} ! {advisory}", host.display_name())?;
        }
        // Whether the host loaded the plugin (ADR-042): a warning, like the
        // protection line it changes, that leaves `healthy` alone.
        if let Some(loaded) = installed
            .then(|| crate::heartbeat::check(home, &config))
            .flatten()
        {
            let (mark, text) = crate::heartbeat::line(host.display_name(), &loaded);
            let mark = match mark {
                crate::heartbeat::Mark::Note => "·",
                crate::heartbeat::Mark::Warning => "!",
            };
            render::line(out, &format!("{:<16} {mark} {text}", host.display_name()))?;
        }
    }
    if !not_found.is_empty() {
        writeln!(out, "{:<16} · {}", "not found", not_found.join(", "))?;
    }
    for (host, found) in crate::install::detected()? {
        writeln!(
            out,
            "{:<16} · {}  {}",
            host.display_name(),
            host.spec().gaps,
            found.display()
        )?;
    }
    Ok(healthy)
}

/// Each agent's protection level and known gaps.
fn protection_lines(out: &mut impl io::Write, home: &Home, binary: &Path) -> Result<()> {
    for agent in protection::report(home, binary)? {
        if let Some(summary) = agent.summary() {
            let mark = match agent.level {
                protection::Level::HookAndOsSandbox => "✔",
                protection::Level::HookOnly => "!",
                _ => "✗",
            };
            writeln!(out, "{:<16} {mark} protection: {summary}", agent.name)?;
            writeln!(out, "{:<16} · known gaps: {}", agent.name, agent.gaps)?;
        }
    }
    Ok(())
}

/// The audit log line and the most recent events; `false` when the log is
/// missing.
fn audit(out: &mut impl io::Write, home: &Home) -> Result<bool> {
    let audit_path = home.audit_path();
    if !audit_path.is_file() {
        writeln!(out, "audit log        ✗ missing (run `openmoat init`)")?;
        return Ok(false);
    }
    let store = Store::open_read_only(&audit_path)?;
    writeln!(
        out,
        "audit log        {}  ({} events)",
        audit_path.display(),
        store.count()?
    )?;
    let recent = store.recent(RECENT_EVENTS)?;
    if !recent.is_empty() {
        writeln!(out)?;
        render::event_table(&recent)?;
    }
    Ok(true)
}

/// One line per present host's sandbox (Standard tier); `false` on any problem.
fn sandboxes(out: &mut impl io::Write, home: &Home, plan: &Plan, binary: &Path) -> Result<bool> {
    let lock = Lock::load(&home.lock_path()).ok();
    let mut healthy = true;
    let mut present = false;
    for host in host_sandbox::hosts()
        .filter(|h| HostConfig::for_host(home, *h).is_ok_and(|c| c.set_up(binary)))
    {
        let name = host.display_name();
        let problems = host_sandbox::problems(home, host, plan, lock.as_ref());
        if let (Ok(Some(_)), Some(note)) = (&problems, host_sandbox::unavailable(host)) {
            writeln!(out, "{name:<16} · {note}")?;
            continue;
        }
        present |= !matches!(problems, Ok(None));
        match problems {
            Ok(None) => {}
            Ok(Some(problems)) if problems.is_empty() => {
                let report = host_sandbox::report(host, plan);
                writeln!(
                    out,
                    "{name:<16} ✔ sandbox matches the policy ({} stricter, {} wider: `openmoat sandbox show`)",
                    report.losses.len(),
                    report.allowances.len()
                )?;
            }
            Ok(Some(problems)) => {
                healthy = false;
                for problem in problems {
                    writeln!(out, "{name:<16} ✗ sandbox: {problem}")?;
                }
            }
            Err(error) => {
                healthy = false;
                writeln!(out, "{name:<16} ✗ sandbox: {error:#}")?;
            }
        }
    }
    if let Some(port) = plan.proxy_port.filter(|_| present) {
        // A warning that leaves `healthy` alone: a stopped proxy fails closed.
        let (ok, text) = super::proxy::listening_line(port);
        writeln!(
            out,
            "openmoat proxy   {} {text}",
            if ok { "✔" } else { "!" }
        )?;
    }
    let home = Home::locate()?;
    if let Some((ok, text)) = super::proxy::service_line(&home) {
        writeln!(
            out,
            "openmoat proxy   {} {text}",
            if ok { "✔" } else { "!" }
        )?;
        healthy &= ok;
    }
    Ok(healthy)
}
