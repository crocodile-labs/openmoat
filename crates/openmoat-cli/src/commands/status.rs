//! `moat status`: is the kernel installed, current and active? The short form
//! of `openmoat doctor`: what needs the person, one line per agent, OpenMoat's
//! own state and the latest decisions.

use std::fs;
use std::io;
use std::path::Path;

use anyhow::Result;
use openmoat_audit::Store;
use openmoat_hosts::Host;

use crate::approvals::{self, GRANT_TTL_MS, Grants};
use crate::cli::{Format, StatusArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::integrity::{HookPinGap, Lock};
use crate::report::{Attention, Mark, Printer, Row};
use crate::sandbox::Plan;
use crate::{protection, render, time};

mod agents;

/// How many of the newest audit events `status` lists.
const RECENT_EVENTS: usize = 5;

/// The rows `status` prints, by section.
#[derive(Default)]
struct Shown {
    attention: Attention,
    /// Under the agent rows: agents OpenMoat finds but cannot hook.
    agents: Vec<Row>,
    openmoat: Vec<Row>,
}

impl Shown {
    /// A problem (`✗`) or a warning (`!`) in `Needs your attention`.
    fn needs(&mut self, mark: Mark, label: &str, text: impl Into<String>) {
        self.attention.push(Row::new(mark, label, text));
    }

    fn state(&mut self, mark: Mark, label: &str, text: impl Into<String>) {
        self.openmoat.push(Row::new(mark, label, text));
    }
}

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
            "hook_warnings": hook_warnings(&home, &binary)?,
            "policy_update": update,
            "lock_drift": drift,
            "mcp_changes": mcp_changes(&home, &binary).unwrap_or_default(),
            "mcp_outside": mcp_outside(&home, &binary),
            "project_settings": crate::project_settings::warnings_here(&home)
                .into_iter()
                .map(|warning| warning.text)
                .collect::<Vec<_>>(),
            "other_hooks": crate::project_settings::other_hooks::warnings_here(&home)
                .into_iter()
                .map(|warning| warning.text)
                .collect::<Vec<_>>(),
        }))?;
        return Ok(Code::Ok);
    }
    let mut shown = Shown::default();
    let mut healthy = policies(&mut shown, &home)?;
    if let Some(update) = &update {
        let row = Row::new(Mark::Attention, "Policy", format!("{update} to review"))
            .fix("openmoat policy upgrade");
        shown.attention.push(row);
    }
    healthy &= lock(&mut shown, &home, &binary)?;
    healthy &= mcp_line(&mut shown, &home, &binary);
    // Warnings that leave `healthy` alone: servers that start outside what
    // OpenMoat checks are the person's choice to wrap (ADR-049).
    for line in mcp_outside(&home, &binary) {
        shown.needs(Mark::Attention, "MCP servers", line);
    }
    healthy &= approvals(&mut shown, &home);
    healthy &= agents::hooks(&mut shown, &home, &binary)?;
    // A warning that leaves `healthy` alone: OpenMoat is installed as it should
    // be, and only the person can judge a project's own settings.
    for warning in crate::project_settings::warnings_here(&home) {
        let text = format!("project settings {}", warning.text);
        shown.needs(Mark::Attention, warning.host.display_name(), text);
    }
    for warning in crate::project_settings::other_hooks::warnings_here(&home) {
        let text = format!("other hook {}", warning.text);
        shown.needs(Mark::Attention, warning.host.display_name(), text);
    }
    if let Ok(policy) = home.load_policy() {
        healthy &= agents::sandboxes(&mut shown, &home, &Plan::new(&home, &policy)?, &binary);
    }
    let audit = audit(&mut shown, &home)?;
    healthy &= audit.is_some();

    let table = crate::report::agent_table(
        &protection::report(&home, &binary)?,
        &shown.attention,
        false,
    );
    let mut out = io::stdout().lock();
    let mut printer = Printer::stdout(&mut out);
    printer.title("status")?;
    printer.attention(&shown.attention)?;
    let mut table = table;
    table.rows.append(&mut shown.agents);
    printer.agents(&table)?;
    printer.heading("OpenMoat")?;
    printer.rows(&shown.openmoat)?;
    if let Some(recent) = audit.filter(|r| !r.is_empty()) {
        printer.heading("Latest decisions")?;
        drop(printer);
        render::event_table(&recent)?;
    }
    Ok(if healthy { Code::Ok } else { Code::Usage })
}

/// Advisory trust diagnostics, separate from protection levels and exit codes.
fn hook_warnings(home: &Home, binary: &Path) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    for host in Host::ALL {
        let config = crate::install::HostConfig::for_host(home, host)?;
        if config.set_up(binary)
            && let Some(warning) = config.trust_warning()
        {
            warnings.push(format!("{}: {warning}", host.display_name()));
        }
    }
    Ok(warnings)
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

/// One line per MCP server that starts outside what OpenMoat checks
/// (`mcp/outside.rs`), or why they cannot be listed.
fn mcp_outside(home: &Home, binary: &Path) -> Vec<String> {
    let cwd = std::env::current_dir().ok();
    match crate::mcp::outside::report(home, binary, cwd.as_deref()) {
        Ok(found) => found
            .iter()
            .map(crate::mcp::outside::Outside::describe)
            .collect(),
        Err(e) => vec![format!(
            "cannot list the servers that start outside OpenMoat: {e:#}"
        )],
    }
}

/// The MCP line; `false` when something waits for `moat mcp accept`.
fn mcp_line(shown: &mut Shown, home: &Home, binary: &Path) -> bool {
    match mcp_changes(home, binary) {
        Ok(lines) if lines.is_empty() => {
            let text = "nothing waits for `openmoat mcp accept`";
            shown.state(Mark::Ok, "MCP servers", text);
            true
        }
        Ok(lines) => {
            for line in lines {
                let row = Row::new(Mark::Broken, "MCP servers", line)
                    .fix("`openmoat mcp accept` shows it and asks");
                shown.attention.push(row);
            }
            false
        }
        Err(error) => {
            shown.needs(Mark::Broken, "MCP servers", format!("{error:#}"));
            false
        }
    }
}

/// The policy line and, in a project with one, the repository policy line;
/// `false` on any problem.
fn policies(shown: &mut Shown, home: &Home) -> Result<bool> {
    let mut healthy = true;
    let policy_path = home.policy_path();
    match home.load_policy() {
        Ok(policy) => {
            let bytes = fs::read(&policy_path)?;
            let digest = crate::integrity::sha256_hex(&bytes);
            let (deny, allow, review) = policy.rule_count();
            let text = format!(
                "{} · {deny} deny · {allow} allow · {review} review rules · sha256:{}",
                policy_path.display(),
                digest.get(..12).unwrap_or(&digest)
            );
            shown.state(Mark::Ok, "Policy", text);
        }
        Err(error) => {
            healthy = false;
            shown.needs(Mark::Broken, "Policy", format!("{error:#}"));
        }
    }
    match crate::repo::summary(home) {
        Ok(Some(line)) => shown.state(Mark::Info, "Repo policy", line),
        Ok(None) => {}
        Err(error) => {
            healthy = false;
            let text = format!("{error:#}; every call in this project is denied");
            shown.needs(Mark::Broken, "Repo policy", text);
        }
    }
    Ok(healthy)
}

/// The lock lines: drift, and hook files the lock does not pin; `false` on any
/// problem.
fn lock(shown: &mut Shown, home: &Home, binary: &Path) -> Result<bool> {
    let lock_path = home.lock_path();
    let lock = match Lock::load(&lock_path) {
        Ok(lock) => lock,
        Err(_) if !lock_path.exists() => {
            let row = Row::new(Mark::Broken, "Lock", "missing").fix("openmoat init");
            shown.attention.push(row);
            return Ok(false);
        }
        Err(error) => {
            shown.needs(Mark::Broken, "Lock", format!("{error:#}"));
            return Ok(false);
        }
    };
    let mut healthy = true;
    let drift = lock.verify();
    if drift.is_empty() {
        let text = format!("{} files pinned, intact", lock.entries.len());
        shown.state(Mark::Ok, "Lock", text);
    } else {
        healthy = false;
        for d in drift {
            let row = Row::new(Mark::Broken, "Lock", d.to_string()).fix("openmoat doctor");
            shown.attention.push(row);
        }
    }
    let installed = crate::integrity::installed_hook_files(home, binary)?;
    let gap = HookPinGap::new(&lock, home, &installed);
    for path in gap.unpinned {
        healthy = false;
        let row = Row::new(
            Mark::Broken,
            "Lock",
            format!("{} is not pinned", path.display()),
        )
        .fix("openmoat init to pin it");
        shown.attention.push(row);
    }
    for path in gap.elsewhere {
        let text = format!(
            "{} is pinned but not this shell's hook file ({})",
            path.display(),
            HookPinGap::moved_by()
        );
        shown.state(Mark::Info, "Lock", text);
    }
    Ok(healthy)
}

/// The session grants line; `false` when the grants file is unreadable.
fn approvals(shown: &mut Shown, home: &Home) -> bool {
    let grants = match Grants::load(&home.grants_path()) {
        Ok(grants) => grants,
        Err(error) => {
            shown.needs(Mark::Broken, "Approvals", format!("{error:#}"));
            return false;
        }
    };
    let now = time::now_ms();
    let ages: Vec<i64> = grants.active(now).map(|g| now - g.granted_at_ms).collect();
    let text = match ages.iter().max() {
        Some(oldest) => format!(
            "{} active session grant(s), oldest {} old (each expires after {})",
            ages.len(),
            time::duration(*oldest),
            time::duration(GRANT_TTL_MS)
        ),
        None => "no active session grants".to_owned(),
    };
    shown.state(Mark::Info, "Approvals", text);
    // Written before grants named their project: they apply nowhere now.
    for grant in grants.active(now).filter(|g| g.unbound()) {
        let text = format!(
            "{} session {}: {} needs approving again: it names no project, so it no longer \
             applies (`openmoat allow --last` after its next review)",
            grant.host,
            grant.session_id,
            approvals::describe(&grant.action)
        );
        shown.needs(Mark::Attention, "Approvals", text);
    }
    true
}

/// The audit log line; the most recent events, `None` when the log is missing.
fn audit(shown: &mut Shown, home: &Home) -> Result<Option<Vec<openmoat_audit::Event>>> {
    let audit_path = home.audit_path();
    if !audit_path.is_file() {
        let row = Row::new(Mark::Broken, "Audit log", "missing").fix("openmoat init");
        shown.attention.push(row);
        return Ok(None);
    }
    let store = Store::open_read_only(&audit_path)?;
    let text = format!("{} · {} events", audit_path.display(), store.count()?);
    shown.state(Mark::Ok, "Audit log", text);
    Ok(Some(store.recent(RECENT_EVENTS)?))
}
