//! `moat doctor`: verify the installation and, from a terminal, accept changes.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use openmoat_audit::{ChainReport, Store};
use openmoat_core::Policy;

use crate::cli::{DoctorArgs, Format};
use crate::exit::Code;
use crate::home::Home;
use crate::integrity::{self, HookPinGap, HookPins, Lock};
use crate::protection;
use crate::render::Deferred;
use crate::report::{Mark, Row};
use human::Place;
use rows::Report;

mod bundle;
mod hooks;
mod human;
mod json;
mod mcp;
mod rows;
mod sandboxes;
mod warnings;

/// What a check is about, so accepting changes clears exactly the problems a
/// re-pin fixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Area {
    State,
    Policy,
    Lock,
    Binary,
    Environment,
    Hook,
    Sandbox,
    Audit,
    Service,
    Mcp,
}

/// The `moat doctor` line for the proxy user service (`moat proxy install`,
/// #272). A missing service is silent (opt-in); a drift-blocked or
/// crash-looping service is a problem; a running one is a check.
fn service(report: &mut Report, home: &Home) {
    if let Some((ok, text)) = super::proxy::service_line(home) {
        report.line(Area::Service, ok, text);
    }
}

pub fn run(args: &DoctorArgs) -> Result<Code> {
    let home = Home::locate()?;
    let binary = crate::install::hook_binary()?;
    let as_json = args.format == Format::Json;
    let mut report = Report::new(if as_json || args.bundle.is_some() {
        Deferred::quiet()
    } else {
        Deferred::default()
    });

    report.line(
        Area::State,
        home.exists(),
        format!("state directory  {}", home.root().display()),
    );
    let policy = policies(&mut report, &home);
    if let Some(update) = crate::upgrade::available(&home) {
        report.warn_as(
            &format!("policy update    {update}: `openmoat policy upgrade` shows them and asks"),
            Row::new(Mark::Attention, "Policy", format!("{update} to review"))
                .fix("openmoat policy upgrade"),
        );
    }
    let lock = load_lock(&mut report, &home);
    let drift = lock
        .as_ref()
        .map(|lock| verify_lock(&mut report, lock, &binary))
        .unwrap_or_default();
    environment(&mut report, &home);
    let hook_files = hooks::hooks(&mut report, &home, &binary)?;
    if let Some(lock) = &lock {
        hook_pins(&mut report, lock, &home, &hook_files);
        mcp::lines(&mut report, &home, lock, &binary);
    }
    if let Some(policy) = &policy {
        sandboxes::sandboxes(
            &mut report,
            &home,
            policy,
            lock.as_ref(),
            &binary,
            args.verbose,
        );
    }
    service(&mut report, &home);
    let open = warnings::tiocsti_open(&home, &binary)?;
    let tiocsti = warnings::tiocsti(open, warnings::legacy_tiocsti().as_deref());
    let hangs = warnings::hangs(&home, crate::time::now_ms());
    let linux = cfg!(target_os = "linux");
    let state = policy
        .as_ref()
        .and_then(|policy| warnings::state_in_grant(&home, policy, linux));
    let macos = warnings::old_macos(crate::os_version::macos().as_deref());
    let network = super::run::port_only_network();
    let lightweight = super::run::tier::doctor_warning(super::run::bubblewrap());
    let alias = warnings::alias_hooks(&home, &binary);
    for warning in [tiocsti, hangs, state, macos, network, lightweight]
        .into_iter()
        .flatten()
        .chain(alias)
    {
        report.warn(&warning);
    }
    report.note(warnings::RENAMED);
    // Loaded when a session starts here, where no `ConfigChange` fires.
    for warning in crate::project_settings::warnings_here(&home) {
        let name = warning.host.display_name();
        report.warn(&format!("{name:<16} project settings {}", warning.text));
    }
    for warning in crate::project_settings::other_hooks::warnings_here(&home) {
        let name = warning.host.display_name();
        report.warn(&format!("{name:<16} other hook {}", warning.text));
    }
    // Run by the agent's own git when a session starts, before any hook.
    for warning in crate::project_settings::git_config::warnings_here() {
        report.warn(&format!("{:<16} git config {warning}", "Repository"));
    }
    protections(&mut report, &home, &binary)?;
    match Store::open_read_only(&home.audit_path()).and_then(|store| store.verify_chain()) {
        Ok(chain) => audit_line(&mut report, &chain),
        Err(e) => report.line(Area::Audit, false, format!("audit log        {e}")),
    }
    if let Some(last) = crate::anchor::Last::load(&home) {
        let text = format!(
            "audit anchor     last made {} (event {}) in {}",
            crate::time::timestamp(last.anchored_ms),
            last.event,
            last.to
        );
        report.note_at(&text, Place::OpenMoat);
    }
    if !as_json && args.bundle.is_none() {
        let agents = std::mem::take(&mut report.agents);
        human::sections(&mut report, &agents, args.verbose);
    }
    if args.accept {
        let intact = drift.is_empty() && lock.is_some();
        accept(&mut report, &home, &binary, policy.is_some(), intact)?;
    }
    if let Some(path) = &args.bundle {
        return bundle::write(&home, &binary, &report.rows, path, args.bundle_events);
    }
    if as_json {
        return json::finish(&report.rows, report.problems.len());
    }
    finish(report, args.verbose)
}

/// Each agent's protection level, its limit and its known gaps; the text
/// output shows the level in its `Agents` section, the rest with `--verbose`.
fn protections(report: &mut Report, home: &Home, binary: &Path) -> Result<()> {
    let agents = protection::report(home, binary)?;
    for agent in &agents {
        if let Some(line) = crate::install::trust_note::protection_line(agent) {
            report.note(&line);
            if let Some(limit) = agent.limit {
                // Shown under the agent's row (`report::agent_table`).
                let text = format!("{:<16} limit: {limit}", agent.name);
                report.warn_at(&text, Place::Details);
            }
            report.note(&format!("{:<16} known gaps: {}", agent.name, agent.gaps));
        }
    }
    report.agents = agents;
    Ok(())
}

/// The policy line and, in a project with one, the repository policy line;
/// the policy when it lints.
fn policies(report: &mut Report, home: &Home) -> Option<Policy> {
    let policy = match home.load_policy() {
        Ok(policy) => {
            let (deny, allow, review) = policy.rule_count();
            report.line_as(
                Area::Policy,
                true,
                format!("policy           lints ({deny} deny, {allow} allow, {review} review)"),
                Place::OpenMoat,
                Row::new(
                    Mark::Ok,
                    "Policy",
                    format!("{deny} deny · {allow} allow · {review} review rules"),
                ),
            );
            Some(policy)
        }
        Err(e) => {
            report.line(Area::Policy, false, format!("policy           {e:#}"));
            None
        }
    };
    match crate::repo::summary(home) {
        Ok(Some(line)) => report.note_at(&format!("repo policy      {line}"), Place::OpenMoat),
        Ok(None) => {}
        Err(e) => report.line(
            Area::Policy,
            false,
            format!("repo policy      {e:#}; every call in this project is denied"),
        ),
    }
    policy
}

/// The lock, or the line saying why there is none.
fn load_lock(report: &mut Report, home: &Home) -> Option<Lock> {
    let lock_path = home.lock_path();
    match Lock::load(&lock_path) {
        Ok(lock) => Some(lock),
        Err(_) if !lock_path.exists() => {
            report.line(
                Area::Lock,
                false,
                "lock             missing; run `openmoat init`".to_owned(),
            );
            None
        }
        Err(e) => {
            report.line(Area::Lock, false, format!("lock             {e:#}"));
            None
        }
    }
}

/// The lock lines: what drifted, and whether the lock pins this binary;
/// returns the drift.
fn verify_lock(report: &mut Report, lock: &Lock, binary: &Path) -> Vec<integrity::Drift> {
    let drift = lock.verify();
    if drift.is_empty() {
        report.line(
            Area::Lock,
            true,
            format!(
                "lock             {} files pinned, all intact",
                lock.entries.len()
            ),
        );
    }
    for d in &drift {
        report.line(Area::Lock, false, format!("lock             {d}"));
    }
    if let Some(warning) = warnings::alias_lock(&lock.binary, binary) {
        report.warn(&warning);
    } else if lock.binary != binary.to_string_lossy() {
        report.line(
            Area::Binary,
            false,
            format!(
                "binary           lock expects {}, running {}; run `openmoat init`",
                lock.binary,
                binary.display()
            ),
        );
    }
    drift
}

/// The search-path snapshot line.
fn environment(report: &mut Report, home: &Home) {
    match crate::environment::Snapshot::load(&home.environment_path()) {
        Ok(snapshot) => report.line(
            Area::Environment,
            true,
            format!(
                "environment      {} dirs, {} programs pinned",
                snapshot.path.len(),
                snapshot.programs.len()
            ),
        ),
        Err(e) => report.line(
            Area::Environment,
            false,
            format!("environment      {e:#}; run `openmoat init`"),
        ),
    }
}

/// Installed hook files the lock does not pin, and pinned ones this shell
/// does not use.
fn hook_pins(report: &mut Report, lock: &Lock, home: &Home, hook_files: &[PathBuf]) {
    let gap = HookPinGap::new(lock, home, hook_files);
    for path in gap.unpinned {
        report.line(
            Area::Hook,
            false,
            format!(
                "hook file        {} is not pinned by the lock; run `openmoat init` to pin it",
                path.display()
            ),
        );
    }
    for path in gap.elsewhere {
        let (path, moved) = (path.display(), HookPinGap::moved_by());
        report.note_at(
            &format!(
                "hook file        {path} is pinned but not this shell's ({moved}); re-pinning keeps it"
            ),
            Place::OpenMoat,
        );
    }
}

/// `--accept`: re-pin from a terminal when the policy lints and the lock is
/// not intact, clearing the problems a re-pin fixes.
fn accept(
    report: &mut Report,
    home: &Home,
    binary: &Path,
    policy_lints: bool,
    intact: bool,
) -> Result<()> {
    crate::terminal::refuse_agent("openmoat doctor --accept")?;
    if !crate::terminal::interactive() {
        bail!(
            "`openmoat doctor --accept` must be run by a person in a terminal, not from a hook or script"
        );
    }
    if !policy_lints {
        bail!(
            "refusing to pin a policy that does not lint; fix it, then run `openmoat doctor --accept` again"
        );
    }
    writeln!(report.out)?;
    if intact {
        // MCP definitions are not files of the lock: accepted on their own, after
        // a person has seen each change.
        if home.lock_path().is_file() {
            mcp::accept(report, home, binary)?;
        }
        writeln!(report.out, "nothing else to accept: lock is intact")?;
        return Ok(());
    }
    let lock = integrity::repin(home, binary, HookPins::Keep)?;
    writeln!(
        report.out,
        "✔ lock re-pinned for {} files",
        lock.entries.len()
    )?;
    report
        .problems
        .retain(|(area, _)| !matches!(area, Area::Lock | Area::Binary));
    mcp::accept(report, home, binary)
}

/// The closing line, the output and the exit code.
fn finish(mut report: Report, verbose: bool) -> Result<Code> {
    human::footer(&mut report, verbose);
    let healthy = report.problems.is_empty();
    report.out.finish()?;
    Ok(if healthy { Code::Ok } else { Code::Usage })
}

/// The audit log line: event count and whether the hash chain holds.
fn audit_line(report: &mut Report, chain: &ChainReport) {
    if let Some(broken) = &chain.broken {
        report.line(
            Area::Audit,
            false,
            format!(
                "audit log        hash chain broken at event {}: {}; keep the file as evidence",
                broken.id,
                broken.kind.describe()
            ),
        );
        return;
    }
    report.line(
        Area::Audit,
        true,
        format!(
            "audit log        {} events, hash chain intact",
            chain.events
        ),
    );
    // Shown without --verbose: the head is what a person records elsewhere.
    if let Some(head) = &chain.head {
        report.note_at(
            &format!(
                "audit log        head {head}; record it elsewhere (`openmoat audit anchor`), then `openmoat audit verify --against` it later"
            ),
            Place::OpenMoat,
        );
    }
    if chain.unchained > 0 {
        report.note_at(
            &format!(
                "audit log        {} events written before the hash chain existed are not covered",
                chain.unchained
            ),
            Place::OpenMoat,
        );
    }
}
