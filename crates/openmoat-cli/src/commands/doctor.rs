//! `moat doctor`: verify the installation and, from a terminal, accept changes.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use openmoat_audit::{ChainReport, Store};
use openmoat_core::Policy;
use openmoat_hosts::Host;

use crate::cli::{DoctorArgs, Format};
use crate::exit::Code;
use crate::home::Home;
use crate::install::{
    CONTINUE_CLI_WARNING, HookState, HostConfig, Recorded, dir_variable, env_config_dir, stale_hint,
};
use crate::integrity::{self, HookPinGap, HookPins, Lock};
use crate::protection;
use crate::render::Deferred;

mod json;
mod mcp;
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
        if ok {
            report.line(Area::Service, true, text);
        } else {
            report.line(Area::Service, false, text);
        }
    }
}

struct Report {
    problems: Vec<(Area, String)>,
    out: Deferred,
    /// Every row in order, for `--format json`.
    rows: Vec<json::Row>,
}

impl Report {
    fn line(&mut self, area: Area, ok: bool, text: String) {
        // `Deferred` keeps a write error for `finish`; it never returns one here.
        let _ = writeln!(self.out, "{} {text}", if ok { "✔" } else { "✗" });
        let status = if ok {
            json::Status::Ok
        } else {
            json::Status::Problem
        };
        self.rows.push(json::Row::new(status, Some(area), &text));
        if !ok {
            self.problems.push((area, text));
        }
    }

    fn note(&mut self, text: &str) {
        let _ = writeln!(self.out, "· {text}");
        self.rows
            .push(json::Row::new(json::Status::Note, None, text));
    }

    /// A row that needs attention without being a problem: the exit code stays 0.
    fn warn(&mut self, text: &str) {
        let _ = writeln!(self.out, "! {text}");
        self.rows
            .push(json::Row::new(json::Status::Warning, None, text));
    }
}

pub fn run(args: &DoctorArgs) -> Result<Code> {
    let home = Home::locate()?;
    let binary = crate::install::hook_binary()?;
    let as_json = args.format == Format::Json;
    let mut report = Report {
        problems: Vec::new(),
        out: if as_json {
            Deferred::quiet()
        } else {
            Deferred::default()
        },
        rows: Vec::new(),
    };

    report.line(
        Area::State,
        home.exists(),
        format!("state directory  {}", home.root().display()),
    );
    let policy = policies(&mut report, &home);
    if let Some(update) = crate::upgrade::available(&home) {
        report.warn(&format!(
            "policy update    {update}: `moat policy upgrade` shows them and asks"
        ));
    }
    let lock = load_lock(&mut report, &home);
    let drift = lock
        .as_ref()
        .map(|lock| verify_lock(&mut report, lock, &binary))
        .unwrap_or_default();
    environment(&mut report, &home);
    let hook_files = hooks(&mut report, &home, &binary)?;
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
    let codex = HostConfig::for_host(&home, Host::Codex)?.state(&binary) == HookState::Installed;
    let tiocsti = warnings::tiocsti(codex, warnings::legacy_tiocsti().as_deref());
    let hangs = warnings::hangs(&home, crate::time::now_ms());
    let linux = cfg!(target_os = "linux");
    let state = policy
        .as_ref()
        .and_then(|policy| warnings::state_in_grant(&home, policy, linux));
    for warning in [tiocsti, hangs, state].into_iter().flatten() {
        report.warn(&warning);
    }
    for agent in protection::report(&home, &binary)? {
        if let Some(summary) = agent.summary() {
            report.note(&format!("{:<16} protection: {summary}", agent.name));
            report.note(&format!("{:<16} known gaps: {}", agent.name, agent.gaps));
        }
    }
    match Store::open_read_only(&home.audit_path()).and_then(|store| store.verify_chain()) {
        Ok(chain) => audit_line(&mut report, &chain),
        Err(e) => report.line(Area::Audit, false, format!("audit log        {e}")),
    }
    if let Some(last) = crate::anchor::Last::load(&home) {
        report.note(&format!(
            "audit anchor     last made {} (event {}) in {}",
            crate::time::timestamp(last.anchored_ms),
            last.event,
            last.to
        ));
    }
    if args.accept {
        let intact = drift.is_empty() && lock.is_some();
        accept(&mut report, &home, &binary, policy.is_some(), intact)?;
    }
    if as_json {
        return json::finish(&report.rows, report.problems.len());
    }
    finish(report)
}

/// The policy line and, in a project with one, the repository policy line;
/// the policy when it lints.
fn policies(report: &mut Report, home: &Home) -> Option<Policy> {
    let policy = match home.load_policy() {
        Ok(policy) => {
            let (deny, allow, ask) = policy.rule_count();
            report.line(
                Area::Policy,
                true,
                format!("policy           lints ({deny} deny, {allow} allow, {ask} ask)"),
            );
            Some(policy)
        }
        Err(e) => {
            report.line(Area::Policy, false, format!("policy           {e:#}"));
            None
        }
    };
    match crate::repo::summary(home) {
        Ok(Some(line)) => report.note(&format!("repo policy      {line}")),
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
                "lock             missing; run `moat init`".to_owned(),
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
    if lock.binary != binary.to_string_lossy() {
        report.line(
            Area::Binary,
            false,
            format!(
                "binary           lock expects {}, running {}; run `moat init`",
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
            format!("environment      {e:#}; run `moat init`"),
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
                "hook file        {} is not pinned by the lock; run `moat init` to pin it",
                path.display()
            ),
        );
    }
    for path in gap.elsewhere {
        report.note(&format!(
            "hook file        {} is pinned but not this shell's (CLAUDE_CONFIG_DIR, CODEX_HOME or CURSOR_CONFIG_DIR differ); re-pinning keeps it",
            path.display()
        ));
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
    crate::terminal::refuse_agent("moat doctor --accept")?;
    if !crate::terminal::interactive() {
        bail!(
            "`moat doctor --accept` must be run by a person in a terminal, not from a hook or script"
        );
    }
    if !policy_lints {
        bail!(
            "refusing to pin a policy that does not lint; fix it, then run `moat doctor --accept` again"
        );
    }
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
fn finish(mut report: Report) -> Result<Code> {
    if report.problems.is_empty() {
        writeln!(report.out, "healthy")?;
        report.out.finish()?;
        return Ok(Code::Ok);
    }
    writeln!(
        report.out,
        "{} problem(s). `moat init` re-installs and re-pins; `moat doctor --accept` accepts edits you made yourself.",
        report.problems.len()
    )?;
    report.out.finish()?;
    Ok(Code::Usage)
}

/// One line per host's hook, then the Continue CLI warning; returns the
/// installed hook files.
fn hooks(report: &mut Report, home: &Home, binary: &Path) -> Result<Vec<PathBuf>> {
    let recorded = Recorded::load(home)?;
    let mut hook_files = Vec::new();
    for host in Host::ALL {
        let config = HostConfig::for_host(home, host)?;
        let name = host.display_name();
        // Every command follows the record; a variable naming another directory
        // is reported rather than silently ignored or followed.
        if let Some(set_up) = config.openclaw_location() {
            if recorded.dir(host).is_some()
                && let Some(line) = crate::install::openclaw::location::env_disagrees(&set_up)?
            {
                report.line(Area::Hook, false, format!("{name:<16} {line}"));
            }
        } else if let (Some(env), Some(dir)) = (env_config_dir(host)?, recorded.dir(host))
            && env != dir
        {
            let (var, _) = dir_variable(host)?;
            report.line(
                Area::Hook,
                false,
                format!(
                    "{name:<16} {var} is {}, but `moat init` set it up in {}, which moat uses; \
                     run `moat init` with {var} set to set up that directory instead",
                    env.display(),
                    dir.display()
                ),
            );
        }
        let state = config.state(binary);
        if recorded.skipped(host) && config.host_present() && matches!(state, HookState::Missing) {
            report.note(&format!(
                "{name:<16} not set up; `moat init --hosts {}` adds it",
                host.id()
            ));
            continue;
        }
        match state {
            HookState::Installed => {
                hook_files.push(config.settings_path.clone());
                report.line(
                    Area::Hook,
                    true,
                    format!(
                        "{name:<16} hook installed  {}",
                        config.settings_path.display()
                    ),
                );
                if config.runs_calls_when_hook_fails() {
                    report.warn(&format!(
                        "{name:<16} runs a tool call when its hook fails to start, crashes or \
                         times out: no `claude` 2.1.295 or later on PATH, so the hook has no \
                         `onFailure: \"block\"`; update Claude Code, then run `moat init`"
                    ));
                }
            }
            HookState::Missing if !config.host_present() => {
                report.note(&format!("{name:<16} host not found"));
            }
            HookState::Missing => {
                report.line(
                    Area::Hook,
                    false,
                    format!("{name:<16} hook missing; run `moat init`"),
                );
            }
            HookState::Stale { command } => {
                report.line(
                    Area::Hook,
                    false,
                    format!("{name:<16} {}", stale_hint(&command)),
                );
            }
            HookState::Unreadable(e) => {
                report.line(Area::Hook, false, format!("{name:<16} {e}"));
            }
        }
    }
    if let Some(found) = crate::install::continue_cli()? {
        let name = Host::Continue.display_name();
        report.note(&format!(
            "{name:<16} {CONTINUE_CLI_WARNING}  {}",
            found.display()
        ));
    }
    Ok(hook_files)
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
    if let Some(head) = &chain.head {
        report.note(&format!(
            "audit log        head {head}; record it elsewhere (`moat audit anchor`), then `moat audit verify --against` it later"
        ));
    }
    if chain.unchained > 0 {
        report.note(&format!(
            "audit log        {} events written before the hash chain existed are not covered",
            chain.unchained
        ));
    }
}
