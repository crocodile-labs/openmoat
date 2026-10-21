//! `moat init`: create the state directory, default policy, audit log and host hooks.

use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{Result, bail};
use openmoat_audit::Store;
use openmoat_core::{DEFAULT_POLICY, Policy};
use openmoat_hosts::Host;

use crate::cli::InitArgs;
use crate::environment::Snapshot;
use crate::exit::Code;
use crate::home::Home;
use crate::install::{HostConfig, Outcome, Recorded, dir_variable, env_config_dir};
use crate::integrity;
use crate::render::Deferred;
use crate::sandbox::{self, Plan};

mod mcp;
mod preview;
#[cfg(test)]
mod tests;
mod unattended;

pub fn run(args: &InitArgs) -> Result<Code> {
    let dry_run = args.dry_run;
    let prefix = if dry_run { "would" } else { "✔" };
    let home = Home::locate()?;
    let binary = crate::install::hook_binary()?;
    refuse_writable_binary(&home, &binary)?;
    let mut out = Deferred::default();
    // Whether a lock existed before this run; `repin` below always leaves one.
    let lock_existed = !dry_run && refuse_repin(&home, &mut out)?;
    // No person over an existing lock: what the lock trusts stays (`unattended.rs`).
    let unattended = unattended::applies(lock_existed, crate::terminal::person());
    if unattended {
        let recorded = crate::install::self_paths::recorded_binary(&home)?;
        unattended::refuse_other_binary(&recorded, &binary)?;
    }
    // Asked before anything is written, so declining everything changes nothing
    // but OpenMoat's own state directory.
    let hosts = choose_hosts(&home, args, &binary, &mut out)?;

    state(&home, dry_run, unattended, &mut out)?;
    if !dry_run {
        home.ensure_approval_files()?;
        // Recorded before the files are written: every command from here on,
        // this one included, finds each agent where this shell says it is.
        record(&home, &hosts, unattended)?;
    }
    for host in hosts.iter().copied() {
        let config = unattended::config(&home, host, unattended)?;
        let outcome = config.install(&home, &binary, dry_run)?;
        let verb = match outcome {
            Outcome::Installed => "installed",
            Outcome::Updated => "updated",
            Outcome::Unchanged => "unchanged",
        };
        let events: Vec<&str> = config.hooks.iter().map(|spec| spec.event).collect();
        writeln!(
            out,
            "{prefix} {:<16} {} ({verb}: {} → {} guard --host {})",
            host.display_name(),
            config.settings_path.display(),
            events.join(", "),
            binary.display(),
            host.id()
        )?;
    }

    sandboxes(&home, &binary, &hosts, dry_run, &mut out)?;

    if dry_run {
        writeln!(out, "would lock             {}", home.lock_path().display())?;
        if args.mcp_proxy {
            super::mcp::wrap_servers(&home, &binary, &hosts, &[], false, true, &mut out)?;
        }
        writeln!(out, "dry run: nothing was written")?;
    } else {
        let lock = integrity::repin(&home, &binary, integrity::HookPins::Adopt)?;
        writeln!(
            out,
            "✔ lock             {} ({} files pinned)",
            home.lock_path().display(),
            lock.entries.len()
        )?;
        mcp::servers(&home, &binary, args.mcp_proxy, &hosts, unattended, &mut out)?;
        if !hosts.is_empty() {
            backups(&home, &hosts, &mut out)?;
        }
        writeln!(out, "done. run `openmoat status` any time to verify.")?;
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// Which checks guard `init`'s re-pin of an existing lock.
#[derive(Debug, PartialEq, Eq)]
struct RepinChecks {
    /// Refuse when an agent is among the parent processes.
    agent: bool,
    /// Refuse when pinned files drifted.
    drift: bool,
}

/// The checks for an `init` that writes. A first install has no lock, so
/// nothing to re-pin, and stays open to scripts and the agent setting it up.
/// Over an existing lock an agent is always refused; without a terminal (a
/// script, CI, or a process detached from the agent that started it) drift
/// is refused too, while a person at a terminal re-pins over it as
/// documented, shown what drifted.
fn repin_checks(lock_exists: bool, interactive: bool) -> RepinChecks {
    RepinChecks {
        agent: lock_exists,
        drift: lock_exists && !interactive,
    }
}

/// Refuse, before anything is written, a re-pin [`repin_checks`] does not
/// allow; returns whether a lock exists. An unreadable lock counts as drift:
/// `init` at a terminal is how a person recovers from one, and without a
/// terminal it is refused like any other drift.
fn refuse_repin(home: &Home, out: &mut Deferred) -> Result<bool> {
    let lock_path = home.lock_path();
    let lock_exists = lock_path.exists();
    let checks = repin_checks(lock_exists, crate::terminal::interactive());
    let drift: Vec<String> = if lock_exists {
        integrity::Lock::load(&lock_path).map_or_else(
            |error| vec![format!("{} cannot be read: {error:#}", lock_path.display())],
            |lock| lock.verify().iter().map(ToString::to_string).collect(),
        )
    } else {
        Vec::new()
    };
    if checks.drift && !drift.is_empty() {
        bail!(
            "refusing to re-pin while the policy lock shows drift ({}) and no person is at \
             a terminal:\n  {}\nrun `openmoat doctor` to see what changed, then `openmoat doctor \
             --accept` in a terminal of your own if the changes are yours",
            integrity::INTEGRITY_RULE,
            drift.join("\n  ")
        );
    }
    if checks.agent {
        crate::terminal::refuse_agent("openmoat init")?;
    }
    if !drift.is_empty() {
        writeln!(
            out,
            "! lock drift       re-pinning over: {}",
            drift.join("; ")
        )?;
    }
    Ok(lock_exists)
}

/// Refuse, before anything is written, a binary an agent could replace; the
/// sandboxes' writable directories come from the policy `init` will apply.
fn refuse_writable_binary(home: &Home, binary: &std::path::Path) -> Result<()> {
    let policy = if home.policy_path().exists() {
        home.load_policy()
    } else {
        Ok(Policy::parse(DEFAULT_POLICY)?)
    };
    // A policy that does not lint is reported by `sandboxes`, which then
    // writes no sandbox, so there are no sandbox grants to check.
    let writable = policy
        .and_then(|p| Plan::for_binary(home, &p, binary))
        .map(|plan| plan.writable_dirs())
        .unwrap_or_default();
    crate::install::self_paths::refuse_writable(binary, &writable)
}

/// OpenMoat's own state: the directory, the default policy (kept when there is
/// one), the audit log and the search-path snapshot (kept when `unattended`).
fn state(home: &Home, dry_run: bool, unattended: bool, out: &mut Deferred) -> Result<()> {
    let prefix = if dry_run { "would" } else { "✔" };
    if !dry_run {
        home.ensure()?;
    }
    writeln!(out, "{prefix} state directory  {}", home.root().display())?;

    let policy_path = home.policy_path();
    let wrote_policy = if dry_run {
        !policy_path.exists()
    } else {
        home.ensure_policy()?
    };
    if wrote_policy {
        writeln!(
            out,
            "{prefix} policy           {} (defaults v1)",
            policy_path.display()
        )?;
    } else {
        writeln!(out, "✔ policy           {} (kept)", policy_path.display())?;
        if let Some(update) = crate::upgrade::available(home) {
            writeln!(
                out,
                "! policy update    {update}: `openmoat policy upgrade` shows them and asks"
            )?;
        }
    }

    if !dry_run {
        Store::open(&home.audit_path())?;
    }
    writeln!(
        out,
        "{prefix} audit log        {}",
        home.audit_path().display()
    )?;

    if dry_run {
        writeln!(
            out,
            "would environment      {}",
            home.environment_path().display()
        )?;
    } else if unattended && home.environment_path().is_file() {
        writeln!(
            out,
            "· environment      {} kept: no person at a terminal to record a new search path",
            home.environment_path().display()
        )?;
    } else {
        let snapshot = Snapshot::capture();
        snapshot.save(&home.environment_path())?;
        writeln!(
            out,
            "✔ environment      {} ({} dirs, {} programs pinned)",
            home.environment_path().display(),
            snapshot.path.len(),
            snapshot.programs.len()
        )?;
    }
    Ok(())
}

/// The backups `init` made of `hosts`' files, and how to undo.
fn backups(home: &Home, hosts: &[Host], out: &mut Deferred) -> Result<()> {
    let recorded = Recorded::load(home)?;
    let mut backups = Vec::new();
    for host in hosts {
        for file in host_files(&HostConfig::for_host(home, *host)?) {
            let made = crate::install::backups(&file);
            backups.extend(made.into_iter().filter(|b| recorded.owns(b)));
        }
    }
    let backups: Vec<String> = backups.iter().map(|p| p.display().to_string()).collect();
    if backups.is_empty() {
        writeln!(
            out,
            "· backups          none: the agents had no files to back up"
        )?;
    } else {
        writeln!(out, "✔ backups          {}", backups.join(", "))?;
    }
    writeln!(out, "Undo anytime: openmoat uninstall")?;
    Ok(())
}

/// The hosts to set up: `--hosts` as given; else every host found, each confirmed
/// at the terminal (all of them with `--yes` or `--dry-run`, none without a
/// terminal, so a script never changes an agent's files unasked).
fn choose_hosts(
    home: &Home,
    args: &InitArgs,
    binary: &std::path::Path,
    out: &mut Deferred,
) -> Result<Vec<Host>> {
    if let Some(explicit) = &args.hosts {
        return Ok(explicit.clone());
    }
    let mut found = Vec::new();
    for config in Host::ALL
        .into_iter()
        .filter_map(|h| HostConfig::for_init(home, h).ok())
    {
        if config.host_present() {
            found.push(config);
        } else if env_config_dir(config.host)?.is_some() {
            // The agent creates its directory on first start; say so instead of
            // leaving it out silently. The directory is not created here.
            let name = config.host.display_name();
            writeln!(
                out,
                "{name}: {} is {}, which does not exist yet; start {name} once to create \
                 it, then run openmoat init again",
                dir_variable(config.host)?.0,
                config.dir().display()
            )?;
        }
    }
    let names: Vec<&str> = found.iter().map(|c| c.host.display_name()).collect();
    if found.is_empty() {
        writeln!(
            out,
            "· agents           none found; pass --hosts to set one up"
        )?;
        return Ok(Vec::new());
    }
    if args.yes || args.dry_run {
        return Ok(found.iter().map(|c| c.host).collect());
    }
    if !crate::terminal::interactive() {
        writeln!(
            out,
            "· agents           found {}; none changed without a terminal: run `openmoat init` \
             in a terminal to choose, or `openmoat init --yes` to set up all of them",
            names.join(", ")
        )?;
        return Ok(Vec::new());
    }
    writeln!(out, "Found these agents:")?;
    for config in &found {
        let files: Vec<String> = host_files(config)
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        writeln!(
            out,
            "  {:<12} {} (changes {})",
            config.host.display_name(),
            config.dir().display(),
            files.join(", ")
        )?;
    }
    writeln!(
        out,
        "OpenMoat adds its hook and sandbox settings to each agent you accept, backing \
         up every file first; `openmoat uninstall` undoes it. Each agent's changes are shown \
         before you are asked."
    )?;
    // The sandbox settings the policy `init` keeps or installs gives each agent.
    let plan = sandbox_plan(home, binary).ok();
    let mut chosen = Vec::new();
    for config in &found {
        preview::show(home, config, binary, plan.as_ref(), out)?;
        write!(
            out,
            "Protect {} ({})? [Y/n] ",
            config.host.display_name(),
            config.dir().display()
        )?;
        out.flush()?;
        // End of input is a no: nothing is changed that a person did not accept.
        let answer = crate::terminal::read_answer()?;
        if answer.is_empty() {
            writeln!(out)?;
            continue;
        }
        if matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "" | "y" | "yes"
        ) {
            chosen.push(config.host);
        }
    }
    if chosen.is_empty() {
        writeln!(
            out,
            "· agents           none accepted; no agent's files were changed"
        )?;
    }
    Ok(chosen)
}

/// Every file `init` may change for `config`'s host: its hook file, and Codex's
/// `config.toml` beside it ([`sandbox::codex_config_path`]).
fn host_files(config: &HostConfig) -> Vec<PathBuf> {
    let mut files = vec![config.settings_path.clone()];
    if config.host == Host::Codex {
        files.push(sandbox::codex_config_beside(&config.settings_path));
    }
    if config.host == Host::Cursor {
        files.push(config.settings_path.with_file_name("sandbox.json"));
    }
    if config.host == Host::OpenClaw {
        files.push(crate::install::openclaw::plugin_path(config));
    }
    files
}

/// Record where each of `hosts` keeps its configuration, so later commands
/// find it without this shell's environment (`hosts.json`, pinned by the lock);
/// `unattended`, a recorded host keeps its record.
fn record(home: &Home, hosts: &[Host], unattended: bool) -> Result<()> {
    let mut recorded = Recorded::load(home)?;
    for host in hosts {
        let config = HostConfig::for_init(home, *host)?;
        unattended::record(&mut recorded, &config, unattended);
    }
    recorded.save(home)
}

/// The sandbox plan for the policy in place, or the default one `init` would
/// install.
fn sandbox_plan(home: &Home, binary: &std::path::Path) -> Result<Plan> {
    let policy = if home.policy_path().exists() {
        home.load_policy()?
    } else {
        Policy::parse(DEFAULT_POLICY)?
    };
    Plan::for_binary(home, &policy, binary)
}

/// Standard tier (ADR-018): each selected host's own sandbox, configured from
/// the policy. A policy that does not lint is reported, not fatal, so `init`
/// can still repair hooks; `moat sandbox sync` writes the sandboxes later.
fn sandboxes(
    home: &Home,
    binary: &std::path::Path,
    hosts: &[Host],
    dry_run: bool,
    out: &mut Deferred,
) -> Result<()> {
    let prefix = if dry_run { "would" } else { "✔" };
    let selected: Vec<Host> = sandbox::install::hosts()
        .filter(|h| hosts.contains(h))
        .collect();
    if selected.is_empty() {
        return Ok(());
    }
    let plan = match sandbox_plan(home, binary) {
        Ok(plan) => plan,
        Err(e) => {
            writeln!(out, "✗ sandbox          not written: {e:#}")?;
            return Ok(());
        }
    };
    for host in selected {
        let changed = sandbox::install::write(home, host, &plan, dry_run)?;
        if let Some(note) = sandbox::install::unavailable(host) {
            if changed {
                writeln!(
                    out,
                    "{prefix} {:<16} {}",
                    host.display_name(),
                    sandbox::install::OLD_SANDBOX_REMOVED
                )?;
            }
            writeln!(out, "· {:<16} {note}", host.display_name())?;
            continue;
        }
        let verb = if changed { "updated" } else { "unchanged" };
        let report = sandbox::install::report(host, &plan);
        writeln!(
            out,
            "{prefix} {:<16} {} (sandbox {verb}; {} stricter, {} wider than the policy: `openmoat sandbox show`)",
            host.display_name(),
            sandbox::install::settings_path(home, host)?.display(),
            report.losses.len(),
            report.allowances.len()
        )?;
    }
    Ok(())
}
