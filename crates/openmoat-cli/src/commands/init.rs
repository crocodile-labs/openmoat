//! `moat init`: create the state directory, default policy, audit log and host hooks.
//!
//! What a person sees: a line per agent found with what it would get and the
//! question (`ask.rs`), then the agents protected, the steps left and how to
//! undo (`summary.rs`). Each file written, the backups and the lock are shown
//! with `--verbose` (and in a dry run).

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use openmoat_audit::Store;
use openmoat_core::{DEFAULT_POLICY, Policy};
use openmoat_hosts::Host;

use crate::cli::InitArgs;
use crate::environment::Snapshot;
use crate::exit::Code;
use crate::home::Home;
use crate::install::{HookLayout, HostConfig, Outcome, Recorded, dir_variable, env_config_dir};
use crate::integrity;
use crate::render::Deferred;
use crate::report::Style;
use crate::sandbox::{self, Plan};

mod ask;
mod mcp;
mod preview;
mod summary;
#[cfg(test)]
mod tests;
mod unattended;

pub fn run(args: &InitArgs) -> Result<Code> {
    let dry_run = args.dry_run;
    // A dry run is a list of what would be written: every line of it shows.
    let verbose = args.verbose || dry_run;
    let home = Home::locate()?;
    let binary = crate::install::hook_binary()?;
    refuse_writable_binary(&home, &binary)?;
    let snapshot = search_path(&home)?;
    let mut out = Deferred::default();
    // Each file written, the backups and the lock: shown with `--verbose`.
    let mut detail = if verbose {
        Deferred::default()
    } else {
        Deferred::quiet()
    };
    let title = if dry_run {
        "what `openmoat init` would change (dry run)"
    } else {
        "protecting the agents on this machine"
    };
    writeln!(
        out,
        "{}\n",
        Style::detect().bold(&format!("OpenMoat {} · {title}", crate::VERSION))
    )?;
    if snapshot.is_none() {
        writeln!(
            out,
            "! environment      {} kept: this shell's PATH finds none of the programs \
             OpenMoat pins; run `openmoat init` from a normal shell to record a new one\n",
            home.environment_path().display()
        )?;
    }
    // Whether a lock existed before this run; `repin` below always leaves one.
    let lock_existed = !dry_run && refuse_repin(&home, &mut out)?;
    // No person over an existing lock: what the lock trusts stays (`unattended.rs`).
    // A person may run a binary the lock does not record yet: moving the hooks
    // to it is what `init` is for.
    let unattended =
        unattended::applies(lock_existed, crate::terminal::person_for("openmoat init"));
    if unattended {
        let recorded = crate::install::self_paths::recorded_binary(&home)?;
        unattended::refuse_other_binary(&recorded, &binary)?;
    }
    // Asked before anything is written, so declining everything changes nothing
    // but OpenMoat's own state directory.
    let hosts = choose_hosts(&home, args, &binary, &mut out)?;

    let mut steps = summary::Steps {
        update: state(&home, dry_run, unattended, snapshot.as_ref(), &mut detail)?,
        ..summary::Steps::default()
    };
    if !dry_run {
        home.ensure_approval_files()?;
        // Recorded before the files are written: every command from here on,
        // this one included, finds each agent where this shell says it is.
        record(&home, &hosts, unattended)?;
    }
    let mut files = Writers {
        out: &mut out,
        detail: &mut detail,
    };
    for host in hosts.iter().copied() {
        install(
            &home, &binary, host, unattended, dry_run, &mut steps, &mut files,
        )?;
    }
    steps.changed |= sandboxes(&home, &binary, &hosts, dry_run, &mut files)?;

    if dry_run {
        let detail = &mut *files.detail;
        writeln!(
            detail,
            "would lock             {}",
            home.lock_path().display()
        )?;
        if args.mcp.mcp_proxy {
            let sandbox = args.mcp.sandbox();
            super::mcp::wrap_servers(&home, &binary, &hosts, &[], sandbox, true, detail)?;
        }
        writeln!(files.out, "dry run: nothing was written")?;
    } else {
        let lock = integrity::repin(&home, &binary, integrity::HookPins::Adopt)?;
        writeln!(
            files.detail,
            "✔ lock             {} ({} files pinned)",
            home.lock_path().display(),
            lock.entries.len()
        )?;
        let wrap = mcp::Wrap::of(args, unattended);
        mcp::servers(&home, &binary, wrap, &hosts, unattended, &mut files)?;
        let backups = if hosts.is_empty() {
            0
        } else {
            backups(&home, &hosts, files.detail)?
        };
        summary::write(&home, &binary, &hosts, &steps, backups, verbose, files.out)?;
    }
    detail.finish()?;
    out.finish()?;
    Ok(Code::Ok)
}

/// What `init` prints: what every run shows, and the lines `--verbose` adds.
struct Writers<'a> {
    out: &'a mut Deferred,
    detail: &'a mut Deferred,
}

/// Install `host`'s hook, noting the steps it leaves to the person.
fn install(
    home: &Home,
    binary: &Path,
    host: Host,
    unattended: bool,
    dry_run: bool,
    steps: &mut summary::Steps,
    files: &mut Writers<'_>,
) -> Result<()> {
    let prefix = if dry_run { "would" } else { "✔" };
    let config = unattended::config(home, host, unattended)?;
    let replaced = match config.layout {
        HookLayout::Owned(file) | HookLayout::Script(file) => {
            crate::install::owned::persons_file(&config, file)
        }
        HookLayout::Entries(_) | HookLayout::Plugin(_) | HookLayout::Yaml(_) => None,
    };
    let outcome = config.install(home, binary, dry_run)?;
    let verb = match outcome {
        Outcome::Installed => "installed",
        Outcome::Updated => "updated",
        Outcome::Unchanged => "unchanged",
    };
    steps.changed |= outcome != Outcome::Unchanged;
    let events: Vec<&str> = config.hooks.iter().map(|spec| spec.event).collect();
    writeln!(
        files.detail,
        "{prefix} {:<16} {} ({verb}: {} → {}{})",
        host.display_name(),
        config.settings_path.display(),
        events.join(", "),
        binary.display(),
        config.guard(binary).shell_args(host.id())
    )?;
    if let Some(backup) = replaced.filter(|_| outcome != Outcome::Unchanged) {
        let verb = if dry_run { "would move" } else { "moved" };
        writeln!(
            files.out,
            "! {:<16} {verb} your own hook {} to {}: {} runs one file there, so yours does \
             not run while OpenMoat is installed; `openmoat uninstall` puts it back",
            host.display_name(),
            config.settings_path.display(),
            backup.display(),
            host.display_name()
        )?;
    }
    // The agent's own record of trusted hooks: after a change, or while it
    // does not trust the hook yet.
    let trust = crate::install::trust_note::after_install(host, outcome).or_else(|| {
        config
            .trust_warning()
            .and_then(|_| crate::install::trust_note::step(host))
    });
    if let Some(note) = trust {
        writeln!(
            files.detail,
            "{prefix} {:<16} next: {note}",
            host.display_name()
        )?;
        steps.trust.push((host.display_name(), note));
    }
    Ok(())
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
/// one), the audit log and the search-path snapshot `snapshot` (the recorded
/// one kept when `unattended` or when [`search_path`] found nothing); the
/// update a kept policy can take from this release's default.
fn state(
    home: &Home,
    dry_run: bool,
    unattended: bool,
    snapshot: Option<&Snapshot>,
    out: &mut Deferred,
) -> Result<Option<String>> {
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
    let mut update = None;
    if wrote_policy {
        writeln!(
            out,
            "{prefix} policy           {} (defaults v1)",
            policy_path.display()
        )?;
    } else {
        writeln!(out, "✔ policy           {} (kept)", policy_path.display())?;
        update = crate::upgrade::available(home);
        if let Some(update) = &update {
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
    } else if let Some(snapshot) = snapshot {
        snapshot.save(&home.environment_path())?;
        writeln!(
            out,
            "✔ environment      {} ({} dirs, {} programs pinned)",
            home.environment_path().display(),
            snapshot.path.len(),
            snapshot.programs.len()
        )?;
    } else {
        writeln!(
            out,
            "· environment      {} kept",
            home.environment_path().display()
        )?;
    }
    Ok(update)
}

/// This shell's search path, as `init` records it; `None` when it finds none
/// of [`PINNED_PROGRAMS`](crate::environment::PINNED_PROGRAMS) (an empty or
/// broken `PATH`, a service's bare environment) and a snapshot is recorded
/// already, which is then kept. Without one it is refused: a snapshot that
/// pins nothing would check no program the guard resolves, and `init` would
/// say it succeeded.
fn search_path(home: &Home) -> Result<Option<Snapshot>> {
    let snapshot = Snapshot::capture();
    if !snapshot.programs.is_empty() {
        return Ok(Some(snapshot));
    }
    if home.environment_path().is_file() {
        return Ok(None);
    }
    bail!(
        "this shell's PATH finds none of the programs OpenMoat pins (sh, git, curl, …), so \
         there is no search path to record and nothing was changed; run `openmoat init` from a \
         normal shell"
    )
}

/// The backups `init` made of `hosts`' files, and how to undo; how many.
fn backups(home: &Home, hosts: &[Host], out: &mut Deferred) -> Result<usize> {
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
    Ok(backups.len())
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
        return supported(explicit.iter().copied(), out);
    }
    let mut found = Vec::new();
    for config in Host::ALL
        .into_iter()
        .filter_map(|h| HostConfig::for_init(home, h).ok())
    {
        if config.host_present() {
            found.push(config);
        } else if env_config_dir(config.host)?.is_some()
            && crate::install::location::custom(config.host)
                .is_none_or(openmoat_hosts::Locate::variables_are_the_hosts)
        {
            // The agent creates its directory on first start; say so instead of
            // leaving it out silently. The directory is not created here.
            let name = config.host.display_name();
            writeln!(
                out,
                "· {name}: {} is {}, which does not exist yet; start {name} once to create \
                 it, then run openmoat init again",
                dir_variable(config.host)?.0,
                config.dir().display()
            )?;
        }
    }
    let takes_hook = supported(found.iter().map(|c| c.host), out)?;
    found.retain(|c| takes_hook.contains(&c.host));
    let names: Vec<&str> = found.iter().map(|c| c.host.display_name()).collect();
    if found.is_empty() {
        writeln!(out, "· No agents found; pass --hosts to set one up")?;
        return Ok(Vec::new());
    }
    if args.yes || args.dry_run {
        return Ok(found.iter().map(|c| c.host).collect());
    }
    if !crate::terminal::interactive() {
        writeln!(
            out,
            "! OpenMoat found {}; none changed without a terminal: run `openmoat init` \
             in a terminal to choose, or `openmoat init --yes` to set up all of them",
            names.join(", ")
        )?;
        return Ok(Vec::new());
    }
    // The sandbox settings the policy `init` keeps or installs gives each agent.
    let plan = sandbox_plan(home, binary).ok();
    let asking = ask::Asking {
        plan: plan.as_ref(),
        verbose: args.verbose,
        every_agent: args.mcp.mcp_proxy,
    };
    let chosen = ask::ask(home, &found, binary, &asking, out)?;
    if chosen.is_empty() {
        writeln!(out, "· No agent accepted; no agent's files were changed")?;
    }
    Ok(chosen)
}

/// `hosts` but those whose version on the search path does not take OpenMoat's
/// hook (OpenCode before 1.3.4), each named with why it is not set up: a hook it does not
/// load would be pinned and reported as protecting nothing.
fn supported(hosts: impl Iterator<Item = Host>, out: &mut Deferred) -> Result<Vec<Host>> {
    let mut kept = Vec::new();
    for host in hosts {
        match crate::install::host_version::unsupported(host) {
            Some(why) => writeln!(out, "· {:<16} not set up: {why}", host.display_name())?,
            None => kept.push(host),
        }
    }
    Ok(kept)
}

/// Every file `init` may change for `config`'s host: its hook file, its
/// sandbox file beside it when that is another file (Codex's `config.toml`,
/// Cursor's `sandbox.json`), and its other hook files (OpenClaw's plugin).
fn host_files(config: &HostConfig) -> Vec<PathBuf> {
    let mut files = vec![config.settings_path.clone()];
    let spec = config.host.spec();
    if let (Some(sandbox), Some(install)) = (&spec.sandbox, &spec.install)
        && sandbox.file != install.config_file
    {
        files.push(config.settings_path.with_file_name(sandbox.file));
    }
    files.extend(config.extra_files());
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
/// Whether a sandbox changed.
fn sandboxes(
    home: &Home,
    binary: &std::path::Path,
    hosts: &[Host],
    dry_run: bool,
    files: &mut Writers<'_>,
) -> Result<bool> {
    let prefix = if dry_run { "would" } else { "✔" };
    let selected: Vec<Host> = sandbox::install::hosts()
        .filter(|h| hosts.contains(h))
        .collect();
    if selected.is_empty() {
        return Ok(false);
    }
    let plan = match sandbox_plan(home, binary) {
        Ok(plan) => plan,
        Err(e) => {
            writeln!(files.out, "✗ sandbox          not written: {e:#}")?;
            return Ok(false);
        }
    };
    let out = &mut *files.detail;
    let mut any = false;
    for host in selected {
        let changed = sandbox::install::write(home, host, &plan, dry_run)?;
        any |= changed;
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
    Ok(any)
}
