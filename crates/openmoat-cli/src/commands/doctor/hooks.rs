//! `openmoat doctor`'s rows for each agent's hook.

use std::path::{Path, PathBuf};

use anyhow::Result;
use openmoat_hosts::Host;

use super::human::Place;
use super::{Area, Report};
use crate::home::Home;
use crate::install::{HookState, HostConfig, Recorded, dir_variable, env_config_dir, stale_hint};
use crate::report::{Mark, Row};

/// One line per host's hook, then the agents OpenMoat finds but cannot hook;
/// returns the installed hook files.
pub(super) fn hooks(report: &mut Report, home: &Home, binary: &Path) -> Result<Vec<PathBuf>> {
    let recorded = Recorded::load(home)?;
    let mut hook_files = Vec::new();
    crate::install::host_version::prefetch_present(home);
    for host in Host::ALL {
        let config = HostConfig::for_host(home, host)?;
        let name = host.display_name();
        // A version with a published advisory: a flaw no hook sees.
        if config.host_present() {
            for line in crate::install::host_version::advisories(host) {
                report.warn(&line);
            }
        }
        // The copies editor extensions bundle, which read the same hook file.
        for (fine, line) in crate::install::host_version::bundled_lines(host) {
            let line = format!("{name:<16} {line}");
            if fine {
                report.note(&line);
            } else {
                report.warn(&line);
            }
        }
        location(report, host, &config, &recorded)?;
        let state = config.state(binary);
        // A version that does not load OpenMoat's hook (OpenCode before
        // 1.3.4), whatever the hook file says.
        if config.host_present()
            && let Some(why) = crate::install::host_version::unsupported(host)
        {
            report.line(
                Area::Hook,
                false,
                format!("{name:<16} not protected: {why}"),
            );
            continue;
        }
        if recorded.skipped(host) && config.host_present() && matches!(state, HookState::Missing) {
            report.note(&format!(
                "{name:<16} not set up; `openmoat init --hosts {}` adds it",
                host.id()
            ));
            continue;
        }
        match state {
            HookState::Installed => installed(report, home, &config, &mut hook_files),
            HookState::Missing if !config.host_present() => {
                report.note(&format!("{name:<16} host not found"));
            }
            HookState::Missing => {
                report.line(
                    Area::Hook,
                    false,
                    format!("{name:<16} hook missing; run `openmoat init`"),
                );
            }
            HookState::Stale { command } => {
                report.line(
                    Area::Hook,
                    false,
                    format!("{name:<16} {}", stale_hint(&command)),
                );
            }
            HookState::Unreadable(e)
            | HookState::Unapproved(e)
            | HookState::FailsOpen(e)
            | HookState::TurnedOff(e) => {
                report.line(Area::Hook, false, format!("{name:<16} {e}"));
            }
        }
    }
    for (host, found) in crate::install::detected()? {
        let name = host.display_name();
        report.note(&format!(
            "{name:<16} {}  {}",
            host.spec().gaps,
            found.display()
        ));
        // What it means for that agent stays in sight: no hook protects it.
        let text = format!("found at {}; {}", found.display(), host.spec().gaps);
        report.human(Place::Agents, Row::new(Mark::Attention, name, text));
        let line = crate::protection::os_sandbox_line(home, host)?;
        report.human(Place::Agents, Row::new(Mark::Info, name, line));
    }
    Ok(hook_files)
}

/// Every command follows the record; a variable naming another directory is
/// reported rather than silently ignored or followed.
fn location(
    report: &mut Report,
    host: Host,
    config: &HostConfig,
    recorded: &Recorded,
) -> Result<()> {
    let name = host.display_name();
    if let Some((locate, set_up)) = config.custom_location() {
        if recorded.dir(host).is_some()
            && let Some(line) = crate::install::location::env_disagrees(locate, &set_up)?
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
                "{name:<16} {var} is {}, but `openmoat init` set it up in {}, which OpenMoat uses; \
                 run `openmoat init` with {var} set to set up that directory instead",
                env.display(),
                dir.display()
            ),
        );
    }
    Ok(())
}

/// The rows of an installed hook: whether the agent trusts it, the hook file,
/// whether the agent loaded the plugin, and whether a failed hook blocks.
fn installed(report: &mut Report, home: &Home, config: &HostConfig, hook_files: &mut Vec<PathBuf>) {
    let (host, name) = (config.host, config.host.display_name());
    if let Some(warning) = config.trust_warning() {
        let text = format!("{name:<16} {warning}");
        match crate::install::trust_note::step(host) {
            Some(step) => {
                report.warn_as(&text, Row::new(Mark::Attention, name, warning).fix(step));
            }
            None => report.warn(&text),
        }
    }
    // the files the lock pins with it (OpenClaw's plugin), as integrity lists them
    hook_files.extend(config.extra_files());
    hook_files.push(config.settings_path.clone());
    // The hook a version runs OpenMoat through, where versions differ
    // (OpenCode 1's and 2's).
    let through = crate::install::host_version::hook_api(host)
        .map(|through| format!(" ({through})"))
        .unwrap_or_default();
    report.line(
        Area::Hook,
        true,
        format!(
            "{name:<16} hook installed{through}  {}",
            config.settings_path.display()
        ),
    );
    // Whether the host loaded the plugin (ADR-042).
    if let Some(loaded) = crate::heartbeat::check(home, config) {
        let (mark, text) = crate::heartbeat::line(name, &loaded);
        let text = format!("{name:<16} {text}");
        match mark {
            crate::heartbeat::Mark::Note => report.note(&text),
            crate::heartbeat::Mark::Warning => report.warn(&text),
        }
    }
    if config.runs_calls_when_hook_fails() {
        report.warn(&format!(
            "{name:<16} runs a tool call when its hook fails to start, crashes or \
             times out: no `claude` {since} or later on PATH or in an editor extension, \
             or an older copy beside it, so the hook has no `onFailure: \"block\"`; \
             update Claude Code, then run `openmoat init`",
            since = crate::install::on_failure_since()
        ));
    }
}
