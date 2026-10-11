//! `moat sandbox show` and `moat sandbox sync`: the host sandbox settings the policy compiles to.

use std::io::{self, Write as _};
use std::path::PathBuf;

use anyhow::{Result, bail};
use openmoat_hosts::Host;
use serde_json::{Value, json};
use toml_edit::DocumentMut;

use crate::cli::{Format, SandboxShowArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::install::HostConfig;
use crate::integrity::{self, HookPins};
use crate::render::{self, Deferred};
use crate::sandbox::{
    Grants, Plan, Report, claude, codex, codex_config_path, install, landlock_rules,
    seatbelt_profile,
};

/// One host's generated settings, ready to print.
struct Shown<'a> {
    host: Host,
    path: PathBuf,
    /// What OpenMoat owns in the file, in the file's own format.
    text: String,
    report: &'a Report,
}

pub fn show(args: &SandboxShowArgs) -> Result<Code> {
    let policy = Home::locate()?.load_policy()?;
    let plan = Plan::new(&policy)?;
    let ctx = crate::context::eval_context(None, None)?;
    let seatbelt = seatbelt_profile(&policy, &ctx, Grants::default())?;
    let landlock = landlock_rules(&policy, &ctx, Grants::default())?;
    // `moat run` in this directory, before it adds the agent, `--write` paths
    // and its proxy's port.
    let landlock_text = serde_json::to_string_pretty(&landlock.rules)?;
    let lightweight = [
        ("Seatbelt (macOS)", &seatbelt.profile, &seatbelt.report),
        ("Landlock (Linux)", &landlock_text, &landlock.report),
    ];
    let mut codex_doc = DocumentMut::new();
    codex::apply(&mut codex_doc, &plan.codex)?;
    let mut claude_doc = json!({});
    claude::apply(&mut claude_doc, &plan.claude, &mut Vec::new())?;
    let hosts = [
        Shown {
            host: Host::ClaudeCode,
            path: HostConfig::for_host(Host::ClaudeCode)?.settings_path,
            text: serde_json::to_string_pretty(&claude_doc)?,
            report: &plan.claude.report,
        },
        Shown {
            host: Host::Codex,
            path: codex_config_path()?,
            text: codex_doc.to_string(),
            report: &plan.codex.report,
        },
        Shown {
            host: Host::Cursor,
            path: install::settings_path(Host::Cursor)?,
            text: serde_json::to_string_pretty(&plan.cursor.settings)?,
            report: &plan.cursor.report,
        },
    ];
    if args.format == Format::Json {
        let doc: serde_json::Map<String, Value> = hosts
            .iter()
            .map(|s| {
                let entry = match install::unavailable(s.host) {
                    Some(note) => json!({ "path": s.path, "unavailable": note }),
                    None => json!({ "path": s.path, "settings": s.text, "report": s.report }),
                };
                (s.host.id().to_owned(), entry)
            })
            .collect();
        render::json(&json!({
            "default_read_roots": plan.default_read_roots,
            "hosts": doc,
            "lightweight": {
                "seatbelt": { "profile": &seatbelt.profile, "report": &seatbelt.report },
                "landlock": { "rules": &landlock.rules, "report": &landlock.report },
            },
        }))?;
        return Ok(Code::Ok);
    }
    let mut out = io::stdout().lock();
    if plan.default_read_roots {
        writeln!(
            out,
            "note: the policy has no `sandbox.read_roots`; the default policy's list applies"
        )?;
    }
    for shown in hosts {
        if let Some(note) = install::unavailable(shown.host) {
            writeln!(out, "{}  {note}", shown.host.display_name())?;
            continue;
        }
        writeln!(
            out,
            "{}  {}",
            shown.host.display_name(),
            shown.path.display()
        )?;
        writeln!(out, "{}", shown.text.trim_end())?;
        write_report(&mut out, shown.report)?;
    }
    for (title, text, report) in lightweight {
        writeln!(
            out,
            "{title}  `moat run` in this directory (Lightweight tier)"
        )?;
        writeln!(out, "{}", text.trim_end())?;
        write_report(&mut out, report)?;
    }
    writeln!(out, "dry run: nothing was written")?;
    Ok(Code::Ok)
}

/// `moat sandbox sync`: write every present host's sandbox settings from the
/// current policy and re-pin them. A re-pin accepts what it pins, so like
/// `moat allow` it refuses over a drifted lock (#163) and without a person.
pub fn sync() -> Result<Code> {
    if !crate::terminal::interactive() {
        bail!(
            "`moat sandbox sync` must be run by a person in a terminal, not from a hook or script"
        );
    }
    let home = Home::locate()?;
    integrity::refuse_drift(&home, "sync")?;
    let plan = Plan::new(&home.load_policy()?)?;
    let binary = crate::install::hook_binary()?;
    let mut out = Deferred::default();
    let (mut files, mut codex_configs) = (Vec::new(), Vec::new());
    for host in install::HOSTS {
        let path = install::settings_path(host)?;
        if !path.parent().is_some_and(std::path::Path::is_dir) {
            writeln!(out, "· {:<16} host not found", host.display_name())?;
            continue;
        }
        let changed = install::write(host, &plan, false)?;
        if let Some(note) = install::unavailable(host) {
            if changed {
                let removed = install::OLD_SANDBOX_REMOVED;
                writeln!(out, "✔ {:<16} {removed}", host.display_name())?;
                files.push(path);
            }
            writeln!(out, "· {:<16} {note}", host.display_name())?;
            continue;
        }
        let verb = if changed { "updated" } else { "unchanged" };
        writeln!(
            out,
            "✔ {:<16} {} (sandbox {verb})",
            host.display_name(),
            path.display()
        )?;
        write_report(&mut out, install::report(host, &plan))?;
        match host {
            Host::Codex => codex_configs.push(path),
            _ => files.push(path),
        }
    }
    let lock = integrity::repin_with(&home, &binary, HookPins::Keep, &files, &codex_configs)?;
    writeln!(
        out,
        "✔ lock             {} files and {} Codex profile(s) pinned",
        lock.entries.len(),
        lock.codex_profiles.len()
    )?;
    // The proxy reads the policy once at start-up, so a policy change needs a
    // reload. An installed service is restarted; a missing one is fine
    // (service routing is opt-in, #272).
    match super::proxy::restart_if_installed(&home) {
        Ok(Some(message)) => writeln!(out, "✔ service          {message}")?,
        Ok(None) => {}
        Err(e) => writeln!(
            out,
            "! service          restart failed: {e:#}; `moat proxy install` restarts it by hand"
        )?,
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// Losses and allowances, as `sandbox show`, `sandbox sync` and `doctor` print them.
pub(super) fn write_report(out: &mut impl io::Write, report: &Report) -> io::Result<()> {
    for loss in &report.losses {
        writeln!(out, "  stricter: {loss}")?;
    }
    for allowance in &report.allowances {
        writeln!(out, "  wider:    {allowance}")?;
    }
    Ok(())
}
