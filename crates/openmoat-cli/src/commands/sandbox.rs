//! `moat sandbox show` and `moat sandbox sync`: the host sandbox settings the policy compiles to.

use std::io::{self, Write as _};
use std::path::PathBuf;

use anyhow::{Result, bail};
use openmoat_hosts::Host;
use serde_json::{Value, json};

use crate::cli::{Format, SandboxShowArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::install::{HookState, HostConfig};
use crate::integrity::{self, HookPins};
use crate::render::{self, Deferred};
use crate::sandbox::backend::{Pin, SandboxBackend, SecretMask};
use crate::sandbox::{Grants, Plan, Report, install, landlock_rules, own_login, seatbelt_profile};

/// One host's generated settings, ready to print.
struct Shown<'a> {
    host: Host,
    path: PathBuf,
    /// What OpenMoat owns in the file, in the file's own format.
    text: String,
    report: &'a Report,
}

pub fn show(args: &SandboxShowArgs) -> Result<Code> {
    let home = Home::locate()?;
    let policy = home.load_policy()?;
    let plan = Plan::new(&home, &policy)?;
    let ctx = crate::context::eval_context(&home, None, None)?;
    let seatbelt = seatbelt_profile(&policy, &ctx, Grants::default())?;
    let landlock = landlock_rules(&policy, &ctx, Grants::default())?;
    // `moat run` in this directory, before it adds the agent, `--write` paths
    // and its proxy's port.
    let landlock_text = serde_json::to_string_pretty(&landlock.rules)?;
    let lightweight = [
        ("Seatbelt (macOS)", &seatbelt.profile, &seatbelt.report),
        ("Landlock (Linux)", &landlock_text, &landlock.report),
    ];
    let masks = shown_masks(&plan, &policy.secrets)?;
    let mut hosts = Vec::new();
    for host in install::hosts() {
        let Some(backend) = install::backend(host) else {
            continue;
        };
        hosts.push(Shown {
            host,
            path: install::settings_path(&home, host)?,
            text: backend.shown(&plan)?,
            report: backend.report(&plan),
        });
    }
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
            "hook_only": hook_only_json(&policy),
            "agent_logins": agent_logins_json(&policy),
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
    write_secrets(&mut out, &policy.secrets, masks.as_ref())?;
    write_hook_only(&mut out, &policy)?;
    write_agent_logins(&mut out, &policy)?;
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
            "{title}  `openmoat run` in this directory (Lightweight tier)"
        )?;
        writeln!(out, "{}", text.trim_end())?;
        write_report(&mut out, report)?;
    }
    writeln!(out, "dry run: nothing was written")?;
    Ok(Code::Ok)
}

/// `moat sandbox sync`: write the sandbox settings of every host that is set up
/// ([`HostConfig::set_up`]) from the current policy and re-pin them; any other
/// host's files are left as they are. A re-pin accepts what it pins, so like
/// `moat allow` it refuses over a drifted lock (#163) and without a person.
pub fn sync() -> Result<Code> {
    let home = Home::locate()?;
    let mut out = Deferred::default();
    sync_checked(&home, "openmoat sandbox sync", &mut out)?;
    out.finish()?;
    Ok(Code::Ok)
}

/// What [`sync_checked`] did: how many agents' sandbox settings changed.
pub struct Synced {
    pub updated: usize,
}

/// `moat sandbox sync` as `command` runs it (`openmoat policy upgrade` runs it
/// after writing the policy): refused from an agent, without a terminal and
/// over a drifted lock, as `sync` is; one line per host to `out`.
pub fn sync_checked(home: &Home, command: &str, out: &mut impl io::Write) -> Result<Synced> {
    crate::terminal::refuse_agent(command)?;
    if !crate::terminal::interactive() {
        bail!("`{command}` must be run by a person in a terminal, not from a hook or script");
    }
    integrity::refuse_drift(home, "sync")?;
    write_all(home, out)
}

/// Write every set-up host's sandbox settings and re-pin them, after the
/// checks of [`sync_checked`].
fn write_all(home: &Home, out: &mut impl io::Write) -> Result<Synced> {
    let plan = Plan::new(home, &home.load_policy()?)?;
    let binary = crate::install::hook_binary()?;
    let mut updated = 0;
    let (mut files, mut by_part) = (Vec::new(), Vec::new());
    if crate::install::migrate_hooks::update(home, &binary)? {
        writeln!(
            out,
            "✔ existing hooks updated; review and trust changed OpenMoat hooks in your agent"
        )?;
    }
    for host in install::hosts() {
        let path = install::settings_path(home, host)?;
        if !path.parent().is_some_and(std::path::Path::is_dir) {
            writeln!(out, "· {:<16} host not found", host.display_name())?;
            continue;
        }
        let config = HostConfig::for_host(home, host)?;
        if !config.set_up(&binary) {
            let why = match config.state(&binary) {
                HookState::Missing => "not set up",
                _ => "hook out of date or unreadable; `openmoat init` repairs it",
            };
            let (name, id) = (host.display_name(), host.id());
            writeln!(
                out,
                "· {name:<16} {why} (`openmoat init --hosts {id}` adds it)"
            )?;
            continue;
        }
        let changed = install::write(home, host, &plan, false)?;
        if let Some(note) = install::unavailable(host) {
            if changed {
                let removed = install::OLD_SANDBOX_REMOVED;
                writeln!(out, "✔ {:<16} {removed}", host.display_name())?;
                files.push(path);
            }
            writeln!(out, "· {:<16} {note}", host.display_name())?;
            continue;
        }
        updated += usize::from(changed);
        let verb = if changed { "updated" } else { "unchanged" };
        writeln!(
            out,
            "✔ {:<16} {} (sandbox {verb})",
            host.display_name(),
            path.display()
        )?;
        write_report(out, install::report(host, &plan))?;
        // A file the host also edits is pinned by the part OpenMoat owns, any
        // other sandbox file whole.
        if matches!(
            install::backend(host).map(SandboxBackend::pin),
            Some(Pin::Part { .. })
        ) {
            by_part.push(path);
        } else {
            files.push(path);
        }
    }
    let lock = integrity::repin_with(home, &binary, HookPins::Keep, &files, &by_part)?;
    writeln!(
        out,
        "✔ lock             {} files and {} Codex profile(s) pinned",
        lock.entries.len(),
        lock.codex_profiles.len()
    )?;
    // The proxy reads the policy once at start-up, so a policy change needs a
    // reload. An installed service is restarted; a missing one is fine
    // (service routing is opt-in, #272).
    match super::proxy::restart_if_installed(home) {
        Ok(Some(message)) => writeln!(out, "✔ service          {message}")?,
        Ok(None) => {}
        Err(e) => writeln!(
            out,
            "! service          restart failed: {e:#}; `openmoat proxy install` restarts it by hand"
        )?,
    }
    Ok(Synced { updated })
}

/// The host whose own broker masks the policy's secrets, and what it does with
/// each of `secrets` in the settings as `sync` writes them.
fn shown_masks<'a>(
    plan: &Plan,
    secrets: &'a [openmoat_core::Secret],
) -> Result<Option<(Host, Vec<SecretMask<'a>>)>> {
    let masking = install::hosts().find_map(|host| {
        install::backend(host)
            .filter(|b| b.masks_secrets())
            .map(|b| (host, b))
    });
    let Some((host, backend)) = masking else {
        return Ok(None);
    };
    let settings = install::parse_json(&backend.shown(plan)?)?;
    Ok(Some((host, backend.secret_masks(&settings, secrets, plan))))
}

/// One line per policy secret: where its value is read (never the value) and
/// what `masks` says the host's broker does with it, or why it does not (the
/// `secrets.<id>` loss).
fn write_secrets(
    out: &mut impl io::Write,
    secrets: &[openmoat_core::Secret],
    masks: Option<&(Host, Vec<SecretMask<'_>>)>,
) -> io::Result<()> {
    if secrets.is_empty() {
        return Ok(());
    }
    writeln!(out, "Secrets  values are never shown")?;
    let Some((host, masks)) = masks else {
        return Ok(());
    };
    for SecretMask { secret, text, .. } in masks {
        let source = match &secret.source {
            openmoat_core::SecretSource::Env(name) => format!("env {name}"),
            openmoat_core::SecretSource::File(path) => format!("file {path}"),
            openmoat_core::SecretSource::Keychain { service, .. } => format!("keychain {service}"),
        };
        let state = if install::masks_unavailable() {
            format!(
                "{}'s sandbox is not available here, so it masks nothing",
                host.display_name()
            )
        } else {
            text.clone()
        };
        writeln!(
            out,
            "  {}  {} {} from {source}; {state}",
            secret.id, secret.host, secret.header
        )?;
    }
    Ok(())
}

/// A `hook_only` group's id and its file patterns by kind (`fs.read`, `fs.write`).
type HookOnly<'a> = (&'a str, Vec<(&'static str, &'a [String])>);

/// The `hook_only` deny groups (ADR-034) and their file patterns by kind:
/// the hook denies the agent's own reads and writes of them, the OS sandboxes
/// leave them to the other rules.
fn hook_only(policy: &openmoat_core::Policy) -> Vec<HookOnly<'_>> {
    use openmoat_core::Kind;
    policy
        .deny
        .iter()
        .filter(|group| group.hook_only)
        .map(|group| {
            let kinds = [Kind::FsRead, Kind::FsWrite]
                .into_iter()
                .map(|kind| (kind.as_str(), group.patterns(kind)))
                .filter(|(_, patterns)| !patterns.is_empty())
                .collect();
            (group.id.as_str(), kinds)
        })
        .collect()
}

/// [`hook_only`] for `--format json`.
fn hook_only_json(policy: &openmoat_core::Policy) -> Value {
    hook_only(policy)
        .into_iter()
        .map(|(id, kinds)| {
            let mut entry = serde_json::Map::new();
            entry.insert("id".to_owned(), json!(id));
            for (kind, patterns) in kinds {
                entry.insert(kind.to_owned(), json!(patterns));
            }
            Value::Object(entry)
        })
        .collect()
}

/// The [`hook_only`] groups, so nobody takes the OS sandbox to cover them.
fn write_hook_only(out: &mut impl io::Write, policy: &openmoat_core::Policy) -> io::Result<()> {
    let groups = hook_only(policy);
    if groups.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "Hook only  decided by the hook only, not in the OS sandbox (ADR-034): the agent's own \
         reads and writes are denied, commands the sandbox runs can still use these files"
    )?;
    for (id, kinds) in groups {
        for (kind, patterns) in kinds {
            writeln!(out, "  {id}  {kind}: {}", patterns.join(", "))?;
        }
    }
    Ok(())
}

/// Whether `policy` denies the agents' logins in the OS sandboxes (ADR-054):
/// its `agent-credentials` group is there and not `hook_only`.
fn agent_logins_denied(policy: &openmoat_core::Policy) -> bool {
    policy
        .deny
        .iter()
        .any(|g| g.id == own_login::RULE && !g.hook_only)
}

/// Each agent with a login and the patterns `openmoat run` keeps readable
/// when it starts that agent, in the host list's order.
fn kept_logins() -> Vec<(Host, Vec<String>)> {
    Host::ALL
        .into_iter()
        .map(|host| (host, own_login::own_patterns(host)))
        .filter(|(_, patterns)| !patterns.is_empty())
        .collect()
}

/// [`kept_logins`] for `--format json`, under the rule they come from.
fn agent_logins_json(policy: &openmoat_core::Policy) -> Value {
    let denied = agent_logins_denied(policy);
    let kept: serde_json::Map<String, Value> = kept_logins()
        .into_iter()
        .filter(|_| denied)
        .map(|(host, patterns)| (host.id().to_owned(), json!(patterns)))
        .collect();
    json!({ "rule": own_login::RULE, "denied": denied, "run_keeps": kept })
}

/// Where the agents' logins are denied, and what `openmoat run` keeps of them.
fn write_agent_logins(out: &mut impl io::Write, policy: &openmoat_core::Policy) -> io::Result<()> {
    if !agent_logins_denied(policy) {
        return Ok(());
    }
    writeln!(
        out,
        "Agent logins  every sandbox denies the agents' login files to the commands an agent \
         runs (`{}`, ADR-054); the agents' own sandboxes confine only those commands, so the \
         agent still signs in. `openmoat run` holds the agent itself, so it keeps the login of \
         the agent it starts readable (`{}`), or for another program the logins inside its \
         `--write` paths:",
        own_login::RULE,
        own_login::ALLOWANCE
    )?;
    for (host, patterns) in kept_logins() {
        writeln!(out, "  {}  {}", host.display_name(), patterns.join(", "))?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use openmoat_core::{DEFAULT_POLICY, Policy};

    use super::{hook_only_json, write_hook_only};

    #[test]
    fn show_lists_the_hook_only_groups_as_outside_the_os_sandbox() {
        let policy = Policy::parse(DEFAULT_POLICY).unwrap();
        let mut out = Vec::new();
        write_hook_only(&mut out, &policy).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("decided by the hook only, not in the OS sandbox"),
            "{text}"
        );
        assert!(
            text.contains("build-credentials  fs.read: ~/.m2/settings.xml"),
            "{text}"
        );
        assert!(text.contains("build-credentials  fs.write:"), "{text}");
        let json = hook_only_json(&policy);
        assert_eq!(json[0]["id"], "build-credentials");
        assert_eq!(json[0]["fs.read"][0], "~/.m2/settings.xml");
    }

    #[test]
    fn a_policy_without_hook_only_groups_shows_nothing_for_them() {
        let policy = Policy::parse("version: 1\n").unwrap();
        let mut out = Vec::new();
        write_hook_only(&mut out, &policy).unwrap();
        assert_eq!(out, Vec::<u8>::new());
        assert_eq!(hook_only_json(&policy), serde_json::json!([]));
    }
}
