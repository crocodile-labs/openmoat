//! `moat allow`: turn an `ask` (a shell command or a file action) into a session
//! grant or a permanent rule, allow a site or a directory permanently, or remove a
//! permanent rule.

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail, ensure};
use openmoat_audit::Event;
use openmoat_core::{Action, PathResolver as _, RuleGroup, Verdict};

use crate::approvals::{self, GRANT_TTL_MS, Grants, Overlay};
use crate::cli::AllowArgs;
use crate::context::{absolute, path_string};
use crate::exit::Code;
use crate::home::Home;
use crate::integrity::{self, HookPins};
use crate::realpath::FsPathResolver;
use crate::render::{self, Deferred};

/// How many recent events `--last` searches for the newest `ask` it can approve.
const LAST_ASK_SEARCH: usize = 200;

pub fn run(args: &AllowArgs) -> Result<Code> {
    let home = checked_home()?;
    let mut out = Deferred::default();
    if args.site.is_some() || args.dir.is_some() || args.remove.is_some() {
        change_overlay(&home, args, &mut out)?;
        repin(&home, out)?;
        return sync_sandboxes();
    }
    let (host, session, action) = match (&args.command, args.last) {
        (Some(command), false) => (
            args.host.map(|h| h.id().to_owned()),
            args.session.clone(),
            Action::Shell {
                command: command.trim().to_owned(),
            },
        ),
        (None, true) => {
            let event = newest_ask(&home.open_audit()?)?
                .context("no recent `ask` for a shell command or a file in the audit log")?;
            let action = asked(&event)?;
            let last = format!(
                "last ask: {} on {} (session {}) wanted to {}",
                event.id,
                event.host,
                event.session_id,
                approvals::describe(&action)
            );
            render::line(&mut out, &last)?;
            (Some(event.host), Some(event.session_id), action)
        }
        _ => bail!("give a command, or --last to take the most recent ask"),
    };
    approve(&home, host, session, &action, args.always, out)
}

/// Approve exactly `action` (from [`asked`]) for the host session, or for good
/// with `always`: the home screen's answer, with the same checks as `run`.
pub(super) fn run_for(host: &str, session: &str, action: &Action, always: bool) -> Result<Code> {
    let home = checked_home()?;
    let (host, session) = (Some(host.to_owned()), Some(session.to_owned()));
    approve(&home, host, session, action, always, Deferred::default())
}

/// The state directory, once a person at a terminal is confirmed and the lock
/// shows no drift.
fn checked_home() -> Result<Home> {
    if !crate::terminal::interactive() {
        bail!("`moat allow` must be run by a person in a terminal, not from a hook or script");
    }
    let home = Home::locate()?;
    if !home.exists() {
        bail!("{} does not exist; run `moat init`", home.root().display());
    }
    // The re-pin below covers every pinned file, so approving one command over a
    // drifted lock would also accept a tampered policy or hook unseen. Without a
    // lock there is nothing to accept yet and the re-pin creates one.
    if home.lock_path().exists()
        && let Some(deny) = integrity::violation(&home)?
    {
        bail!(
            "refusing to approve while the policy lock shows drift ({}):\n  {}",
            integrity::INTEGRITY_RULE,
            deny.reasons.join("\n  ")
        );
    }
    Ok(home)
}

/// Write the session grant, or with `always` the permanent rule, then re-pin;
/// a permanent file rule also updates the agents' sandboxes.
fn approve(
    home: &Home,
    host: Option<String>,
    session: Option<String>,
    action: &Action,
    always: bool,
    mut out: Deferred,
) -> Result<Code> {
    if always {
        let path = home.overlay_path();
        let mut overlay = Overlay::load(&path)?;
        let rule = if let Action::Shell { command } = action {
            overlay.allow_command(command)?.clone()
        } else {
            let (reads, writes) = approvals::files(action);
            overlay
                .allow_files(&spellings(reads), &spellings(writes))?
                .clone()
        };
        render::line(&mut out, &will_allow(&rule))?;
        overlay.save(&path)?;
        if let Action::Shell { command } = action {
            let added = format!("✔ permanent rule {} allows shell \"{command}\"", rule.id);
            render::line(&mut out, &added)?;
        } else {
            writeln!(out, "✔ added to {}:", path.display())?;
            for line in openmoat_core::yaml::to_string(&[&rule])?.lines() {
                render::line(&mut out, &format!("    {line}"))?;
            }
            writeln!(
                out,
                "  `moat allow --dir <dir>` allows a whole directory, `moat edit` any pattern"
            )?;
        }
        writeln!(out, "  undo: moat allow --remove {}", rule.id)?;
        warn_if_shadowed(home, &rule.id, &mut out)?;
    } else {
        let session = session.context(
            "give --host and --session for a session grant, --always for a permanent rule, or --last",
        )?;
        let host = host.context("--session needs --host")?;
        let path = home.grants_path();
        let mut grants = Grants::load(&path)?;
        let now = crate::time::now_ms();
        grants.grant(&host, &session, action, now);
        grants.save(&path, now)?;
        let granted = format!(
            "✔ session {session} on {host} may {} for {}",
            approvals::describe(action),
            crate::time::duration(GRANT_TTL_MS)
        );
        render::line(&mut out, &granted)?;
        let resume = if host == openmoat_hosts::Host::ClaudeCode.id() {
            " (`claude --continue` resumes this one)"
        } else {
            ""
        };
        writeln!(
            out,
            "  only in this agent session: a new session asks again{resume}"
        )?;
    }
    repin(home, out)?;
    // a command rule is the hook's alone; a file rule is also a sandbox grant
    if always && !matches!(action, Action::Shell { .. }) {
        return sync_sandboxes();
    }
    Ok(Code::Ok)
}

/// A rule that names a directory, a file or a host changes what the agents'
/// OS sandboxes may reach, so write them now, as `moat sandbox sync` does:
/// until then a sandboxed command still meets the old settings.
fn sync_sandboxes() -> Result<Code> {
    println!("Updating the agents' sandbox settings:");
    super::sandbox::sync()
}

/// What a permanent rule from `--always` will match, printed before it is
/// written: shell rules are prefixes (`Overlay::allow_command`), file rules
/// name exact paths.
fn will_allow(rule: &RuleGroup) -> String {
    let what = if rule.shell.is_empty() {
        let files: Vec<String> = [("read", &rule.fs_read), ("write", &rule.fs_write)]
            .iter()
            .filter(|(_, paths)| !paths.is_empty())
            .map(|(verb, paths)| format!("{verb} exactly {}", paths.join(", ")))
            .collect();
        format!("{} (no other path)", files.join(" and "))
    } else {
        format!(
            "{} (and the same command with extra arguments)",
            rule.shell.join(", ")
        )
    };
    format!("will allow: {what}; deny rules still win")
}

/// Each path as asked and with its symlinks resolved, since the hook checks a
/// path both ways and the stricter answer wins.
fn spellings(paths: &[String]) -> Vec<String> {
    let mut out = paths.to_vec();
    for real in paths.iter().filter_map(|p| FsPathResolver.resolve(p)) {
        if !out.contains(&real) {
            out.push(real);
        }
    }
    out
}

fn repin(home: &Home, mut out: Deferred) -> Result<Code> {
    let binary = crate::install::hook_binary()?;
    let lock = integrity::repin(home, &binary, HookPins::Keep)?;
    writeln!(out, "✔ lock re-pinned ({} files)", lock.entries.len())?;
    out.finish()?;
    Ok(Code::Ok)
}

/// `--site`, `--dir` or `--remove`: change the overlay, check that the merged
/// policy still lints (restoring the overlay if not), and print the rule exactly
/// as written so the person sees what changed and how to take it back.
fn change_overlay(home: &Home, args: &AllowArgs, out: &mut Deferred) -> Result<()> {
    let path = home.overlay_path();
    let before = Overlay::load(&path)?;
    let mut overlay = before.clone();
    let (verb, rule) = if let Some(id) = &args.remove {
        let ids: Vec<String> = overlay.allow.iter().map(|g| g.id.clone()).collect();
        let rule = overlay.remove(id).with_context(|| {
            format!(
                "no rule `{id}` in {}; rules there: {}",
                path.display(),
                if ids.is_empty() {
                    "none".to_owned()
                } else {
                    ids.join(", ")
                }
            )
        })?;
        ("removed from", rule)
    } else if let Some(host) = &args.site {
        ("added to", overlay.allow_site(host)?.clone())
    } else {
        let dir = args
            .dir
            .as_deref()
            .context("give --site, --dir or --remove")?;
        ("added to", overlay.allow_dir(&dir_spellings(dir)?).clone())
    };
    overlay.save(&path)?;
    if let Err(error) = home.load_policy() {
        before.save(&path)?;
        return Err(error.context(format!("{} left unchanged", path.display())));
    }
    writeln!(out, "✔ {verb} {}:", path.display())?;
    for line in openmoat_core::yaml::to_string(&[&rule])?.lines() {
        writeln!(out, "    {line}")?;
    }
    if args.remove.is_none() {
        if args.dir.is_some() {
            writeln!(
                out,
                "  deny rules still win: secrets and kernel files in it stay denied"
            )?;
        }
        writeln!(out, "  undo: moat allow --remove {}", rule.id)?;
        warn_if_shadowed(home, &rule.id, out)?;
    }
    Ok(())
}

/// The directory as written (made absolute) and with its symlinks resolved,
/// since the hook checks a path both ways. Refuses a directory that would open
/// the home directory or the whole machine, and one whose name holds glob
/// characters, which a rule would read as wildcards.
fn dir_spellings(dir: &Path) -> Result<Vec<String>> {
    let written = absolute(dir)?;
    let real = std::fs::canonicalize(&written)
        .with_context(|| format!("{} does not exist", written.display()))?;
    ensure!(real.is_dir(), "{} is not a directory", written.display());
    ensure!(
        crate::project::trusted(&written, &crate::home::user_home()?),
        "refusing to allow {}: it is the home directory, one of its ancestors or a \
         filesystem root; name a directory inside it",
        written.display()
    );
    let mut spellings = vec![path_string(&written)];
    let real = path_string(&real);
    if real != spellings[0] {
        spellings.push(real);
    }
    ensure!(
        !spellings
            .iter()
            .any(|s| s.contains(['*', '?', '[', ']', '{', '}', '\\'])),
        "{} contains glob characters; write it in the policy with `moat edit` instead",
        written.display()
    );
    Ok(spellings)
}

/// A rule a deny already covers can never decide anything; say so rather than
/// let the person believe the command is now allowed.
fn warn_if_shadowed(home: &Home, id: &str, out: &mut Deferred) -> Result<()> {
    let Ok(policy) = home.load_policy() else {
        return Ok(());
    };
    for warning in openmoat_core::lint::warnings(&policy) {
        if warning.rule == id {
            writeln!(out, "warning: {warning}")?;
        }
    }
    Ok(())
}

/// The action an ask named, as a grant or rule approves it ([`approvals::approvable`]).
pub(super) fn asked(event: &Event) -> Result<Action> {
    let cwd = match event.cwd.as_deref() {
        Some(cwd) => Some(path_string(&absolute(Path::new(cwd))?)),
        None => None,
    };
    let home = path_string(&crate::home::user_home()?);
    event
        .action
        .as_ref()
        .and_then(|a| approvals::approvable(a, cwd.as_deref(), &home))
        .with_context(|| {
            format!(
                "ask {} names no file `moat allow` can approve (none, or a relative path \
                 without a working directory); allow it with `moat edit` instead",
                event.id
            )
        })
}

/// The most recent `ask` for a shell command or a file: what `--last` takes.
pub(super) fn newest_ask(store: &openmoat_audit::Store) -> Result<Option<Event>> {
    Ok(store.recent(LAST_ASK_SEARCH)?.into_iter().find(|e| {
        e.verdict == Verdict::Ask
            && matches!(
                e.action,
                Some(
                    Action::Shell { .. }
                        | Action::FsRead { .. }
                        | Action::FsWrite { .. }
                        | Action::Patch { .. }
                        | Action::ReadFiles { .. }
                )
            )
    }))
}
