//! `moat policy upgrade`: add what this release's default changed to the
//! person's policy, show what changes (grouped, `summary.rs`; the full diff on
//! `d` or `--diff`) and ask; once applied, sync the agents' sandboxes as `openmoat
//! sandbox sync` does. `--undo` puts the previous policy back.

use std::fs;
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use similar::{Algorithm, udiff::unified_diff};

use crate::VERSION;
use crate::cli::UpgradeArgs;
use crate::context::read_policy;
use crate::exit::Code;
use crate::home::{Home, write_private};
use crate::integrity::{self, HookPins};
use crate::render::{DIFF_CONTEXT_LINES, Deferred};
use crate::upgrade::{Base, Plan};

mod summary;

pub fn run(args: &UpgradeArgs) -> Result<Code> {
    let home = Home::locate()?;
    if !home.policy_path().is_file() {
        bail!(
            "no policy at {}; run `openmoat init`",
            home.policy_path().display()
        );
    }
    if args.undo {
        return undo(&home, args.yes);
    }
    let plan = Plan::for_home(&home)?;
    let mut out = Deferred::default();
    describe(&plan, args, &mut out)?;
    let binary = crate::install::hook_binary()?;
    let hook_upgrade = crate::install::migrate_hooks::needed(&home, &binary)?;
    if hook_upgrade {
        writeln!(
            out,
            "OpenMoat's hooks change too; an agent that keeps its own record of trusted hooks \
             asks you to trust the changed one"
        )?;
    }
    if plan.applicable() == 0 || args.dry_run {
        if hook_upgrade && !args.dry_run {
            person("openmoat policy upgrade")?;
            integrity::refuse_drift(&home, "upgrade existing hooks")?;
            crate::install::migrate_hooks::update(&home, &binary)?;
            integrity::repin(&home, &binary, HookPins::Keep)?;
            writeln!(out, "✔ OpenMoat's hooks updated")?;
            trust_steps(&home, &binary, &mut out)?;
        }
        if !args.dry_run && up_to_date_without_record(&plan) && crate::terminal::person() {
            // Recorded now so a later default is compared with this one, not 0.3.0.
            write_private(&home.policy_base_path(), plan.merge.base.as_bytes())?;
        }
        out.finish()?;
        return Ok(Code::Ok);
    }
    person("openmoat policy upgrade")?;
    // Applying re-pins every pinned file, so upgrading over drift would accept it unseen.
    integrity::refuse_drift(&home, "upgrade the policy")?;
    let checkpoint = integrity::Checkpoint::take(&home)?;
    lint(&home, &plan.merge.text)?;
    if !args.yes && !confirm(&plan, &mut out)? {
        writeln!(out, "the policy was not changed")?;
        out.finish()?;
        return Ok(Code::Ok);
    }
    // The re-pin after the writes covers every pinned file: one changed while
    // the question waited would be accepted unseen.
    checkpoint.verify(&home, &[])?;
    apply(&home, &plan, &mut out)?;
    if hook_upgrade {
        trust_steps(&home, &binary, &mut out)?;
    }
    sync(&home, &mut out)?;
    out.finish()?;
    Ok(Code::Ok)
}

/// `Apply these changes? [y/N/d]`, where `d` shows the full diff and asks
/// again; anything but yes, end of input included, is no.
fn confirm(plan: &Plan, out: &mut Deferred) -> Result<bool> {
    loop {
        let question = "\nApply these changes? [y/N/d]   (d = show the full diff) ";
        match crate::commands::edit::answer(out, question)?.as_str() {
            "y" | "yes" => return Ok(true),
            "d" | "diff" => full_diff(plan, out)?,
            _ => return Ok(false),
        }
    }
}

/// The policy as it is against the policy upgraded, as `diff -u` shows it.
fn full_diff(plan: &Plan, out: &mut Deferred) -> Result<()> {
    let diff = unified_diff(
        Algorithm::Myers,
        &plan.current,
        &plan.merge.text,
        DIFF_CONTEXT_LINES,
        Some(("policy.yaml (installed)", "policy.yaml (upgraded)")),
    );
    write!(out, "{diff}")?;
    Ok(())
}

/// The step each set-up agent with its own record of trusted hooks needs
/// after its hook changed (Codex's `/hooks`).
fn trust_steps(home: &Home, binary: &Path, out: &mut Deferred) -> Result<()> {
    for host in openmoat_hosts::Host::ALL {
        if let Some(step) = crate::install::trust_note::step(host)
            && crate::install::HostConfig::for_host(home, host)?.set_up(binary)
        {
            writeln!(out, "! {}: {step}", host.display_name())?;
        }
    }
    Ok(())
}

/// The agents' sandboxes from the upgraded policy, as `openmoat sandbox sync`
/// writes them, after the same checks; when they cannot be written, the
/// command to run.
fn sync(home: &Home, out: &mut Deferred) -> Result<()> {
    let mut lines = Vec::new();
    match crate::commands::sandbox::sync_checked(home, "openmoat policy upgrade", &mut lines) {
        Ok(synced) if synced.updated == 0 => {
            writeln!(out, "✔ Agents' sandboxes already follow the policy")?;
        }
        Ok(_) => writeln!(out, "✔ Agents' sandboxes updated")?,
        Err(e) => writeln!(
            out,
            "! Agents' sandboxes not updated: {e:#}\n  run `openmoat sandbox sync` so the agents' \
             sandboxes follow the upgraded policy"
        )?,
    }
    Ok(())
}

/// What the default adds, grouped (`summary.rs`) or, with `--diff`, also as a
/// diff of the policy, and what it cannot add.
fn describe(plan: &Plan, args: &UpgradeArgs, out: &mut Deferred) -> Result<()> {
    match plan.base {
        Base::Recorded => {}
        Base::Assumed => writeln!(
            out,
            "No record of the default this policy started from; comparing with the \
             OpenMoat 0.3.0 default (the policy predates OpenMoat recording it)."
        )?,
        Base::Unrelated => {
            writeln!(
                out,
                "This policy was not made from OpenMoat's default, so no change of the default \
                 is offered; compare it with `openmoat policy lint` and the default in docs/POLICY.md."
            )?;
            if !plan.renamed {
                return Ok(());
            }
        }
    }
    let count = plan.applicable();
    if count > 0 {
        let from_default = count - usize::from(plan.renamed);
        let title = if from_default > 0 {
            format!("OpenMoat {VERSION} has new default rules for your policy")
        } else {
            format!("OpenMoat {VERSION} renames a word in your policy")
        };
        writeln!(out, "{title}\n")?;
        let applied: Vec<_> = plan.merge.applied().collect();
        summary::summarise(&plan.current, &plan.merge.text, &applied, plan.renamed).write(out)?;
        if args.diff {
            writeln!(out)?;
            full_diff(plan, out)?;
        }
        if args.dry_run {
            writeln!(
                out,
                "\nNothing was changed: `openmoat policy upgrade` applies them after asking \
                 (`--diff` shows the full diff); `--undo` takes them back."
            )?;
        }
    }
    for change in plan.merge.conflicts() {
        writeln!(
            out,
            "Not applied: you changed the policy at line {}; the default now has:",
            change.line
        )?;
        for line in change.default.lines() {
            writeln!(out, "  {line}")?;
        }
    }
    if plan.merge.conflicts().next().is_some() {
        writeln!(
            out,
            "Make those by hand with `openmoat edit` if you want them."
        )?;
    } else if count == 0 {
        writeln!(
            out,
            "The policy has every change of the OpenMoat {VERSION} default."
        )?;
    }
    Ok(())
}

/// A policy from before `policy.base.yaml` that already has every change.
fn up_to_date_without_record(plan: &Plan) -> bool {
    plan.base == Base::Assumed && plan.merge.changes.is_empty()
}

/// Refuse unless a person is at a terminal: writing the policy re-pins the lock.
fn person(command: &str) -> Result<()> {
    crate::terminal::refuse_agent(command)?;
    if !crate::terminal::interactive() {
        bail!(
            "`{command}` must be run by a person in a terminal, not from a hook or script; \
             `openmoat policy upgrade --dry-run` shows the changes anywhere"
        );
    }
    Ok(())
}

/// Check the upgraded policy, with `moat allow` rules merged, the way `moat
/// edit` checks its draft: from a file in the state directory agents cannot write.
fn lint(home: &Home, text: &str) -> Result<()> {
    let draft = home.root().join("policy.upgrade.yaml");
    write_private(&draft, text.as_bytes())?;
    let checked = home.load_policy_at(&draft);
    let _ = fs::remove_file(&draft);
    checked
        .map(drop)
        .context("the upgraded policy does not lint; the policy was not changed")
}

/// The policy and base each upgrade replaced, kept for `--undo`.
fn backups(home: &Home) -> (PathBuf, PathBuf) {
    let root = home.root();
    (
        root.join("policy.yaml.before-upgrade"),
        root.join("policy.base.yaml.before-upgrade"),
    )
}

fn apply(home: &Home, plan: &Plan, out: &mut Deferred) -> Result<()> {
    let (policy_backup, base_backup) = backups(home);
    write_private(&policy_backup, plan.current.as_bytes())?;
    copy_or_remove(&home.policy_base_path(), &base_backup)?;
    write_private(&home.policy_path(), plan.merge.text.as_bytes())?;
    // A policy not made from the default takes only the rename (ADR-053); recording
    // the assumed 0.3.0 default as its base would make the next upgrade merge the
    // default into it as if the person had edited every line.
    if plan.base != Base::Unrelated {
        write_private(&home.policy_base_path(), plan.merge.base.as_bytes())?;
    }
    let binary = crate::install::hook_binary()?;
    crate::install::migrate_hooks::update(home, &binary)?;
    integrity::repin(home, &binary, HookPins::Keep)?;
    let paths = crate::report::Paths::detect();
    writeln!(out)?;
    writeln!(
        out,
        "✔ Policy upgraded            undo: openmoat policy upgrade --undo"
    )?;
    writeln!(
        out,
        "  the previous policy is in {}",
        paths.path(&policy_backup)
    )?;
    Ok(())
}

fn undo(home: &Home, yes: bool) -> Result<Code> {
    let (policy_backup, base_backup) = backups(home);
    if !policy_backup.is_file() {
        bail!(
            "no upgrade to undo: {} does not exist",
            policy_backup.display()
        );
    }
    person("openmoat policy upgrade --undo")?;
    integrity::refuse_drift(home, "undo the policy upgrade")?;
    let checkpoint = integrity::Checkpoint::take(home)?;
    let current = read_policy(&home.policy_path())?;
    let previous = read_policy(&policy_backup)?;
    let mut out = Deferred::default();
    let diff = unified_diff(
        Algorithm::Myers,
        &current,
        &previous,
        DIFF_CONTEXT_LINES,
        Some((
            "policy.yaml (installed)",
            "policy.yaml (before the upgrade)",
        )),
    );
    write!(out, "{diff}")?;
    if !yes && !crate::commands::edit::confirm(&mut out, "Restore it? [y/N] ")? {
        writeln!(out, "the policy was not changed")?;
        out.finish()?;
        return Ok(Code::Ok);
    }
    checkpoint.verify(home, &[])?;
    write_private(&home.policy_path(), previous.as_bytes())?;
    copy_or_remove(&base_backup, &home.policy_base_path())?;
    fs::remove_file(&policy_backup)
        .with_context(|| format!("removing {}", policy_backup.display()))?;
    remove_if_present(&base_backup)?;
    let binary = crate::install::hook_binary()?;
    let written = [home.policy_path()];
    let lock = integrity::repin_after(home, &binary, HookPins::Keep, &checkpoint, &written)?;
    writeln!(
        out,
        "✔ {} restored to before the upgrade",
        home.policy_path().display()
    )?;
    writeln!(out, "✔ lock re-pinned ({} files)", lock.entries.len())?;
    out.finish()?;
    Ok(Code::Ok)
}

/// Make `to` a copy of `from`, or absent when `from` is: a policy without a
/// recorded base gets none back on undo.
fn copy_or_remove(from: &Path, to: &Path) -> Result<()> {
    if from.is_file() {
        write_private(to, read_policy(from)?.as_bytes())
    } else {
        remove_if_present(to)
    }
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != ErrorKind::NotFound => {
            Err(e).with_context(|| format!("removing {}", path.display()))
        }
        _ => Ok(()),
    }
}
