//! `moat policy upgrade`: add what this release's default changed to the
//! person's policy, show the diff and ask; `--undo` puts the previous one back.

use std::fs;
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use similar::{Algorithm, udiff::unified_diff};

use crate::cli::UpgradeArgs;
use crate::context::read_policy;
use crate::exit::Code;
use crate::home::{Home, write_private};
use crate::integrity::{self, HookPins};
use crate::render::Deferred;
use crate::upgrade::{Base, Plan};

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn run(args: &UpgradeArgs) -> Result<Code> {
    let home = Home::locate()?;
    if !home.policy_path().is_file() {
        bail!(
            "no policy at {}; run `moat init`",
            home.policy_path().display()
        );
    }
    if args.undo {
        return undo(&home, args.yes);
    }
    let plan = Plan::for_home(&home)?;
    let mut out = Deferred::default();
    describe(&plan, &mut out)?;
    if plan.applicable() == 0 || args.dry_run {
        if !args.dry_run && up_to_date_without_record(&plan) && crate::terminal::person() {
            // Recorded now so a later default is compared with this one, not 0.3.0.
            write_private(&home.policy_base_path(), plan.merge.base.as_bytes())?;
        }
        out.finish()?;
        return Ok(Code::Ok);
    }
    person("moat policy upgrade")?;
    // Applying re-pins every pinned file, so upgrading over drift would accept it unseen.
    integrity::refuse_drift(&home, "upgrade the policy")?;
    lint(&home, &plan.merge.text)?;
    let count = plan.applicable();
    let question = format!("Apply {count} change{}? [y/N] ", plural(count));
    if !args.yes && !crate::commands::edit::confirm(&mut out, &question)? {
        writeln!(out, "the policy was not changed")?;
        out.finish()?;
        return Ok(Code::Ok);
    }
    apply(&home, &plan, &mut out)?;
    out.finish()?;
    Ok(Code::Ok)
}

/// What the default adds, as a diff of the policy, and what it cannot add.
fn describe(plan: &Plan, out: &mut Deferred) -> Result<()> {
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
                "This policy was not made from OpenMoat's default, so no change is offered; \
                 compare it with `moat policy lint` and the default in docs/POLICY.md."
            )?;
            return Ok(());
        }
    }
    let count = plan.applicable();
    if count > 0 {
        writeln!(
            out,
            "Policy update available: {count} change{} from the OpenMoat {VERSION} default",
            plural(count)
        )?;
        let diff = unified_diff(
            Algorithm::Myers,
            &plan.current,
            &plan.merge.text,
            3,
            Some(("policy.yaml (installed)", "policy.yaml (upgraded)")),
        );
        write!(out, "{diff}")?;
        writeln!(
            out,
            "`moat policy upgrade` applies them after asking; `--undo` takes them back."
        )?;
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
        writeln!(out, "Make those by hand with `moat edit` if you want them.")?;
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
             `moat policy upgrade --dry-run` shows the changes anywhere"
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
    write_private(&home.policy_base_path(), plan.merge.base.as_bytes())?;
    let lock = integrity::repin(home, &crate::install::hook_binary()?, HookPins::Keep)?;
    let count = plan.applicable();
    writeln!(
        out,
        "✔ {} upgraded ({count} change{})",
        home.policy_path().display(),
        plural(count)
    )?;
    writeln!(out, "✔ lock re-pinned ({} files)", lock.entries.len())?;
    writeln!(
        out,
        "  the previous policy is in {}; undo: moat policy upgrade --undo",
        policy_backup.display()
    )?;
    writeln!(
        out,
        "  run `moat sandbox sync` so the agents' sandboxes follow the upgraded policy"
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
    person("moat policy upgrade --undo")?;
    integrity::refuse_drift(home, "undo the policy upgrade")?;
    let current = read_policy(&home.policy_path())?;
    let previous = read_policy(&policy_backup)?;
    let mut out = Deferred::default();
    let diff = unified_diff(
        Algorithm::Myers,
        &current,
        &previous,
        3,
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
    write_private(&home.policy_path(), previous.as_bytes())?;
    copy_or_remove(&base_backup, &home.policy_base_path())?;
    fs::remove_file(&policy_backup)
        .with_context(|| format!("removing {}", policy_backup.display()))?;
    remove_if_present(&base_backup)?;
    let lock = integrity::repin(home, &crate::install::hook_binary()?, HookPins::Keep)?;
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

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}
