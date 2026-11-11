//! `openmoat restore [<snapshot>] [--patch] [-- <paths>]` (ADR-085 §4).
//!
//! A person's command, like `openmoat allow`: it refuses when an agent (or
//! `openmoat run`) is among the processes that started it and when no person
//! is at a terminal, and the default policy denies it to agents
//! (`kernel-self`). It takes a snapshot of the files as they are first, shows
//! every change, asks at the terminal, and only then writes.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

use crate::cli::RestoreArgs;
use crate::context;
use crate::exit::Code;
use crate::home::Home;
use crate::render::{Deferred, clean, clean_lines};
use crate::snapshot::{self, ChangeKind, Limits, Listed, Plan, Reason, Store};

/// At most this many changed paths are named one by one.
const MAX_SHOWN: usize = 200;

pub fn run(args: &RestoreArgs) -> Result<Code> {
    crate::terminal::refuse_agent("openmoat restore")?;
    if !crate::terminal::interactive() {
        bail!(
            "`openmoat restore` must be run by a person in a terminal, not from a hook or script"
        );
    }
    let home = Home::locate()?;
    home.require_exists()?;
    crate::integrity::refuse_drift(&home, "restore files")?;
    let ctx = context::eval_context(&home, None, None)?;
    let project = ctx.project.clone().context(
        "a restore is of a project: run it in the project, not in your home directory, one of \
         its ancestors or a filesystem root",
    )?;
    let Some(store) = Store::existing(&home, Path::new(&project))? else {
        bail!("no snapshots of {project} yet: `openmoat run` and `openmoat snapshot` take them");
    };
    let target = match &args.snapshot {
        Some(id) => store.find(id)?,
        None => newest_run_start(&store)?,
    };
    let only = only_paths(store.project(), &args.paths)?;
    let denied = snapshot::denied(&home, &ctx)?;
    // Held until the files are written, so no prune drops the snapshot to
    // restore or the undo snapshot in between.
    let held = store.lock(snapshot::LOCK_WAIT)?;
    let undo = store
        .take(&held, &denied, Limits::default(), Reason::PreRestore, None)
        .context("taking the snapshot that lets this restore be undone")?
        .snapshot()
        .clone();
    let plan = store.plan(target, undo, &only)?;
    let mut out = Deferred::default();
    show(&mut out, &plan)?;
    if args.patch {
        write!(out, "{}", clean_lines(&store.patch(&plan, MAX_SHOWN)?))?;
    }
    if plan.changes.is_empty() {
        writeln!(
            out,
            "nothing to restore: the files match snapshot {}",
            plan.target.id
        )?;
        out.finish()?;
        return Ok(Code::Ok);
    }
    write!(out, "Restore these {} file(s)? [y/N] ", plan.changes.len())?;
    out.flush()?;
    let answer = crate::terminal::read_answer()?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        writeln!(out, "nothing changed")?;
        out.finish()?;
        return Ok(Code::Ok);
    }
    let applied = store.apply(&held, &plan)?;
    drop(held);
    writeln!(
        out,
        "restored from snapshot {}: {} written, {} deleted",
        plan.target.id, applied.written, applied.deleted
    )?;
    for (path, why) in &applied.skipped {
        writeln!(out, "  not changed: {} ({})", clean(path), clean(why))?;
    }
    writeln!(
        out,
        "undo with `openmoat restore {}`, the snapshot of the files before this restore",
        plan.undo.id
    )?;
    snapshot::record(
        &home,
        &format!("restore-{}", crate::time::now_ms()),
        "restore",
        "restore",
        format!(
            "restored snapshot {} in {project}: {} written, {} deleted, {} not changed; undo \
             snapshot {}",
            plan.target.id,
            applied.written,
            applied.deleted,
            applied.skipped.len(),
            plan.undo.id
        ),
    );
    out.finish()?;
    Ok(Code::Ok)
}

/// The newest snapshot `openmoat run` took before its agent started.
fn newest_run_start(store: &Store) -> Result<Listed> {
    store
        .list()?
        .into_iter()
        .rev()
        .find(|s| s.meta.reason == Reason::RunStart)
        .context(
            "no snapshot `openmoat run` took before an agent started; name one from \
             `openmoat snapshot --list`",
        )
}

/// The project-relative form of each path a person named.
fn only_paths(root: &Path, paths: &[PathBuf]) -> Result<Vec<String>> {
    let cwd = std::env::current_dir().context("determining the current directory")?;
    paths
        .iter()
        .map(|p| {
            let absolute = cwd.join(p);
            let parent = absolute
                .parent()
                .and_then(|d| std::fs::canonicalize(d).ok())
                .zip(absolute.file_name())
                .map(|(d, name)| d.join(name));
            parent
                .as_deref()
                .and_then(|a| snapshot::relative(root, a))
                .with_context(|| format!("{} is not a path inside the project", p.display()))
        })
        .collect()
}

fn show(out: &mut Deferred, plan: &Plan) -> Result<()> {
    let t = &plan.target;
    writeln!(
        out,
        "snapshot {} of {} ({}), {} files",
        t.id,
        crate::time::timestamp(t.ts_ms),
        t.meta.reason.words(),
        t.meta.files
    )?;
    for (shown, change) in plan.changes.iter().enumerate() {
        if shown == MAX_SHOWN {
            writeln!(out, "  … and {} more", plan.changes.len() - MAX_SHOWN)?;
            break;
        }
        let word = match change.kind {
            ChangeKind::Changed => "changed back",
            ChangeKind::Added => "added back  ",
            ChangeKind::Deleted => "deleted     ",
        };
        writeln!(out, "  {word} {}", clean(&change.path))?;
        if let Some(why) = &change.no_copy {
            writeln!(
                out,
                "               no copy of it as it is now is kept: {why}"
            )?;
        }
    }
    for path in plan.kept.iter().take(MAX_SHOWN) {
        writeln!(
            out,
            "  kept as is   {} (not in the snapshot, which left it out)",
            clean(path)
        )?;
    }
    for omitted in &t.meta.left_out {
        writeln!(
            out,
            "  not restored {} ({})",
            clean(&omitted.path),
            omitted.why.words()
        )?;
    }
    Ok(())
}
