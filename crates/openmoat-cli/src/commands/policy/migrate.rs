//! `moat policy migrate` (ADR-103): a policy file rewritten in the current
//! policy schema (`upgrade/migrate.rs`), shown as a diff and applied only by
//! a person at a terminal, with the previous file kept beside it. The
//! installed policy is pinned, so writing it re-pins the lock, over no drift
//! and after checking nothing changed while the question waited.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_core::SUPPORTED_VERSION;
use similar::{Algorithm, udiff::unified_diff};

use crate::cli::MigrateArgs;
use crate::context::read_policy;
use crate::exit::Code;
use crate::home::{Home, write_private};
use crate::integrity::{self, HookPins};
use crate::render::{DIFF_CONTEXT_LINES, Deferred};
use crate::upgrade::migrate::migrate;

const COMMAND: &str = "openmoat policy migrate";

pub fn run(args: &MigrateArgs) -> Result<Code> {
    let home = Home::locate()?;
    let installed = args.file.is_none();
    let path = args.file.clone().unwrap_or_else(|| home.policy_path());
    let current = read_policy(&path)?;
    let migration = migrate(&current).with_context(|| format!("migrating {}", path.display()))?;
    let paths = crate::report::Paths::detect();
    let mut out = Deferred::default();
    if migration.steps.is_empty() {
        writeln!(
            out,
            "{} is in policy schema version {SUPPORTED_VERSION}, the current one: nothing to \
             migrate",
            paths.path(&path)
        )?;
        out.finish()?;
        return Ok(Code::Ok);
    }
    writeln!(
        out,
        "{} in policy schema version {SUPPORTED_VERSION} (no rule changes):",
        paths.path(&path)
    )?;
    for step in &migration.steps {
        writeln!(out, "  · {}", step.describe())?;
    }
    let name = path
        .file_name()
        .map_or_else(|| "policy".to_owned(), |n| n.to_string_lossy().into_owned());
    let diff = unified_diff(
        Algorithm::Myers,
        &current,
        &migration.text,
        DIFF_CONTEXT_LINES,
        Some((&format!("{name} (now)"), &format!("{name} (migrated)"))),
    );
    write!(out, "\n{diff}")?;
    if args.dry_run {
        writeln!(
            out,
            "\nNothing was changed: `{COMMAND}` applies this after asking."
        )?;
        out.finish()?;
        return Ok(Code::Ok);
    }
    person()?;
    // The installed policy is pinned: re-pinning over drift would accept it unseen.
    let checkpoint = if installed {
        integrity::refuse_drift(&home, "migrate the policy")?;
        Some(integrity::Checkpoint::take(&home)?)
    } else {
        None
    };
    if !args.yes && !crate::commands::edit::confirm(&mut out, "\nApply this? [y/N] ")? {
        writeln!(out, "the policy was not changed")?;
        out.finish()?;
        return Ok(Code::Ok);
    }
    let backup = backup_of(&path);
    if let Some(checkpoint) = &checkpoint {
        checkpoint.verify(&home, &[])?;
        write_private(&backup, current.as_bytes())?;
        write_private(&path, migration.text.as_bytes())?;
        let binary = crate::install::hook_binary()?;
        let written = [path.clone()];
        let lock = integrity::repin_after(&home, &binary, HookPins::Keep, checkpoint, &written)?;
        writeln!(out, "✔ lock re-pinned ({} files)", lock.entries.len())?;
    } else {
        write_plain(&backup, &current)?;
        write_plain(&path, &migration.text)?;
        writeln!(
            out,
            "! a trusted repository policy needs `openmoat trust` again once it changes"
        )?;
    }
    writeln!(
        out,
        "✔ {} migrated; the previous file is in {}",
        paths.path(&path),
        paths.path(&backup)
    )?;
    out.finish()?;
    Ok(Code::Ok)
}

/// Where the file a migration replaces is kept.
fn backup_of(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".before-migrate");
    PathBuf::from(name)
}

/// A file outside OpenMoat's state directory, written as the person's editor
/// would: it keeps the access it has.
fn write_plain(path: &Path, text: &str) -> Result<()> {
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}

/// Refuse unless a person is at a terminal (AGENTS §7): writing the
/// installed policy re-pins the lock.
fn person() -> Result<()> {
    crate::terminal::refuse_agent(COMMAND)?;
    if !crate::terminal::interactive() {
        bail!(
            "`{COMMAND}` must be run by a person in a terminal, not from a hook or script; \
             `{COMMAND} --dry-run` shows the changes anywhere"
        );
    }
    Ok(())
}
