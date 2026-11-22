//! `openmoat init`'s two opt-in questions (ADR-106), asked after the agents'
//! and only of a person at a terminal: plant decoy keys, and start hook-only
//! agents in `openmoat run`'s sandbox. Each defaults to no (Enter, or the end
//! of input), names every file it would write, shows them with `d`, and is
//! undone by `openmoat uninstall`. A script, `--yes`, a dry run or a run with
//! no person over an existing lock is never asked and changes nothing here.

use std::io::Write as _;
use std::path::Path;

use anyhow::Result;
use openmoat_hosts::Host;

use crate::canary::{self, Offer};
use crate::cli::{Format, InitArgs};
use crate::home::{Home, user_home};
use crate::protection::os_sandbox::RunHere;
use crate::render::Deferred;
use crate::report::Paths;
use crate::start::{self, Shim, rc};

/// Whether `init` asks these questions: only of a person at a terminal, never
/// with `--yes`, `--hooks-only` or `--format json` (which prints no question),
/// nor with no person over an existing lock (`unattended`).
pub(super) fn asked(args: &InitArgs, unattended: bool) -> bool {
    !unattended
        && !args.yes
        && !args.hooks_only
        && args.format != Format::Json
        && crate::terminal::person_for("openmoat init")
}

/// Ask both questions and act on the answers; whether anything was written.
pub(super) fn ask(home: &Home, binary: &Path, hosts: &[Host], out: &mut Deferred) -> Result<bool> {
    let user = user_home()?;
    let paths = Paths::detect();
    let mut changed = decoys(home, &user, &paths, out)?;
    changed |= sandboxed_start(home, binary, hosts, (&user, &paths), out)?;
    Ok(changed)
}

/// The decoy keys' question, when there is somewhere to plant one.
fn decoys(home: &Home, user: &Path, paths: &Paths, out: &mut Deferred) -> Result<bool> {
    let mut record = canary::Record::load(home)?;
    let offers = canary::offers(&record, user);
    if offers.is_empty() {
        return Ok(false);
    }
    let files: Vec<String> = offers.iter().map(|o| paths.path(&o.file)).collect();
    let question = format!(
        "  Decoy keys       plant {} fake key file(s) ({}) so that any attempt to read or send \
         them is caught? No real file is touched  [y/N/d] ",
        offers.len(),
        files.join(", ")
    );
    if !yes(&question, out, |out| decoys_diff(&offers, paths, out))? {
        return Ok(false);
    }
    let planted = canary::plant(home, &mut record, &offers)?;
    let planted: Vec<String> = planted.iter().map(|p| paths.path(p)).collect();
    writeln!(
        out,
        "✔ decoy keys       {} planted: {}; reading or sending one is denied (rule canary)",
        planted.len(),
        planted.join(", ")
    )?;
    Ok(!planted.is_empty())
}

/// What `d` shows for the decoys: each new file whole. The values are fakes
/// made for this machine, so nothing real is shown.
fn decoys_diff(offers: &[Offer], paths: &Paths, out: &mut Deferred) -> Result<()> {
    for offer in offers {
        let sample = offer.target.content(&offer.target.values()?);
        writeln!(
            out,
            "--- {} (new file, {})",
            paths.path(&offer.file),
            offer.target.what
        )?;
        for line in sample.lines() {
            writeln!(out, "+ {line}")?;
        }
    }
    writeln!(
        out,
        "  (the random part of each key is drawn again when it is planted)"
    )?;
    Ok(())
}

/// The sandboxed-start question, when an agent set up here can start in
/// `openmoat run` and has no shim yet.
fn sandboxed_start(
    home: &Home,
    binary: &Path,
    hosts: &[Host],
    (user, paths): (&Path, &Paths),
    out: &mut Deferred,
) -> Result<bool> {
    let search = crate::environment::absolute_search_path();
    let shims = start::offers(home, binary, hosts, &search, &RunHere::detect())?;
    if shims.is_empty() {
        return Ok(false);
    }
    let dir = start::shim_dir(home);
    let shell = std::env::var("SHELL").ok();
    let rc_file = rc::file(user, shell.as_deref());
    let lines = rc::lines(&dir, user);
    let names: Vec<&str> = shims.iter().map(|s| s.name).collect();
    let writes = match &rc_file {
        Some(file) => format!(
            "writes {} shim(s) to {} and 2 lines to {}",
            shims.len(),
            paths.path(&dir),
            paths.path(file)
        ),
        None => format!(
            "writes {} shim(s) to {}; you add one line to your shell's start-up file",
            shims.len(),
            paths.path(&dir)
        ),
    };
    let question = format!(
        "  Sandboxed start  make typing {} start it in `openmoat run`'s sandbox? It {writes}  \
         [y/N/d] ",
        names.join(", ")
    );
    let shown = |out: &mut Deferred| start_diff(&shims, &dir, rc_file.as_deref(), &lines, out);
    if !yes(&question, out, shown)? {
        return Ok(false);
    }
    start::write(home, &shims)?;
    let Some(file) = rc_file else {
        writeln!(
            out,
            "! sandboxed start  shims in {}; add this line to your shell's start-up file, then \
             open a new shell: {}",
            paths.path(&dir),
            lines.lines().last().unwrap_or_default()
        )?;
        return Ok(true);
    };
    let mut record = start::Record::load(home)?;
    // Lines written by an earlier `init` stay where they are, one file only.
    let written = match &record.rc {
        Some(earlier) => Err(earlier.path.clone()),
        None => Ok(rc::add(home, &file, &lines)?),
    };
    let rc_note = match written {
        Ok(Some(written)) => {
            let backup = if written.created {
                "a new file".to_owned()
            } else {
                let backup = crate::install::backup_path(&file, crate::install::HOOK_BACKUP);
                format!("backup {}", paths.path(&backup))
            };
            record.rc = Some(written);
            record.save(home)?;
            format!("{} puts it first on PATH ({backup})", paths.path(&file))
        }
        Ok(None) => format!("{} already puts it first on PATH", paths.path(&file)),
        Err(earlier) => format!("{} already puts it first on PATH", paths.path(&earlier)),
    };
    writeln!(
        out,
        "✔ sandboxed start  {}: shims in {}; {rc_note}; open a new shell to use it",
        names.join(", "),
        paths.path(&dir)
    )?;
    Ok(true)
}

/// What `d` shows for sandboxed start: each shim whole, and the lines added
/// to the start-up file.
fn start_diff(
    shims: &[Shim],
    dir: &Path,
    rc_file: Option<&Path>,
    lines: &str,
    out: &mut Deferred,
) -> Result<()> {
    for shim in shims {
        writeln!(out, "--- {} (new file)", dir.join(shim.name).display())?;
        for line in shim.text.lines() {
            writeln!(out, "+ {line}")?;
        }
    }
    if let Some(file) = rc_file {
        write!(out, "{}", rc::diff(file, lines))?;
    }
    Ok(())
}

/// Ask `question` until it is answered; `d` runs `diff` and asks again. Only
/// `y` or `yes` is a yes: Enter, the end of input and anything else are no.
fn yes(
    question: &str,
    out: &mut Deferred,
    diff: impl Fn(&mut Deferred) -> Result<()>,
) -> Result<bool> {
    loop {
        write!(out, "{question}")?;
        out.flush()?;
        let answer = crate::terminal::read_answer()?;
        if answer.is_empty() {
            writeln!(out)?;
            return Ok(false);
        }
        match answer.trim().to_ascii_lowercase().as_str() {
            "d" | "diff" => diff(out)?,
            "y" | "yes" => return Ok(true),
            _ => return Ok(false),
        }
    }
}
