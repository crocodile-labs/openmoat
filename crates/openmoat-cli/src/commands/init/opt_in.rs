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
use crate::start::{self, enable, rc};

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

/// The sandboxed-start questions, one per agent set up here that can start
/// in `openmoat run` and has no shim yet (ADR-108 §8): each shows the
/// protection score it has and would have, and only `y` turns it on.
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
    let writes = match rc::file(user, shell.as_deref()) {
        Some(file) => format!(
            "a yes writes a shim to {} and, once, 2 lines to {}",
            paths.path(&dir),
            paths.path(&file)
        ),
        None => format!(
            "a yes writes a shim to {}; you add one line to your shell's start-up file",
            paths.path(&dir)
        ),
    };
    writeln!(
        out,
        "  Sandboxed start  these agents run with the hook only: an allowed call runs with your \
         permissions, so a classifier mistake is a bypass. `openmoat run` confines them; {writes}"
    )?;
    let score = crate::commands::run_default_score();
    let mut chosen = Vec::new();
    for shim in shims {
        let question = format!(
            "  {:<16} {}: {}?  [y/N/d] ",
            shim.host.display_name(),
            enable::score_change(score),
            enable::what_starts(&shim)
        );
        let one = std::slice::from_ref(&shim);
        if yes(&question, out, |out| enable::diff(home, one, user, out))? {
            chosen.push(shim);
        }
    }
    if chosen.is_empty() {
        writeln!(
            out,
            "  sandboxed start  not set up; `openmoat confine <agent>` turns it on later, and \
             `openmoat status` shows the command that starts each agent confined"
        )?;
        return Ok(false);
    }
    enable::enable(home, &chosen, (user, paths), out)?;
    Ok(true)
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
