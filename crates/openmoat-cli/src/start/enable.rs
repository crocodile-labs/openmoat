//! Turning sandboxed start on for the agents a person chose, as `openmoat
//! init`'s question and `openmoat confine` both do: the shims, then the two
//! lines that put their directory first on `PATH` (ADR-106, ADR-108 §8).

use std::io::Write as _;
use std::path::Path;

use anyhow::Result;

use super::{Record, Shim, rc, shim_dir};
use crate::home::Home;
use crate::render::Deferred;
use crate::report::Paths;

/// `hook only 0/100 → openmoat run 85/100`: what the agent has today and what
/// `openmoat run`'s default tier would give it here (ADR-108 §2).
pub fn score_change(run: Option<u32>) -> String {
    match run {
        Some(points) => format!("hook only 0/100 → openmoat run {points}/100"),
        None => "hook only 0/100 → openmoat run".to_owned(),
    }
}

/// What typing the shim's command starts confined: the agent, or for a host
/// that serves a port its server alone (`openclaw gateway`).
pub fn what_starts(shim: &Shim) -> String {
    match shim.host.spec().run_listen {
        Some(listen) => match shim.host.spec().run {
            openmoat_hosts::RunFacts::Known { args, .. } if !args.is_empty() => format!(
                "typing `{} {}` starts {} confined; its other commands start as before",
                shim.name,
                args.join(" "),
                listen.what
            ),
            _ => format!("typing `{}` starts it confined", shim.name),
        },
        None => format!("typing `{}` starts it confined", shim.name),
    }
}

/// Write `shims`, and the `PATH` lines into the start-up file of the shell
/// `$SHELL` names once, after a backup; one line to `out` saying what was
/// written. The caller re-pins the lock.
pub fn enable(
    home: &Home,
    shims: &[Shim],
    (user, paths): (&Path, &Paths),
    out: &mut Deferred,
) -> Result<()> {
    let dir = shim_dir(home);
    let shell = std::env::var("SHELL").ok();
    let rc_file = rc::file(user, shell.as_deref());
    let lines = rc::lines(&dir, user);
    let names: Vec<&str> = shims.iter().map(|s| s.name).collect();
    super::write(home, shims)?;
    let Some(file) = rc_file else {
        writeln!(
            out,
            "! sandboxed start  shims in {}; add this line to your shell's start-up file, then \
             open a new shell: {}",
            paths.path(&dir),
            lines.lines().last().unwrap_or_default()
        )?;
        return Ok(());
    };
    let mut record = Record::load(home)?;
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
    Ok(())
}

/// What `d` shows for sandboxed start: each shim whole, and the lines added
/// to the start-up file.
pub fn diff(home: &Home, shims: &[Shim], user: &Path, out: &mut Deferred) -> Result<()> {
    let dir = shim_dir(home);
    for shim in shims {
        writeln!(out, "--- {} (new file)", dir.join(shim.name).display())?;
        for line in shim.text.lines() {
            writeln!(out, "+ {line}")?;
        }
    }
    let shell = std::env::var("SHELL").ok();
    if let Some(file) = rc::file(user, shell.as_deref())
        && Record::load(home)?.rc.is_none()
    {
        write!(out, "{}", rc::diff(&file, &rc::lines(&dir, user)))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_score_change_names_both_sides() {
        assert_eq!(
            score_change(Some(85)),
            "hook only 0/100 → openmoat run 85/100"
        );
        assert_eq!(score_change(None), "hook only 0/100 → openmoat run");
    }
}
