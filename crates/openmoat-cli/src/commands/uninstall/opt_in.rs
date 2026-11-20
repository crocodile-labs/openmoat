//! `openmoat uninstall` for the opt-in choices of `openmoat init` (ADR-106):
//! each uninstalled agent's sandboxed-start shim, the `PATH` lines with the
//! last shim, and, when every agent is uninstalled, the decoy keys. Only what
//! is still as OpenMoat wrote it is deleted; anything changed since stays and
//! is named.

use std::io::Write as _;
use std::path::PathBuf;

use anyhow::Result;
use openmoat_hosts::Host;

use crate::canary::{self, Removed as Decoy};
use crate::home::{Home, user_home};
use crate::render::Deferred;
use crate::start::{self, Removed as Shim};

/// What the lock must forget, and the state files it must pin again.
#[derive(Debug, Default)]
pub(super) struct Undone {
    pub deleted: Vec<PathBuf>,
    pub rewritten: Vec<PathBuf>,
}

/// Undo the choices for `hosts`; the decoys too when `every_agent`.
pub(super) fn undo(
    home: &Home,
    hosts: &[Host],
    every_agent: bool,
    out: &mut Deferred,
) -> Result<Undone> {
    let mut undone = Undone::default();
    let (shims, rc) = start::remove(home, hosts)?;
    for shim in shims {
        match shim {
            Shim::Deleted(path) => {
                writeln!(out, "✔ sandboxed start  {} deleted", path.display())?;
                undone.deleted.push(path);
            }
            Shim::Changed(path) => writeln!(
                out,
                "! sandboxed start  {} kept: it changed since `openmoat init` wrote it",
                path.display()
            )?,
        }
    }
    if let Some(rc) = rc {
        writeln!(out, "✔ sandboxed start  {rc}")?;
    }
    if every_agent {
        for (path, removed) in canary::remove(home, &user_home()?)? {
            let line = match removed {
                Decoy::Deleted => format!("✔ decoy key        {} deleted", path.display()),
                Decoy::Changed => format!(
                    "! decoy key        {} kept: it changed since `openmoat init` planted it",
                    path.display()
                ),
                Decoy::Gone => format!("· decoy key        {} was gone already", path.display()),
            };
            writeln!(out, "{line}")?;
        }
    }
    undone.rewritten = [canary::record_path(home), start::record_path(home)]
        .into_iter()
        .filter(|p| p.is_file())
        .collect();
    Ok(undone)
}
