//! `moat run` where OpenMoat cannot generate a Lightweight sandbox: refused, never
//! run unconfined.

use std::path::Path;
use std::process::{Command, ExitStatus};

use anyhow::{Result, bail};
use openmoat_core::{EvalContext, Policy};

use crate::cli::IsolatedArgs;
use crate::exit::Code;
use crate::sandbox::{Grants, Report};

/// Never constructed.
pub enum Confined {}

pub fn confine(_: &Policy, _: &EvalContext, _: Grants, _: &Path, _: &Path) -> Result<Confined> {
    bail!(
        "`openmoat run` needs an operating-system sandbox OpenMoat can generate (Seatbelt on macOS, \
         Landlock on Linux); there is none on {}. Use the Standard tier: `openmoat init` \
         configures the agent's own sandbox",
        std::env::consts::OS
    )
}

pub fn isolate(_: &Policy, _: &EvalContext, _: Grants, _: &Path, _: &Path) -> Result<Confined> {
    bail!(
        "`openmoat run --isolate` runs on Linux only (bubblewrap); there is no Isolated tier on {}",
        std::env::consts::OS
    )
}

pub fn inside(_: &IsolatedArgs) -> Result<Code> {
    bail!("only `openmoat run --isolate` on Linux starts this")
}

/// None: `moat run` refuses here.
pub fn port_only_network() -> Option<String> {
    None
}

/// None: `moat run` refuses here.
pub fn terminals() -> Vec<String> {
    Vec::new()
}

impl Confined {
    pub fn command(&mut self) -> &mut Command {
        match *self {}
    }

    pub fn report(&self) -> &Report {
        match *self {}
    }

    pub fn warning(&self) -> Option<&str> {
        match *self {}
    }

    pub fn status(self) -> Result<ExitStatus> {
        match self {}
    }
}
