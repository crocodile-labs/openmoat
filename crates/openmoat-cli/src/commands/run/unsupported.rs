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

/// None: `moat run` refuses here, so nothing starts to need a variable.
pub const BASE_ENV: &[&str] = &[];

/// Why `moat run` cannot sandbox here: there is no sandbox OpenMoat can generate.
#[expect(
    clippy::unnecessary_wraps,
    reason = "macOS and Linux decide at run time; every platform file shares the signature"
)]
pub fn unavailable() -> Option<String> {
    Some(format!(
        "`openmoat run` has no sandbox OpenMoat can generate on {}",
        std::env::consts::OS
    ))
}

/// None: Landlock is Linux's (ADR-082).
pub fn landlock() -> Option<crate::sandbox::landlock::abi::Kernel> {
    None
}

/// None: `moat run` refuses here.
pub fn port_only_network() -> Option<String> {
    None
}

/// None: [`unavailable`] already says why there is no boundary here.
pub fn no_network_namespace() -> Option<String> {
    None
}

/// No Isolated tier: `moat run` refuses here.
pub fn isolation() -> super::isolation::Offered {
    super::isolation::Offered::Not
}

/// None: `moat run` refuses here, so it has no Linux-only gap to name.
pub fn bubblewrap() -> Option<bool> {
    None
}

/// None: `moat run` refuses here, so nothing in a project is open to it.
pub fn project_open(_: &Policy, _: &EvalContext) -> Option<String> {
    None
}

/// `moat run` refuses here, so no wrapper is ever linked.
pub fn link_tool_shell(_: &Path, _: &Path) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// `moat run` refuses here.
#[expect(
    clippy::unnecessary_wraps,
    reason = "one signature on every platform: Linux's adds a Landlock layer, which can fail"
)]
pub fn seal_tool_shell() -> Result<()> {
    Ok(())
}

/// `moat run` refuses here, so the wrapper is never started.
pub fn exec_tool_shell(_: &mut Command) -> std::io::Error {
    std::io::ErrorKind::Unsupported.into()
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

    pub fn report_mut(&mut self) -> &mut Report {
        match *self {}
    }

    pub fn warning(&self) -> Option<&str> {
        match *self {}
    }

    pub fn project_notice(&self) -> Option<&str> {
        match *self {}
    }

    pub fn status(self) -> Result<ExitStatus> {
        match self {}
    }
}
