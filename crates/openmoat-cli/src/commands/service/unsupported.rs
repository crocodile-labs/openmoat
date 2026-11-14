//! Platforms without a user-service story yet. Windows is here: Standard-tier
//! proxy routing is not planned for the first release (#272), and the
//! approvals listener has no Windows service either (ADR-094), so `openmoat
//! proxy install` and `openmoat approvals install` refuse with a clear message;
//! the user still has `openmoat proxy` and `openmoat approvals listen` to run
//! in a terminal themselves. There is never a service to report on or
//! restart, so the stub has no state: `moat proxy status` refuses, `moat
//! doctor` and `moat sandbox sync` say nothing about a service
//! (`commands/proxy.rs`).

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use super::{Job, Manager};
use crate::home::{Home, user_home};

pub const DISPLAY: &str = "user service";

pub fn manager(_home: &Home, job: &'static Job) -> Result<Box<dyn Manager>> {
    // Resolve the user's home so the Windows branch mirrors the macOS/Linux
    // ones: no home means no story, surfaced as the error there instead of
    // later from inside a `Manager` call.
    let _ = user_home()?;
    Ok(Box::new(Unsupported { job }))
}

struct Unsupported {
    job: &'static Job,
}

impl Manager for Unsupported {
    fn install(&self, _binary: &Path, _moat_home: &Path) -> Result<PathBuf> {
        bail!(
            "`{}` is not supported on {} yet; run `openmoat {}` in a terminal to keep {} up",
            self.job.install,
            std::env::consts::OS,
            self.job.terminal,
            self.job.noun
        )
    }

    fn uninstall(&self) -> Result<Option<PathBuf>> {
        Ok(None)
    }
}
