//! Platforms without a `moat proxy` service story yet. Windows is here:
//! Standard-tier proxy routing is not planned for the first release (#272),
//! so `moat proxy install` on Windows refuses with a clear message and the
//! user still has `moat proxy` to run the proxy in a terminal themselves.
//! There is never a service to report on or restart, so the stub has no
//! state: `moat proxy status` refuses, `moat doctor` and `moat sandbox sync`
//! say nothing about a service (`commands/proxy.rs`).

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use super::Manager;
use crate::home::{Home, user_home};

pub const DISPLAY: &str = "user service";

pub fn manager(_home: &Home) -> Result<Box<dyn Manager>> {
    // Resolve the user's home so the Windows branch mirrors the macOS/Linux
    // ones: no home means no story, surfaced as the error there instead of
    // later from inside a `Manager` call.
    let _ = user_home()?;
    Ok(Box::new(Unsupported))
}

struct Unsupported;

impl Manager for Unsupported {
    fn install(&self, _binary: &Path, _moat_home: &Path) -> Result<PathBuf> {
        bail!(
            "`openmoat proxy install` is not supported on {} yet (#272 defers Standard-tier \
             proxy routing on Windows); run `openmoat proxy` in a terminal to keep the proxy up",
            std::env::consts::OS
        )
    }

    fn uninstall(&self) -> Result<Option<PathBuf>> {
        Ok(None)
    }
}
