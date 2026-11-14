//! `openmoat approvals install` / `uninstall`: keep `openmoat approvals
//! listen` running after the terminal closes, as a launchd user agent (macOS)
//! or a systemd user unit (Linux) started at login and restarted when it
//! fails (ADR-094). The same service code as `openmoat proxy install`
//! ([`crate::commands::service`]); Windows is refused.

use std::io::Write as _;

use anyhow::Result;

use super::{connected, person, store};
use crate::commands::service::{self, APPROVALS};
use crate::exit::Code;
use crate::render::Deferred;

/// `openmoat approvals install`: a person at a terminal, with a channel
/// connected, writes and starts the listener's service.
pub fn install() -> Result<Code> {
    person(APPROVALS.install)?;
    let (home, store) = store()?;
    // A service with nothing to listen to would only wait; say so now.
    connected(&store)?;
    let binary = crate::install::hook_binary()?;
    let manager = service::manager(&home, &APPROVALS)?;
    let path = manager.install(&binary, home.root())?;
    let mut out = Deferred::default();
    writeln!(
        out,
        "✔ {} installed and started: {}",
        service::display_name(),
        path.display()
    )?;
    writeln!(
        out,
        "  `openmoat approvals listen` now runs at login, restarts when it fails, and logs \
         to {} (owner-only).",
        home.root().join("logs").join("approvals.err.log").display()
    )?;
    writeln!(
        out,
        "  `openmoat approvals status` reports it; `{}` removes it.",
        APPROVALS.uninstall
    )?;
    out.finish()?;
    Ok(Code::Ok)
}

/// `openmoat approvals uninstall`: stop and remove the listener's service.
pub fn uninstall() -> Result<Code> {
    person(APPROVALS.uninstall)?;
    let home = crate::home::Home::locate()?;
    let manager = service::manager(&home, &APPROVALS)?;
    let mut out = Deferred::default();
    match manager.uninstall()? {
        Some(path) => writeln!(
            out,
            "✔ {} removed: {}; answers arrive only while `openmoat approvals listen` runs",
            service::display_name(),
            path.display()
        )?,
        None => writeln!(out, "· {} was not installed", service::display_name())?,
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// The service's `status` and `doctor` lines: silent when not installed.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn lines(home: &crate::home::Home) -> Vec<(bool, String)> {
    service::lines::lines(home, &APPROVALS, "approvals service")
}

/// Windows: no service, so no line.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn lines(_home: &crate::home::Home) -> Vec<(bool, String)> {
    Vec::new()
}
