//! `openmoat gate setup`, `status` and `remove`: the possession factor on
//! every loosening (ADR-117, `crate::gate`).

use std::io::Write as _;

use anyhow::{Context as _, Result, bail};

use crate::exit::Code;
use crate::gate::{self, Enrolment};
use crate::home::Home;
use crate::render::Deferred;

/// The checks `setup` and `remove` make first; the state directory.
fn person(command: &str) -> Result<Home> {
    crate::terminal::refuse_agent(command)?;
    if !crate::terminal::interactive() {
        bail!("`{command}` must be run by a person in a terminal, not from a hook or script");
    }
    let home = Home::locate()?;
    home.require_exists()?;
    Ok(home)
}

pub fn setup() -> Result<Code> {
    let home = person("openmoat gate setup")?;
    if gate::enrolled(&home) {
        bail!(
            "the gate is set up already ({}): to move it to another app, run `openmoat gate \
             remove`, which asks for a code of this one, then `openmoat gate setup` again",
            gate::path(&home).display()
        );
    }
    let enrolment = Enrolment::new()?;
    let mut out = Deferred::default();
    writeln!(
        out,
        "Add this account to your authenticator app (any app that takes TOTP codes: SHA-1, \
         6 digits, 30 seconds).\nOpen the link, or a QR code of it, on your phone:\n\n  {}\n\n\
         or type the key by hand:\n\n  {}\n\nIt is shown only now: OpenMoat never prints it \
         again. Keep the app's copy; without it, a loosening can no longer be confirmed. Clear \
         your terminal's scrollback after this.",
        enrolment.uri().as_str(),
        enrolment.text().as_str()
    )?;
    write!(out, "\nCode the app shows now: ")?;
    out.flush()?;
    let typed = crate::terminal::read_answer().context("reading the code")?;
    enrolment.confirm(&home, &typed)?;
    writeln!(
        out,
        "✔ gate on: `openmoat allow`, `trust`, `edit`, `doctor --accept` and every other command \
         that widens or re-pins now ask for a code too ({})",
        gate::path(&home).display()
    )?;
    out.finish()?;
    Ok(Code::Ok)
}

pub fn status() -> Result<Code> {
    let home = Home::locate()?;
    let (on, failures) = gate::status(&home)?;
    let mut out = Deferred::default();
    if on {
        writeln!(
            out,
            "✔ gate on: every command that widens or re-pins asks for a code from your \
             authenticator app"
        )?;
        writeln!(
            out,
            "  {failures} of {} wrong codes counted in the last {} minutes",
            gate::MAX_FAILURES,
            gate::WINDOW_MS / 60_000
        )?;
    } else {
        writeln!(
            out,
            "· gate off: commands that widen or re-pin need a person at a terminal only; \
             `openmoat gate setup` adds a code from your authenticator app"
        )?;
    }
    writeln!(
        out,
        "  each loosening is recorded: `openmoat show --session {}`",
        gate::SESSION
    )?;
    out.finish()?;
    Ok(Code::Ok)
}

pub fn remove() -> Result<Code> {
    let home = person("openmoat gate remove")?;
    let mut out = Deferred::default();
    if !gate::enrolled(&home) {
        writeln!(out, "· the gate is not set up; nothing to remove")?;
        out.finish()?;
        return Ok(Code::Ok);
    }
    let pass = gate::pass(&home, "openmoat gate remove")?;
    gate::remove(&home)?;
    pass.record(&home, "possession factor removed", &[]);
    writeln!(
        out,
        "✔ gate off: commands that widen or re-pin need a person at a terminal only. Remove \
         OpenMoat's account from your authenticator app"
    )?;
    out.finish()?;
    Ok(Code::Ok)
}
