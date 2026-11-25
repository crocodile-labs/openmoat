//! `openmoat agent-account setup`, `status` and `remove` (ADR-129): the
//! local account `openmoat run` starts the agent as on Windows. Setup and
//! remove change the machine for every later run, so they take what every
//! widening takes: a person at an interactive terminal, the code gate when it
//! is set up (ADR-117) and a row in the policy-change ledger; and, since they
//! create an account and change the sign-in screen's list, an administrator
//! terminal. On every other system each refuses with exit 64.

use anyhow::{Result, bail};

use crate::exit::Code;
use crate::home::Home;

#[cfg(windows)]
use super::run::windows::account as platform;

/// Elsewhere: `openmoat run` needs no account, so each command refuses.
#[cfg(not(windows))]
mod platform {
    use anyhow::{Result, bail};

    use crate::exit::Code;
    use crate::home::Home;

    /// What `openmoat agent-account` says on any other system.
    const NOT_WINDOWS: &str = "`openmoat agent-account` is for Windows: `openmoat run` here \
         needs no account, its sandbox holds reads and the network already (docs/SANDBOX.md)";

    pub fn supported() -> Result<()> {
        bail!("{NOT_WINDOWS}")
    }

    pub fn require_elevated(_: &str) -> Result<()> {
        supported()
    }

    pub fn setup(_: &Home) -> Result<Vec<String>> {
        supported().map(|()| Vec::new())
    }

    pub fn status(_: &Home) -> Result<Code> {
        supported().map(|()| Code::Ok)
    }

    pub fn remove(_: &Home) -> Result<Option<Vec<String>>> {
        supported().map(|()| None)
    }
}

/// The checks `setup` and `remove` make first, in this order: the system,
/// the person, the terminal, the administrator token; the state directory.
fn person(command: &str) -> Result<Home> {
    platform::supported()?;
    crate::terminal::refuse_agent(command)?;
    if !crate::terminal::interactive() {
        bail!("`{command}` must be run by a person in a terminal, not from a hook or script");
    }
    platform::require_elevated(command)?;
    let home = Home::locate()?;
    home.require_exists()?;
    Ok(home)
}

pub fn setup() -> Result<Code> {
    const COMMAND: &str = "openmoat agent-account setup";
    let home = person(COMMAND)?;
    let pass = crate::gate::pass(&home, COMMAND)?;
    let details = platform::setup(&home)?;
    pass.record(&home, "agent account set up (ADR-129)", &details);
    Ok(Code::Ok)
}

pub fn status() -> Result<Code> {
    platform::supported()?;
    platform::status(&Home::locate()?)
}

pub fn remove() -> Result<Code> {
    const COMMAND: &str = "openmoat agent-account remove";
    let home = person(COMMAND)?;
    let pass = crate::gate::pass(&home, COMMAND)?;
    if let Some(details) = platform::remove(&home)? {
        pass.record(&home, "agent account removed (ADR-129)", &details);
    }
    Ok(Code::Ok)
}
