//! Whether a person is at the keyboard.
//!
//! `moat allow`, `moat doctor --accept` and the other human-only commands
//! widen or re-pin the policy, so they refuse to run unless stdin is a
//! terminal (hooks and scripts never have one) and no agent started them
//! ([`refuse_agent`]): an agent can give a command a terminal through a pty
//! wrapper, but it cannot remove itself from the command's ancestors. Their
//! answers are read from the controlling terminal ([`read_answer`]).

mod ancestry;
mod own_binary;

use std::io::{self, BufRead as _, IsTerminal as _};

use anyhow::{Result, bail};

/// Debug builds honour `MOAT_ASSUME_TTY=1` so end-to-end tests can drive the
/// terminal-only commands. Release builds (`cargo install`, distributed
/// binaries) do not contain this check at all.
#[cfg(debug_assertions)]
const ASSUME_TTY: &str = "MOAT_ASSUME_TTY";

/// Whether `MOAT_ASSUME_TTY=1` stands in for a person; always false in a
/// release build.
fn assumed() -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os(ASSUME_TTY).is_some_and(|v| v == "1") {
        static NOTED: std::sync::Once = std::sync::Once::new();
        NOTED.call_once(|| eprintln!("moat: {ASSUME_TTY}=1 honoured (debug build only)"));
        return true;
    }
    false
}

pub fn interactive() -> bool {
    assumed() || std::io::stdin().is_terminal()
}

/// Whether a person, not an agent, is at the terminal: what the home screen
/// needs before it offers to approve or accept anything.
pub fn person() -> bool {
    interactive() && refuse_agent("openmoat").is_ok()
}

/// Refuse `command` when an agent host (`ancestry::AGENTS`, a Cursor editor
/// helper on macOS) or `moat run` is among the processes that started this one, or when they
/// cannot be read. Windows is not checked yet: there only the terminal check
/// applies. Every command but `openmoat init` also refuses to run from an
/// executable other than the one the policy lock records (`own_binary.rs`).
pub fn refuse_agent(command: &str) -> Result<()> {
    if assumed() {
        return Ok(());
    }
    if command != "openmoat init" {
        own_binary::refuse_copy(command)?;
    }
    match ancestry::agent_ancestor() {
        Ok(None) => Ok(()),
        Ok(Some(agent)) => bail!(
            "`{command}` must be run by a person, not by an agent: it was started from \
             `{agent}`. Run it in a terminal of your own"
        ),
        Err(error) => bail!(
            "`{command}` must be run by a person, and the programs that started it cannot \
             be checked ({error}). Run it in a terminal of your own"
        ),
    }
}

/// One line typed at the controlling terminal (`/dev/tty`), so an answer
/// cannot come from whatever stdin was handed; end of input, or no controlling
/// terminal, reads as an empty line. Under `MOAT_ASSUME_TTY=1` (debug builds)
/// and on Windows the line comes from stdin.
pub fn read_answer() -> io::Result<String> {
    let mut line = String::new();
    if assumed() || cfg!(windows) {
        io::stdin().lock().read_line(&mut line)?;
        return Ok(line);
    }
    match std::fs::File::open("/dev/tty") {
        Ok(tty) => {
            io::BufReader::new(tty).read_line(&mut line)?;
        }
        Err(error) => eprintln!("moat: no controlling terminal to read the answer from: {error}"),
    }
    Ok(line)
}
