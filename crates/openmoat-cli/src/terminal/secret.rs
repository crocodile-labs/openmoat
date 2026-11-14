//! Reading a secret a person types or pastes, without showing it.
//!
//! [`read_secret`] reads one line from the controlling terminal with the
//! terminal's echo turned off, as a password prompt does, and puts the
//! terminal back as it was on every path out, a Ctrl-C included. It refuses
//! when stdin is not a terminal: a secret piped in would sit in a script or a
//! shell history, which is what `--credential-file` and its "delete the file
//! afterwards" are for. Nothing here prints what was read.

#[cfg(unix)]
mod unix;

#[cfg(all(test, unix))]
mod tests;

use std::io::{self, BufRead as _, IsTerminal as _, Write as _};

use anyhow::{Result, bail};
use zeroize::Zeroizing;

/// The longest secret line taken. A terminal in canonical mode holds at most
/// `MAX_CANON` bytes of one line (1024 on macOS); a longer paste is cut by the
/// terminal, so it is refused rather than stored cut.
pub const MAX_SECRET: usize = 1000;

/// Where a secret is read from, given whether `MOAT_ASSUME_TTY=1` stands in
/// for a person (debug builds) and whether stdin is a terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// The end-to-end tests' stdin, under `MOAT_ASSUME_TTY=1` only.
    Stdin,
    /// The controlling terminal, echo off.
    Terminal,
    /// Not read at all: stdin is a pipe or a file.
    Refused,
}

fn source(assumed: bool, stdin_terminal: bool) -> Source {
    if assumed {
        Source::Stdin
    } else if stdin_terminal {
        Source::Terminal
    } else {
        Source::Refused
    }
}

/// One secret line typed after `ask`, without its line end, never echoed.
pub fn read_secret(ask: &str) -> Result<Zeroizing<String>> {
    match source(super::assumed(), io::stdin().is_terminal()) {
        Source::Refused => bail!(
            "a secret is read only from a terminal, never from piped input; give it as a \
             file instead"
        ),
        Source::Stdin => {
            eprint!("{ask}");
            io::stderr().flush()?;
            let mut line = Zeroizing::new(String::new());
            io::stdin().lock().read_line(&mut line)?;
            finish(line.as_bytes())
        }
        Source::Terminal => from_terminal(ask),
    }
}

#[cfg(unix)]
fn from_terminal(ask: &str) -> Result<Zeroizing<String>> {
    use anyhow::Context as _;

    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("opening the controlling terminal to read the secret")?;
    eprint!("{ask}");
    io::stderr().flush()?;
    let line = unix::read_hidden(&tty)?;
    finish(&line)
}

/// Windows has no terminal echo control here (its console modes are Win32
/// calls this crate does not make), and a secret is never read with echo on.
#[cfg(not(unix))]
fn from_terminal(_ask: &str) -> Result<Zeroizing<String>> {
    bail!(
        "on {} a secret cannot be typed without showing it; give it as a file instead",
        std::env::consts::OS
    )
}

/// The line `raw` as text, its line end and surrounding blanks removed;
/// refused when empty, too long or not UTF-8. Errors never show it.
fn finish(raw: &[u8]) -> Result<Zeroizing<String>> {
    let Ok(text) = std::str::from_utf8(raw) else {
        bail!("the secret is not text; nothing was saved");
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        bail!("no secret was given; nothing was saved");
    }
    if trimmed.len() > MAX_SECRET {
        bail!("the secret is longer than {MAX_SECRET} bytes; give it as a file instead");
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
}
