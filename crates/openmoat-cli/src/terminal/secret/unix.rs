//! The terminal side of [`super::read_secret`] on Unix: echo off through
//! `termios`, one line read, the terminal's own settings put back.
//!
//! Ctrl-C would kill the process with echo still off and leave the person's
//! shell typing blind, so while the secret is read the interrupt key does not
//! send a signal: it ends the line instead (the terminal's extra end-of-line
//! character, `VEOL`, is set to it) and the read is cancelled.

use std::fs::File;
use std::io::{ErrorKind, Read as _, Write as _};

use anyhow::{Context as _, Result, bail};
use rustix::termios::{
    LocalModes, OptionalActions, SpecialCodeIndex, Termios, tcgetattr, tcsetattr,
};
use zeroize::Zeroizing;

/// The most bytes read before giving up on a line end: past
/// [`super::MAX_SECRET`], so a longer paste is refused, not cut.
const READ_CAP: usize = 4 * super::MAX_SECRET;

/// The terminal's settings as found, put back when dropped.
struct Restore<'a> {
    tty: &'a File,
    saved: Termios,
}

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        let _ = tcsetattr(self.tty, OptionalActions::Now, &self.saved);
    }
}

/// `saved` with echo off for one hidden line: typed characters are not shown,
/// the Enter still moves to the next line, and the interrupt key ends the
/// line instead of signalling (when the terminal has one). The interrupt
/// character, when it ends lines now.
fn hidden(saved: &Termios) -> (Termios, Option<u8>) {
    let mut hidden = saved.clone();
    hidden.local_modes.remove(LocalModes::ECHO);
    hidden.local_modes.insert(LocalModes::ECHONL);
    let interrupt = saved.special_codes[SpecialCodeIndex::VINTR];
    // An unused `VEOL` holds the terminal's "disabled" value; an interrupt key
    // set to that value means there is none to catch.
    if interrupt == saved.special_codes[SpecialCodeIndex::VEOL] {
        return (hidden, None);
    }
    hidden.local_modes.remove(LocalModes::ISIG);
    hidden.special_codes[SpecialCodeIndex::VEOL] = interrupt;
    (hidden, Some(interrupt))
}

/// One line from `tty`, its characters never echoed, without its line end.
pub fn read_hidden(tty: &File) -> Result<Zeroizing<Vec<u8>>> {
    let saved = tcgetattr(tty).context("the controlling terminal is not a terminal")?;
    let (settings, interrupt) = hidden(&saved);
    let restore = Restore { tty, saved };
    tcsetattr(tty, OptionalActions::Now, &settings).context("turning the terminal's echo off")?;
    let mut line = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; 256]);
    let mut reader = tty;
    loop {
        let n = match reader.read(chunk.as_mut()) {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("reading the secret from the terminal"),
        };
        line.extend_from_slice(&chunk[..n]);
        let last = line.last().copied();
        if n == 0 || last == Some(b'\n') || last == interrupt || line.len() > READ_CAP {
            break;
        }
    }
    drop(restore);
    if interrupt.is_some() && line.last().copied() == interrupt {
        // The line end the cancelled read did not echo.
        let _ = (&mut reader).write_all(b"\n");
        bail!("cancelled; nothing was saved");
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    Ok(line)
}
