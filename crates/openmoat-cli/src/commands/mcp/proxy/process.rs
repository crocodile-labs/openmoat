//! Bound the shutdown of a stdio server after either side of the relay stops.
//!
//! The agent closing the proxy's input closes the server's; a server that
//! does not then close its output and exit within [`GRACE`] is asked to stop
//! (`SIGTERM` to its process group on Unix) and, [`TERM_GRACE`] later,
//! killed. The same happens at once when the server's output can no longer be
//! relayed: a server still running would wait on a host that hears nothing
//! more from it.

use std::io;
use std::process::{Child, ExitStatus};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};

#[cfg(not(unix))]
mod other;
#[cfg(unix)]
mod unix;

#[cfg(not(unix))]
use other as platform;
#[cfg(unix)]
use unix as platform;

pub(super) use platform::own;

/// How long the server has to close its output once the agent closed its
/// input, and to exit once its output closed. A server started under
/// `openmoat run` exits through its sandbox and the run's proxy teardown, which
/// on a busy machine takes more than a second; a server that ignores its
/// closed input is still stopped within seconds.
const GRACE: Duration = Duration::from_secs(5);

/// How long a server asked to stop has before it is killed.
const TERM_GRACE: Duration = Duration::from_secs(5);

/// A side of the relay that finished.
pub(super) enum Pump {
    /// The agent closed the proxy's input (an error is already noted).
    Host,
    /// The server's output closed, or could not be relayed.
    Server(Result<()>),
}

/// Reap the server whether the relay finishes cleanly or it has to be
/// stopped; whether it exited successfully on its own. Why it was stopped
/// goes to `note`; a stopped server is a failed one (exit 1, as when it exits
/// non-zero), whatever its status.
pub(super) fn supervise(
    mut child: Child,
    finished: &Receiver<Pump>,
    note: fn(&str),
) -> Result<bool> {
    let ended = drain(finished, GRACE).and_then(|()| match wait(&mut child, GRACE)? {
        Some(status) => Ok(status),
        None => bail!("the MCP server did not exit after closing its output"),
    });
    match ended {
        Ok(status) => Ok(status.success()),
        Err(why) => {
            note(&format!("{why:#}; stopping it"));
            stop(&mut child, TERM_GRACE)?;
            Ok(false)
        }
    }
}

/// Until the server's side finishes: once the host's side has, for at most
/// `grace`.
fn drain(finished: &Receiver<Pump>, grace: Duration) -> Result<()> {
    let mut next = finished
        .recv()
        .context("the MCP relay stopped without reporting its result")?;
    loop {
        if let Pump::Server(result) = next {
            return result;
        }
        next = match finished.recv_timeout(grace) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => {
                bail!("the MCP server did not close its output after the agent closed its input")
            }
            Err(error) => {
                return Err(error)
                    .context("the MCP server's side stopped without reporting its result");
            }
        };
    }
}

/// The server's exit status once it exits within `within`; `None` if it
/// is still running then.
fn wait(child: &mut Child, within: Duration) -> Result<Option<ExitStatus>> {
    let deadline = Instant::now() + within;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error).context("waiting for the MCP server"),
        }
    }
}

/// Ask the server to stop, kill it if it is still running `grace` later, and
/// reap it; its exit status.
fn stop(child: &mut Child, grace: Duration) -> Result<ExitStatus> {
    platform::terminate(child);
    if let Some(status) = wait(child, grace)? {
        return Ok(status);
    }
    platform::kill(child);
    child.wait().context("reaping the stopped MCP server")
}

#[cfg(all(test, unix))]
mod tests;
