//! Bound the shutdown of a stdio upstream after either pipe stops.

use std::io;
use std::process::{Child, ExitStatus};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};

#[cfg(unix)]
#[path = "process/unix.rs"]
mod platform;
#[cfg(not(unix))]
#[path = "process/other.rs"]
mod platform;

pub(super) use platform::own;

const GRACE: Duration = Duration::from_secs(1);

pub(super) enum Pump {
    Host(Result<()>),
    Server(Result<()>),
}

/// Reap the upstream whether the byte pumps finish cleanly or time out.
pub(super) fn supervise(mut child: Child, finished: &Receiver<Pump>) -> Result<ExitStatus> {
    let result = drain(finished).and_then(|()| wait(&mut child));
    if result.is_err() {
        platform::stop(&mut child);
        child.wait().context("reaping the stopped MCP server")?;
    }
    result
}

fn drain(finished: &Receiver<Pump>) -> Result<()> {
    let mut next = finished
        .recv()
        .context("MCP relay stopped without reporting its result")?;
    loop {
        match next {
            Pump::Server(result) => return result,
            Pump::Host(result) => result?,
        }
        next = match finished.recv_timeout(GRACE) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => {
                bail!("MCP server did not close its output after client EOF")
            }
            Err(error) => {
                return Err(error).context("MCP server pump stopped without reporting its result");
            }
        };
    }
}

fn wait(child: &mut Child) -> Result<ExitStatus> {
    let deadline = Instant::now() + GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => bail!("MCP server did not exit after closing its output"),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error).context("waiting for the MCP server"),
        }
    }
}
