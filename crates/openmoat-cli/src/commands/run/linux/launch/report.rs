//! The launch report under bubblewrap (ADR-089). `openmoat isolated` starts
//! the agent inside, so it runs the check there and reports it on a Unix
//! socket in the session's private directory. The socket is bound before
//! bubblewrap starts and `openmoat isolated` connects before it starts the
//! agent, presenting a nonce only it was given (in its environment, removed
//! from the agent's), so a report is never the agent's own.
//!
//! The connection stays open for the reply: one byte, [`GO`] once the run
//! has the report on record and nothing is missing, anything else (another
//! byte, the connection closed, no reply in time) stops the agent and every
//! process it started. In the Lightweight tier's namespace there is no PID
//! namespace, so the agent would outlive a stopped bubblewrap; this way the
//! process that started it stops it. The run also stops bubblewrap's whole
//! tree itself ([`super::tree::stop`]), in case `openmoat isolated` cannot.

use std::io::{BufRead as _, BufReader, ErrorKind, Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use openmoat_core::boundary::LaunchCheck;

use super::tree;
use crate::guard_relay::random_hex;

/// The variable that carries the report's nonce to `openmoat isolated`.
pub const NONCE_ENV: &str = "MOAT_LAUNCH_NONCE";

/// How long either side waits for the other: the run for the report while
/// bubblewrap is still running, `openmoat isolated` for the reply. Past it the
/// agent is stopped rather than left unchecked.
pub const WAIT: Duration = Duration::from_secs(60);

/// The reply that lets the agent run on.
const GO: u8 = b'1';
/// The reply that stops it.
const STOP: u8 = b'0';

/// Outside: the socket `openmoat isolated` reports on, and its nonce.
pub struct Reports {
    listener: UnixListener,
    nonce: String,
    wait: Duration,
}

impl Reports {
    /// Bind `path` (in the session's private directory).
    pub fn bind(path: &Path) -> Result<Self> {
        let listener =
            UnixListener::bind(path).with_context(|| format!("listening on {}", path.display()))?;
        listener.set_nonblocking(true)?;
        let nonce = random_hex(16)?.as_str().to_owned();
        Ok(Self {
            listener,
            nonce,
            wait: WAIT,
        })
    }

    /// Start bubblewrap's `command` with the nonce, wait for the report, give
    /// it to `on_launch`, reply, and wait for bubblewrap. A report that does
    /// not come or cannot be read is a failure `on_launch` records; an error
    /// from `on_launch` replies [`STOP`] and stops bubblewrap's whole tree.
    pub fn start(
        self,
        mut command: Command,
        on_launch: impl FnOnce(Option<LaunchCheck>) -> Result<()>,
    ) -> Result<ExitStatus> {
        command.env(NONCE_ENV, &self.nonce);
        let mut child = command.spawn().context("starting bubblewrap")?;
        let (check, stream) = match self.receive(&mut child) {
            Ok(Some((check, stream))) => (Some(check), Some(stream)),
            Ok(None) => (None, None),
            Err(error) => (
                Some(LaunchCheck {
                    in_bubblewrap: true,
                    failure: Some(format!("{error:#}")),
                    ..LaunchCheck::default()
                }),
                None,
            ),
        };
        let verdict = on_launch(check);
        if let Some(mut stream) = stream {
            let reply = if verdict.is_ok() { GO } else { STOP };
            // A reply that cannot be sent closes the connection, which stops
            // the agent inside as well.
            let _ = stream.write_all(&[reply]);
        }
        if let Err(error) = verdict {
            tree::stop(&mut child);
            return Err(error);
        }
        child.wait().context("waiting for bubblewrap")
    }

    /// The first report that carries the nonce, with its connection for the
    /// reply; `None` when bubblewrap exits before `openmoat isolated` connects
    /// (it never started the agent).
    fn receive(&self, child: &mut Child) -> Result<Option<(LaunchCheck, UnixStream)>> {
        let deadline = Instant::now() + self.wait;
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if let Some(check) = self.read(&stream)? {
                        return Ok(Some((check, stream)));
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if child.try_wait()?.is_some() {
                        // It may have reported between the two calls.
                        let Ok((stream, _)) = self.listener.accept() else {
                            return Ok(None);
                        };
                        return Ok(self.read(&stream)?.map(|check| (check, stream)));
                    }
                    if Instant::now() > deadline {
                        bail!("`openmoat isolated` did not report the agent's start");
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                // A signal interrupted the call; the wait goes on.
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error).context("accepting the launch report"),
            }
        }
    }

    /// The report on `stream`, or `None` for a connection without the nonce.
    /// What the report says is checked here again: its gaps are found from
    /// its own fields, not taken from its `failure`.
    fn read(&self, stream: &UnixStream) -> Result<Option<LaunchCheck>> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(self.wait))?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line)?;
        let Some((nonce, json)) = line.trim_end().split_once(' ') else {
            bail!("`openmoat isolated` ended before it reported the agent's start");
        };
        if nonce != self.nonce {
            return Ok(None);
        }
        let mut check: LaunchCheck = serde_json::from_str(json)?;
        check.in_bubblewrap = true;
        check.failure = check.linux_failure();
        Ok(Some(check))
    }
}

/// Inside: connect to the report socket before the agent starts; once it
/// has, send the check with the nonce and wait for the reply. Anything but
/// [`GO`] is an error, on which the caller stops the agent.
pub fn reporter(path: &Path) -> Result<impl FnOnce(Option<LaunchCheck>) -> Result<()>> {
    let nonce = std::env::var(NONCE_ENV).context("no launch nonce from `openmoat run`")?;
    let stream =
        UnixStream::connect(path).with_context(|| format!("connecting to {}", path.display()))?;
    Ok(
        move |check: Option<LaunchCheck>| {
            exchange(stream, &nonce, &check.unwrap_or_default(), WAIT)
        },
    )
}

/// Send `check` on `stream` and read the reply within `wait`.
fn exchange(
    mut stream: UnixStream,
    nonce: &str,
    check: &LaunchCheck,
    wait: Duration,
) -> Result<()> {
    let json = serde_json::to_string(check)?;
    writeln!(stream, "{nonce} {json}").context("reporting the agent's start")?;
    let deadline = std::time::Instant::now() + wait;
    let mut reply = [0u8; 1];
    loop {
        // A signal (the agent's own SIGCHLD, a terminal resize) interrupts the
        // read without ending the wait: read again for the time that is left.
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            bail!("`openmoat run` did not reply in time, so the agent is stopped");
        }
        stream.set_read_timeout(Some(left))?;
        match stream.read(&mut reply) {
            Ok(1) if reply[0] == GO => return Ok(()),
            Ok(1) => {
                bail!("`openmoat run` could not keep the run on record and stops the agent")
            }
            Ok(_) => bail!("`openmoat run` ended without a reply, so the agent is stopped"),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(error)
                    .context("waiting for `openmoat run`'s reply; the agent is stopped");
            }
        }
    }
}

#[cfg(test)]
mod tests;
