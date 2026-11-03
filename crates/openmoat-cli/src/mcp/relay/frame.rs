//! Lines in and out of the relay: the stdio transport's framing.
//!
//! A message is one line ended by `\n`; a `\r` before it is dropped, and a
//! last line without one still counts. What the relay sends on is a line it
//! wrote itself (`Value::to_string` holds no raw newline or carriage return),
//! so where the reader at the other end splits lines does not matter.

use std::io::{BufRead, Write};
use std::sync::{Mutex, PoisonError};

use anyhow::{Context as _, Result, bail};

use super::{Relay, Routed};

/// A line longer than this ends the session: the relay would have to hold it
/// whole to read it.
const MAX_LINE: u64 = 64 * 1024 * 1024;

/// Read one line; `None` at the end of input.
fn read_line(input: &mut impl BufRead) -> Result<Option<String>> {
    let mut bytes = Vec::new();
    let read = std::io::Read::take(&mut *input, MAX_LINE + 1)
        .read_until(b'\n', &mut bytes)
        .context("reading a message")?;
    if read == 0 {
        return Ok(None);
    }
    if bytes.len() as u64 > MAX_LINE {
        bail!("a message is longer than {} MiB", MAX_LINE / (1024 * 1024));
    }
    while bytes.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        bytes.pop();
    }
    // Bytes that are not UTF-8 become U+FFFD, and the relay checks and sends
    // on that text, never the bytes it could not read.
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

/// Write `line` to `out`; an error once `out` is closed.
fn send<W: Write>(out: &Mutex<Option<W>>, line: &str) -> Result<()> {
    let mut out = out.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(out) = out.as_mut() else {
        bail!("the pipe is closed");
    };
    out.write_all(line.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// Send what `relay` made of one line where it goes; `note` gets why anything
/// was dropped.
fn route<S: Write, H: Write>(
    routed: Vec<Routed>,
    server: &Mutex<Option<S>>,
    host: &Mutex<Option<H>>,
    note: &(dyn Fn(&str) + Sync),
) -> Result<()> {
    for routed in routed {
        match routed {
            Routed::Server(text) => send(server, &text).context("writing to the MCP server")?,
            Routed::Host(text) => send(host, &text).context("writing to the agent")?,
            Routed::Dropped(why) => note(&why),
        }
    }
    Ok(())
}

/// Relay the host's messages from `input` until it ends: to `server`, or
/// answered on `host`.
pub fn pump_host<S: Write, H: Write>(
    relay: &Relay,
    mut input: impl BufRead,
    server: &Mutex<Option<S>>,
    host: &Mutex<Option<H>>,
    note: &(dyn Fn(&str) + Sync),
) -> Result<()> {
    while let Some(line) = read_line(&mut input)? {
        route(relay.host_line(&line), server, host, note)?;
    }
    Ok(())
}

/// Answer each request the host sends on `input` with error `REFUSED` and
/// `message`, until it ends: what the proxy does in place of a server it may
/// not start, so the agent shows why. Notifications and lines that are not a
/// request get no answer, as a server gives none.
pub fn refuse_all<H: Write>(
    mut input: impl BufRead,
    host: &Mutex<Option<H>>,
    message: &str,
) -> Result<()> {
    while let Some(line) = read_line(&mut input)? {
        let Ok(serde_json::Value::Object(request)) = serde_json::from_str(&line) else {
            continue;
        };
        let (Some(id), true) = (request.get("id"), request.contains_key("method")) else {
            continue;
        };
        if id.is_null() {
            continue;
        }
        send(host, &super::error(id, super::REFUSED, message).to_string())
            .context("writing to the agent")?;
    }
    Ok(())
}

/// Relay the server's messages from `input` until it ends: to `host`, or, for
/// what the relay asks the server itself, to `server`.
pub fn pump_server<S: Write, H: Write>(
    relay: &Relay,
    mut input: impl BufRead,
    server: &Mutex<Option<S>>,
    host: &Mutex<Option<H>>,
    note: &(dyn Fn(&str) + Sync),
) -> Result<()> {
    while let Some(line) = read_line(&mut input)? {
        route(relay.server_line(&line), server, host, note)?;
    }
    Ok(())
}
