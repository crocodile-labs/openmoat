//! `openmoat run --listen PORT` before anything starts (ADR-108 §7): refused
//! where nothing in the system holds the network, and a note when an agent
//! that serves a port starts without it.

use anyhow::{Result, bail};

use super::platform;
use crate::sandbox::own_login::Owner;

/// Refuse `listen` where the tier cannot hold a listening socket to the one
/// loopback port (macOS, whose Seatbelt filter lets a bind to every address
/// through; Windows, whose tier holds the network by the proxy variables
/// alone, ADR-115); without it, say so to an agent that serves a port
/// (OpenClaw's Gateway), whose server will not start.
pub(super) fn check(listen: Option<u16>, owner: Owner) -> Result<()> {
    match listen {
        Some(port) => {
            if let Some(why) = platform::listen_refused_here(port) {
                bail!("{why}");
            }
        }
        None => {
            if let Some(hint) = hint(owner) {
                eprintln!("{hint}");
            }
        }
    }
    Ok(())
}

/// What `openmoat run` says when it starts an agent that serves a port
/// without `--listen`.
fn hint(owner: Owner) -> Option<String> {
    let Owner::Agent(host) = owner else {
        return None;
    };
    let listen = host.spec().run_listen?;
    Some(format!(
        "moat run: {} serves a local port (by default {}), which this run does not allow: \
         `openmoat status` shows the command with `--listen`",
        listen.what, listen.default_port
    ))
}
