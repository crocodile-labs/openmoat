//! Hook decisions inside `moat run` (ADR-028).
//!
//! The agent's hooks run `moat guard` inside the run's sandbox, which gives
//! no access to OpenMoat's home: not the lock or the policy it must read, not
//! the audit log it must write. So `moat run` gives the agent
//! [`SOCKET_ENV`] (the loopback address of its proxy's port, the one port the
//! sandbox lets the agent reach) and [`TOKEN_ENV`] (a random token for this
//! run). A guard that has both sends the raw payload there ([`client`]) and
//! prints the answer; the `moat run` process, outside the sandbox, decides it
//! with its own access ([`service`]). Whatever goes wrong denies.

mod client;
mod service;
mod wire;

use std::fmt::Write as _;
use std::io::Read as _;
use std::net::TcpStream;
use std::time::Duration;

use anyhow::{Context as _, Result};
use zeroize::Zeroizing;

pub use client::{Endpoint, configured};
pub use service::Service;
pub use wire::Reply;

/// Where `moat run` answers hook calls: `127.0.0.1:<port>`.
pub const SOCKET_ENV: &str = "MOAT_GUARD_SOCKET";
/// The token `moat run` wants with each call.
pub const TOKEN_ENV: &str = "MOAT_GUARD_TOKEN";

/// The most a hook payload may hold: what `moat guard` reads from standard
/// input, and what the relay carries.
pub const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024;

/// A connection the relay reads and writes, with timeouts.
pub trait Stream: std::io::Read + std::io::Write {
    /// Let each read and write wait at most `limit`.
    fn set_timeouts(&self, limit: Duration) -> std::io::Result<()>;
}

impl Stream for &TcpStream {
    fn set_timeouts(&self, limit: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(limit))?;
        self.set_write_timeout(Some(limit))
    }
}

impl Stream for TcpStream {
    fn set_timeouts(&self, limit: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(limit))?;
        self.set_write_timeout(Some(limit))
    }
}

/// `bytes` random bytes from the system's random source, as hex.
pub fn random_hex(bytes: usize) -> Result<Zeroizing<String>> {
    let mut raw = Zeroizing::new(vec![0u8; bytes]);
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut raw))
        .context("reading random bytes")?;
    let mut out = Zeroizing::new(String::with_capacity(bytes * 2));
    for byte in raw.iter() {
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

#[cfg(all(test, unix))]
mod tests;
