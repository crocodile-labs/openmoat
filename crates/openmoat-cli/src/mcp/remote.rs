//! Remote MCP servers (Streamable HTTP) through OpenMoat's gateway (ADR-127).
//!
//! A person names a remote server once with `openmoat mcp login <server> --url
//! <url>`: its URL is pinned, and the token they give is kept in OpenMoat's own
//! state directory (owner-only, under `mcp-remote/`, which the default policy's
//! `kernel-self` keeps every agent from reading). The agent's configuration starts `openmoat mcp
//! remote --server <server> --url <url>` as a stdio server; that command
//! refuses a URL other than the pinned one, sends each message the relay (the
//! same one stdio servers go through, ADR-045) passed on as an HTTP `POST`
//! with the token added, and hands each answer back to the relay. The agent
//! never holds the token and never sees a response header: no passthrough.
//!
//! Where the request may go is checked twice: the URL here (`https`, no user
//! name or password, no fragment, no address in an unusual notation, plain
//! `http` only to a loopback literal or `localhost`), and every address its
//! name resolves to in `transport.rs`, through the egress proxy's own connect
//! (`openmoat_proxy::connect`): loopback, private and shared addresses only
//! when an allow rule of the policy names the address, link-local and the
//! cloud metadata services never.

use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use openmoat_proxy::{Endpoint, Scheme};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::home::Home;

pub mod discovery;
pub mod sse;
pub mod transport;

#[cfg(test)]
mod tests;

/// What `openmoat mcp login` pinned for one remote server.
#[derive(Serialize, Deserialize)]
pub struct Record {
    /// The server's URL, as the person gave it.
    pub url: String,
    /// The bearer token OpenMoat adds to every request; none for a server that
    /// needs no sign-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl Drop for Record {
    fn drop(&mut self) {
        if let Some(token) = &mut self.token {
            zeroize::Zeroize::zeroize(token);
        }
    }
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Record")
            .field("url", &self.url)
            .field("token", &self.token.as_ref().map(|_| "…"))
            .finish()
    }
}

/// Where server `name`'s record is kept: OpenMoat's state directory, under
/// the same file name its tool pins use.
pub fn path(home: &Home, name: &str) -> PathBuf {
    let pins = super::tools::path(home, name);
    let file = pins.file_name().map_or_else(
        || std::ffi::OsString::from("server.json"),
        ToOwned::to_owned,
    );
    home.root().join("mcp-remote").join(file)
}

impl Record {
    /// The record of server `name`, if a person made one.
    pub fn load(home: &Home, name: &str) -> Result<Option<Self>> {
        let path = path(home, name);
        let text = match std::fs::read(&path) {
            Ok(text) => Zeroizing::new(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let record =
            serde_json::from_slice(&text).with_context(|| format!("reading {}", path.display()))?;
        Ok(Some(record))
    }

    /// Write the record, owner-only.
    pub fn save(&self, home: &Home, name: &str) -> Result<()> {
        let text = Zeroizing::new(serde_json::to_vec_pretty(self)?);
        crate::home::write_private(&path(home, name), &text)
    }
}

/// `url` read as a remote MCP endpoint, or why OpenMoat never sends to it.
pub fn endpoint(url: &str) -> Result<Endpoint> {
    let endpoint = Endpoint::parse(url).map_err(|e| anyhow::Error::msg(e.to_string()))?;
    if endpoint.host.parse::<std::net::IpAddr>().is_err() {
        // A last label of digits, or `0x…`, is an address some resolvers read
        // in another notation (`2852039166`, `0xa9.0xfe.0xa9.0xfe`): only a
        // plain address, which the connect checks, is accepted.
        let last = endpoint.host.rsplit('.').next().unwrap_or("");
        if last.bytes().all(|b| b.is_ascii_digit()) || last.starts_with("0x") {
            bail!("`{url}` names an address in an unusual notation");
        }
    }
    if endpoint.scheme == Scheme::Http && endpoint.host.eq_ignore_ascii_case("localhost") {
        // `localhost` may resolve anywhere a resolver says; a loopback literal
        // is exactly this machine.
        bail!("`{url}`: plain http goes to 127.0.0.1 or [::1], not to a name");
    }
    Ok(endpoint)
}

/// The origin of `url` (scheme, host and port), for messages and the record
/// check: a path or query may carry a credential and is never shown.
pub fn origin(endpoint: &Endpoint) -> String {
    let scheme = match endpoint.scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    };
    let host = if endpoint.host.contains(':') {
        format!("[{}]", endpoint.host)
    } else {
        endpoint.host.clone()
    };
    format!("{scheme}://{host}:{}", endpoint.port)
}

/// The error answer to `message` when it is a request (it has a method and
/// an id), naming `why`: what the agent gets for a request that could not be
/// sent, so it does not wait for it.
pub fn failed_answer(message: &str, why: &str) -> Option<String> {
    let request: serde_json::Value = serde_json::from_str(message).ok()?;
    request.get("method")?;
    let id = request.get("id").filter(|id| !id.is_null())?;
    let answer = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32603,
            "message": format!("OpenMoat could not reach the remote MCP server: {why}"),
        },
    });
    Some(answer.to_string())
}

/// The record of `server` that lets `url` be reached, or why none does.
pub fn admitted(home: &Home, server: &str, url: &str) -> Result<Record> {
    let wanted = endpoint(url)?;
    let Some(record) = Record::load(home, server)? else {
        bail!(
            "no person has named remote MCP server `{server}`; run `openmoat mcp login {server} \
             --url {}` in a terminal (docs/USAGE.md \"Remote MCP servers\")",
            origin(&wanted)
        );
    };
    let pinned = endpoint(&record.url)?;
    if pinned != wanted {
        bail!(
            "remote MCP server `{server}` was named with {}, not {}; if the server moved, run \
             `openmoat mcp login {server} --url <new url>` in a terminal",
            origin(&pinned),
            origin(&wanted)
        );
    }
    Ok(record)
}
