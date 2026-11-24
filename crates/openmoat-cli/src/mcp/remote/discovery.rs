//! Where a remote MCP server says its tokens come from (OAuth 2.0 Protected
//! Resource Metadata, RFC 9728, which MCP's authorization uses), read for the
//! person running `openmoat mcp login` (ADR-127 §3).
//!
//! Nothing here signs in: it names the authorization servers so the person
//! knows where to get a token. The metadata is fetched only over `https`, from
//! the server's own origin, through the same address checks as every request,
//! with no redirect followed; its `resource` must be the server it was asked
//! about, and an authorization server must be an `https` URL OpenMoat would
//! send to. Anything else is refused and named.

use anyhow::{Result, bail};
use openmoat_proxy::{Endpoint, Scheme};
use serde::Deserialize;

use super::transport::Reply;

/// The metadata document's path, put between the origin and the server's path
/// (RFC 9728 §3.1).
const WELL_KNOWN: &str = "/.well-known/oauth-protected-resource";

/// The parts of a protected resource's metadata OpenMoat reads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Metadata {
    /// The resource the document is about.
    pub resource: String,
    /// The authorization servers that issue its tokens.
    #[serde(default)]
    pub authorization_servers: Vec<String>,
}

/// What an answer asking for a sign-in tells the person.
pub fn sign_in_needed(reply: &Reply) -> String {
    let named = reply
        .header("www-authenticate")
        .and_then(resource_metadata)
        .map(|url| match super::endpoint(&url) {
            Ok(e) => format!(" (its sign-in is described at {})", super::origin(&e)),
            Err(_) => String::new(),
        })
        .unwrap_or_default();
    format!(
        "the server asks for a sign-in (HTTP {}){named}; a person gives OpenMoat a token with \
         `openmoat mcp login <server> --url <url>`",
        reply.status
    )
}

/// The `resource_metadata` parameter of a `WWW-Authenticate: Bearer …`
/// challenge (RFC 9728 §5.1), if it names one.
pub fn resource_metadata(challenge: &str) -> Option<String> {
    let rest = challenge.trim_start();
    let params = rest
        .get(..6)
        .filter(|s| s.eq_ignore_ascii_case("bearer"))
        .map(|_| &rest[6..])?;
    for part in split_params(params) {
        let (name, value) = part.split_once('=')?;
        if name.trim().eq_ignore_ascii_case("resource_metadata") {
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            return Some(value.to_owned());
        }
    }
    None
}

/// The parameters of a challenge, split at commas outside quotes.
fn split_params(params: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut quoted) = (0, false);
    for (at, c) in params.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(params[start..at].trim());
                start = at + 1;
            }
            _ => {}
        }
    }
    out.push(params[start..].trim());
    out.into_iter().filter(|p| !p.is_empty()).collect()
}

/// The metadata document of the server at `server` (RFC 9728 §3.1): on its
/// own origin, `https` only.
pub fn well_known(server: &Endpoint) -> Result<Endpoint> {
    if server.scheme != Scheme::Https {
        bail!("sign-in metadata is read only over https");
    }
    let path = server.path.split('?').next().unwrap_or("/");
    let path = path.trim_end_matches('/');
    Ok(Endpoint {
        path: format!("{WELL_KNOWN}{path}"),
        ..server.clone()
    })
}

/// `body`, the metadata of `server`, checked: its `resource` names `server`
/// (same origin and path), and every authorization server is an `https` URL
/// OpenMoat would send to.
pub fn check(server: &Endpoint, body: &[u8]) -> Result<Metadata> {
    let metadata: Metadata = serde_json::from_slice(body)
        .map_err(|e| anyhow::Error::msg(format!("the sign-in metadata is not readable: {e}")))?;
    let resource = super::endpoint(&metadata.resource)?;
    let path = |e: &Endpoint| {
        e.path
            .split('?')
            .next()
            .unwrap_or("/")
            .trim_end_matches('/')
            .to_owned()
    };
    if super::origin(&resource) != super::origin(server) || path(&resource) != path(server) {
        bail!(
            "the sign-in metadata is about {}, not this server ({})",
            super::origin(&resource),
            super::origin(server)
        );
    }
    for issuer in &metadata.authorization_servers {
        let endpoint = super::endpoint(issuer)?;
        if endpoint.scheme != Scheme::Https {
            bail!(
                "authorization server {} is not https",
                super::origin(&endpoint)
            );
        }
    }
    Ok(metadata)
}
