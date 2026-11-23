//! What a server may ask the host for (ADR-114): its own requests under the
//! 2025 revisions, and the `inputRequests` of a 2026-07-28 result, which
//! replace them (Multi Round-Trip Requests,
//! <https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr>).
//! Both go through one check, so the revision a server picks changes nothing:
//!
//! - sampling (`sampling/createMessage`) has the model write text the server
//!   chose, as a user turn, and hands the server the answer: refused unless the
//!   policy's `mcp.allow_sampling` allows it, and then still refused when it asks
//!   for the session's context (ADR-069);
//! - a URL-mode elicitation (`elicitation/create` with `mode: "url"`) has the
//!   host offer to open a page: the specification asks the client to show the
//!   URL and ask first
//!   (<https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation#safe-url-handling>),
//!   and OpenMoat refuses one that is not `https`, carries credentials in the
//!   URL, or names a local, private or link-local address (the cloud metadata
//!   service at 169.254.169.254) or a host the policy denies.
//!
//! One refused input request refuses the whole result: the host gets an error
//! for its request instead of a partial set of questions.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::Value;

use super::Relay;

/// The requests a result may carry in `inputRequests`.
const INPUT_METHODS: [&str; 3] = ["elicitation/create", "sampling/createMessage", "roots/list"];
/// The most input requests one result may carry.
const MAX_INPUT_REQUESTS: usize = 64;

impl Relay {
    /// Why the server's `method` request with `params`, sent as a request or
    /// in a result's `inputRequests`, does not reach the host, if it does not.
    pub(super) fn screen(&self, method: &str, params: Option<&Value>) -> Option<String> {
        match method {
            "sampling/createMessage" if !self.allow_sampling => Some(
                "OpenMoat does not pass on a sampling request from an MCP server: it would have \
                 the model write text the server chose (set `mcp: { allow_sampling: true }` in \
                 the policy to allow it)"
                    .to_owned(),
            ),
            "sampling/createMessage" => context_asked(params),
            "elicitation/create" => self.elicited_url(params),
            _ => None,
        }
    }

    /// Why a URL-mode elicitation is refused, if it is.
    fn elicited_url(&self, params: Option<&Value>) -> Option<String> {
        if params.and_then(|p| p.get("mode")).and_then(Value::as_str) != Some("url") {
            return None;
        }
        let Some(url) = params.and_then(|p| p.get("url")).and_then(Value::as_str) else {
            return Some("a URL-mode elicitation without a URL".to_owned());
        };
        // Only where it points: the rest of the URL is the server's text,
        // and this message reaches the model.
        let shown = crate::render::clean(origin(url));
        if let Some(why) = url_problem(url) {
            return Some(format!(
                "OpenMoat does not pass on an elicitation that sends the person to {shown}: {why}"
            ));
        }
        match self.gate.url_refusal(url) {
            Ok(None) => None,
            Ok(Some(why)) => Some(format!(
                "OpenMoat does not pass on an elicitation that sends the person to {shown}: {why}"
            )),
            Err(e) => Some(format!(
                "OpenMoat cannot decide the elicitation's URL {shown} ({e:#}), so it is refused"
            )),
        }
    }

    /// Check the `inputRequests` of a result: `Err` with why the whole result
    /// is refused; each one that passes is recorded, its text kept as the
    /// server's requests' is.
    pub(super) fn screen_input(&self, result: &Value) -> Result<(), String> {
        let Some(requests) = result.get("inputRequests") else {
            return Ok(());
        };
        let Value::Object(requests) = requests else {
            return Err("the server's `inputRequests` is not an object".to_owned());
        };
        if requests.len() > MAX_INPUT_REQUESTS {
            return Err(format!(
                "the server asks for more than {MAX_INPUT_REQUESTS} inputs at once"
            ));
        }
        let mut asked = Vec::with_capacity(requests.len());
        for request in requests.values() {
            let method = request.get("method").and_then(Value::as_str);
            let Some(method) = method.filter(|m| INPUT_METHODS.contains(m)) else {
                return Err(
                    "the server's `inputRequests` holds something other than an elicitation, \
                     sampling or roots request"
                        .to_owned(),
                );
            };
            let params = request.get("params");
            if let Some(why) = self.screen(method, params) {
                // Recorded as refused; a record that fails refuses it all the same.
                let _ = self.gate.server_refused(method, &why);
                return Err(why);
            }
            asked.push((method, params));
        }
        for (method, params) in asked {
            if let Err(e) = self.gate.server_request(method, params) {
                return Err(format!(
                    "OpenMoat cannot record the server's `{method}` input request ({e:#}), so the \
                     result is refused"
                ));
            }
        }
        Ok(())
    }
}

/// Why a sampling request is refused for the context it asks for:
/// `includeContext` other than `none` has the host add what other servers,
/// or this one, put in the session, which would carry it to this server past
/// the cross-server flow check (ADR-058).
fn context_asked(params: Option<&Value>) -> Option<String> {
    let context = params.and_then(|p| p.get("includeContext"))?;
    if context.as_str() == Some("none") {
        return None;
    }
    Some(format!(
        "OpenMoat does not pass on a sampling request that asks for the session's context \
         (includeContext {context}): it would carry other servers' results to this one"
    ))
}

/// The scheme and host of `url`, at most 100 characters of it.
fn origin(url: &str) -> &str {
    let end = url
        .find("://")
        .and_then(|at| url[at + 3..].find(['/', '?', '#']).map(|e| at + 3 + e))
        .unwrap_or(url.len());
    let end = url
        .char_indices()
        .nth(100)
        .map_or(end, |(cut, _)| end.min(cut));
    &url[..end]
}

/// Why `url` is not a page the person may be sent to, whatever the policy
/// says: not `https`, credentials in it, no host, or a host that is a local,
/// private, link-local or numeric address.
pub(super) fn url_problem(url: &str) -> Option<&'static str> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return Some("it is not an https URL");
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return Some("it is not an https URL");
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return Some("the URL carries a user name or password");
    }
    if authority
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return Some("the URL's host is not plain");
    }
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.rsplit_once(':').map_or(authority, |(h, _)| h),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Some("the URL names no host");
    }
    if host == "localhost" || host.ends_with(".localhost") {
        return Some("it names this machine");
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return local(ip).then_some("it names a local, private or link-local address");
    }
    // A last label of digits, or `0x…`, is an address some resolvers read in
    // another notation (`2852039166`, `0xa9.0xfe.0xa9.0xfe`): only a plain
    // dotted address, checked above, is accepted.
    let last = host.rsplit('.').next().unwrap_or("");
    if last.bytes().all(|b| b.is_ascii_digit()) || last.starts_with("0x") {
        return Some("it names an address in an unusual notation");
    }
    None
}

/// Whether `ip` is this machine, a private network, link-local (the cloud
/// metadata services), shared address space or unspecified.
fn local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => local_v4(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(|| local_v6(v6), local_v4),
    }
}

fn local_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        // Shared address space (100.64.0.0/10), where one cloud's metadata
        // service answers (100.100.100.200).
        || (a == 100 && (64..128).contains(&b))
}

fn local_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    ip.is_loopback()
        || ip.is_unspecified()
        // Unique local (fc00::/7) and link-local (fe80::/10).
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
}
