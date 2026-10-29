//! Brokered secrets: the policy's `secrets:` list (ADR-020, docs/POLICY.md §2.1).
//!
//! OpenMoat keeps the value; the agent holds a placeholder; `moat proxy` puts the
//! value into one header of requests to one host, and with `allow` rules only
//! of the requests they name (`route.rs`, ADR-043). This module is the schema,
//! its validation and the rules' matching: reading the source is the CLI's
//! job, using the value is the proxy's.

mod route;

use serde::{Deserialize, Serialize};

pub use self::route::{MAX_ROUTES, METHOD_OVERRIDE_HEADERS, PathRefusal, RequestPath, Route};
use crate::host::{MAX_DNS_LABEL_LEN, MAX_DNS_NAME_LEN};
use crate::policy::PolicyError;

/// What a brokered secret's id is prefixed with where it stands for a rule id
/// (`secrets.<id>`): lint warnings, policy errors and sandbox losses.
pub const SECRET_RULE_PREFIX: &str = "secrets.";

/// Headers a secret may not be put in: they frame the request or the
/// connection, so a secret there would change how the request is read.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
];

/// One brokered secret. Its `Debug` output names only the id: where the value
/// lives and where it goes say which secrets exist.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Secret {
    /// Stable identifier: lowercase letters, digits and `-`. It names the
    /// placeholder and appears in audit rows; the value never does.
    pub id: String,
    /// The one host (a lowercase DNS name or IPv4 literal, no pattern) whose
    /// requests receive the secret.
    pub host: String,
    /// The request header the secret goes in (`Authorization`, `X-Api-Key`).
    pub header: String,
    /// Where OpenMoat reads the value, written `{ env: NAME }` and so on.
    pub source: Source,
    /// Also inject into plain-HTTP requests, which carry the value in clear
    /// text. Off unless set: without it a plain-HTTP request keeps the
    /// placeholder.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub plain_http: bool,
    /// The port of the plain-HTTP requests that get the value, 1 to 65535;
    /// 80 when unset. A request to another port of the host keeps the
    /// placeholder. Only with `plain_http`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// `terminate`: `openmoat run`'s proxy decrypts HTTPS to `host` with its own
    /// certificate authority and puts the value in there (ADR-043). Off unless
    /// set: without it an HTTPS request keeps the placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
    /// The only requests that may receive the value, `METHOD /path` each
    /// ([`Route`]). Empty: every request to `host` does. With rules, any other
    /// request to `host` that would get the value is refused before it is
    /// added. Needs `tls: terminate` or `plain_http`, where requests can be read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
}

/// How a brokered secret reaches HTTPS requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tls {
    /// The proxy ends the agent's TLS with a certificate it makes for the host,
    /// reads each request, and opens its own TLS to the host.
    Terminate,
}

/// What a secret's `allow` rules say about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Permit {
    /// The secret has no rules: every request to its host gets it.
    Unrestricted,
    /// The request matches this rule.
    Rule(String),
    /// The request matches no rule, or cannot be matched; why, without the path.
    Refused(String),
}

/// Where OpenMoat reads a secret's value. The agent should not be able to read it
/// there; `moat policy lint` warns when no deny rule covers the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Source {
    /// A file, absolute or under `~/`; its contents without the trailing newline.
    File(String),
    /// An environment variable of the `moat proxy` process.
    Env(String),
    /// An item in the operating system's keychain.
    Keychain {
        /// Service name of the item.
        service: String,
        /// Account name of the item.
        account: String,
    },
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Secret {
    /// What the agent holds instead of the value: `moat-secret:<id>:placeholder`.
    /// Ids cannot contain `:`, so no placeholder occurs inside another.
    #[must_use]
    pub fn placeholder(&self) -> String {
        format!("moat-secret:{}:placeholder", self.id)
    }

    /// The port of the plain-HTTP requests the value goes into: `port`, or 80.
    #[must_use]
    pub fn plain_http_port(&self) -> u16 {
        self.port.unwrap_or(80)
    }

    /// True when the host is this machine: `localhost`, a name under it, or
    /// `127.0.0.0/8`. Hosts are validated lowercase DNS names or IPv4. The
    /// address type comes from `core`, which parses and does no I/O.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        let host = self.host.as_str();
        host == "localhost"
            || host.ends_with(".localhost")
            || host
                .parse::<core::net::Ipv4Addr>()
                .is_ok_and(|ip| ip.is_loopback())
    }

    /// Whether `openmoat run`'s proxy decrypts HTTPS to the host (`tls: terminate`).
    #[must_use]
    pub fn terminates(&self) -> bool {
        self.tls == Some(Tls::Terminate)
    }

    /// What the `allow` rules say about a `method` request for `target` (the
    /// request line's target) whose headers are named `header_names`. With
    /// rules, a request is refused when its path could be read as another
    /// ([`PathRefusal`]) or it asks for another method ([`METHOD_OVERRIDE_HEADERS`],
    /// a `_method` query parameter). Reasons never quote the path: it may hold
    /// what the request is about.
    #[must_use]
    pub fn permit(&self, method: &str, target: &str, header_names: &[&str]) -> Permit {
        if self.allow.is_empty() {
            return Permit::Unrestricted;
        }
        let refused = |why: String| {
            Permit::Refused(format!(
                "{method} request to {} is refused for secret `{}`: {why}",
                self.host, self.id
            ))
        };
        let path = match RequestPath::parse(target) {
            Ok(path) => path,
            Err(why) => return refused(why.to_string()),
        };
        if let Some(name) = header_names.iter().find(|name| {
            METHOD_OVERRIDE_HEADERS
                .iter()
                .any(|h| name.eq_ignore_ascii_case(h))
        }) {
            return refused(format!("its `{name}` header asks for another method"));
        }
        if path.overrides_method() {
            return refused("its query names a `_method` parameter".to_owned());
        }
        // Validated when the policy loaded, so every rule parses.
        self.allow
            .iter()
            .find(|rule| Route::parse(rule).is_ok_and(|r| r.matches(method, &path)))
            .map_or_else(
                || refused("it matches none of the secret's `allow` rules".to_owned()),
                |rule| Permit::Rule(rule.clone()),
            )
    }
}

/// Validate the `secrets:` list. Errors name the secret as `secrets.<id>`.
pub(crate) fn check(secrets: &[Secret]) -> Result<(), PolicyError> {
    for (i, secret) in secrets.iter().enumerate() {
        let fail = |problem: String| PolicyError::Rule {
            rule: format!("{SECRET_RULE_PREFIX}{}", secret.id),
            problem,
        };
        check_one(secret).map_err(fail)?;
        if let Some(earlier) = secrets[..i].iter().find(|s| s.id == secret.id) {
            return Err(PolicyError::DuplicateId(format!(
                "{SECRET_RULE_PREFIX}{}",
                earlier.id
            )));
        }
        if let Some(earlier) = secrets[..i]
            .iter()
            .find(|s| s.host == secret.host && s.header.eq_ignore_ascii_case(&secret.header))
        {
            return Err(fail(format!(
                "secret `{}` already sets {} for {}",
                earlier.id, secret.header, secret.host
            )));
        }
    }
    Ok(())
}

fn check_one(secret: &Secret) -> Result<(), String> {
    let id = &secret.id;
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("id must be 1 to 64 lowercase letters, digits or `-`".into());
    }
    if !is_host(&secret.host) {
        return Err(format!(
            "host `{}` must be one lowercase DNS name or IPv4 address, without port or pattern",
            secret.host
        ));
    }
    let header = &secret.header;
    if header.is_empty() || !header.bytes().all(is_token_byte) {
        return Err(format!("header `{header}` is not an HTTP header name"));
    }
    if RESERVED_HEADERS.contains(&header.to_ascii_lowercase().as_str()) {
        return Err(format!(
            "header `{header}` frames the request or connection; it cannot carry a secret"
        ));
    }
    match secret.port {
        Some(0) => return Err("port must be 1 to 65535".into()),
        Some(port) if !secret.plain_http => {
            return Err(format!(
                "port {port} names where plain-HTTP requests get the value; it needs \
                 `plain_http: true`"
            ));
        }
        _ => {}
    }
    check_transport(secret)?;
    match &secret.source {
        Source::File(path) if !(crate::paths::is_absolute(path) || path.starts_with("~/")) => Err(
            format!("source file `{path}` must be absolute or start with `~/`"),
        ),
        Source::Env(name) if !is_env_name(name) => {
            Err(format!("source env `{name}` is not a variable name"))
        }
        Source::Keychain { service, account }
            if [service, account]
                .iter()
                .any(|s| s.is_empty() || s.chars().any(char::is_control)) =>
        {
            Err("source keychain needs a service and an account without control characters".into())
        }
        _ => Ok(()),
    }
}

/// `tls` and `allow`: termination names a host a certificate can name, and
/// rules need requests the proxy can read.
fn check_transport(secret: &Secret) -> Result<(), String> {
    if secret.terminates() && secret.host.parse::<core::net::Ipv4Addr>().is_ok() {
        return Err(format!(
            "`tls: terminate` needs a DNS name; {} is an address, which the proxy's \
             certificate authority may not sign for",
            secret.host
        ));
    }
    if secret.allow.is_empty() {
        return Ok(());
    }
    if !secret.terminates() && !secret.plain_http {
        return Err(
            "`allow` rules need `tls: terminate` or `plain_http: true`: elsewhere the proxy \
             cannot read the request"
                .into(),
        );
    }
    if secret.allow.len() > MAX_ROUTES {
        return Err(format!("`allow` lists more than {MAX_ROUTES} rules"));
    }
    secret
        .allow
        .iter()
        .try_for_each(|rule| Route::parse(rule).map(drop))
}

/// The form `moat proxy` reports hosts in, so the comparison is exact.
fn is_host(host: &str) -> bool {
    host.len() <= MAX_DNS_NAME_LEN
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_DNS_LABEL_LEN
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

/// RFC 9110 `tchar`.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn is_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[cfg(test)]
mod tests;
