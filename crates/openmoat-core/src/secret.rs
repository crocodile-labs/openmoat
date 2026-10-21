//! Brokered secrets: the policy's `secrets:` list (ADR-020, docs/POLICY.md §2.1).
//!
//! OpenMoat keeps the value; the agent holds a placeholder; `moat proxy` puts the
//! value into one header of requests to one host. This module is the schema
//! and its validation only: reading the source is the CLI's job, using the
//! value is the proxy's.

use serde::{Deserialize, Serialize};

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
mod tests {
    use crate::policy::{Policy, PolicyError};

    use super::Source;

    fn parse(secrets: &str) -> Result<Policy, PolicyError> {
        Policy::parse(&format!("version: 1\nsecrets:\n{secrets}"))
    }

    fn problem(secrets: &str) -> String {
        parse(secrets).unwrap_err().to_string()
    }

    const GH: &str = "  - id: gh\n    host: api.github.com\n    header: Authorization\n";

    #[test]
    fn parses_every_source() {
        let p = parse(&format!(
            "{GH}    source: {{ env: GITHUB_TOKEN }}\n  \
             - id: npm\n    host: registry.npmjs.org\n    header: Authorization\n    \
             source: {{ file: ~/.config/moat/npm }}\n  \
             - id: k\n    host: example.com\n    header: X-Api-Key\n    \
             source: {{ keychain: {{ service: moat, account: k }} }}\n"
        ))
        .unwrap();
        assert_eq!(p.secrets.len(), 3);
        assert_eq!(p.secrets[0].source, Source::Env("GITHUB_TOKEN".into()));
        assert_eq!(
            p.secrets[1].source,
            Source::File("~/.config/moat/npm".into())
        );
        assert!(
            matches!(&p.secrets[2].source, Source::Keychain { service, .. } if service == "moat")
        );
        assert_eq!(p.secrets[0].placeholder(), "moat-secret:gh:placeholder");
        assert!(Policy::parse("version: 1\n").unwrap().secrets.is_empty());
    }

    #[test]
    fn debug_output_names_only_the_id() {
        let policy = parse(&format!("{GH}    source: {{ file: ~/.config/moat/gh }}\n")).unwrap();
        let secret = &policy.secrets[0];
        let brokered = crate::ir::BrokeredSecret {
            id: secret.id.clone(),
            host: secret.host.clone(),
            header: secret.header.clone(),
            source: secret.source.clone(),
            plain_http: false,
            port: None,
        };
        for shown in [format!("{policy:?}"), format!("{brokered:?}")] {
            assert!(shown.contains("\"gh\""), "{shown}");
            for hidden in ["~/.config/moat/gh", "api.github.com", "Authorization"] {
                assert!(!shown.contains(hidden), "{hidden} in {shown}");
            }
        }
    }

    #[test]
    fn plain_http_is_off_unless_set() {
        let off = parse(&format!("{GH}    source: {{ env: T }}\n")).unwrap();
        assert!(!off.secrets[0].plain_http);
        let on = parse(&format!(
            "{GH}    source: {{ env: T }}\n    plain_http: true\n"
        ))
        .unwrap();
        assert!(on.secrets[0].plain_http);
        assert!(!on.secrets[0].is_loopback());
        for (host, loopback) in [
            ("localhost", true),
            ("api.localhost", true),
            ("127.0.0.2", true),
            ("10.0.0.1", false),
            ("localhost.example", false),
        ] {
            let mut s = on.secrets[0].clone();
            s.host = host.into();
            assert_eq!(s.is_loopback(), loopback, "{host}");
        }
    }

    #[test]
    fn a_plain_http_secret_goes_to_port_80_unless_it_names_one() {
        let plain = format!("{GH}    source: {{ env: T }}\n    plain_http: true\n");
        assert_eq!(parse(&plain).unwrap().secrets[0].plain_http_port(), 80);
        let on = parse(&format!("{plain}    port: 8080\n")).unwrap();
        assert_eq!(on.secrets[0].port, Some(8080));
        assert_eq!(on.secrets[0].plain_http_port(), 8080);
        assert!(problem(&format!("{plain}    port: 0\n")).contains("1 to 65535"));
        for bad in ["65536", "-1", "80.5", "http", "[80, 81]"] {
            assert!(
                parse(&format!("{plain}    port: {bad}\n")).is_err(),
                "{bad}"
            );
        }
        let without = format!("{GH}    source: {{ env: T }}\n    port: 8080\n");
        assert!(problem(&without).contains("needs `plain_http: true`"));
    }

    #[test]
    fn rejects_bad_fields() {
        let src = "    source: { env: T }\n";
        for (yaml, want) in [
            (format!("  - id: Gh\n    host: a.com\n    header: A\n{src}"), "id must be"),
            (format!("  - id: g:h\n    host: a.com\n    header: A\n{src}"), "id must be"),
            (format!("  - id: g\n    host: '*.a.com'\n    header: A\n{src}"), "host `*.a.com`"),
            (format!("  - id: g\n    host: A.com\n    header: A\n{src}"), "host `A.com`"),
            (format!("  - id: g\n    host: a.com:443\n    header: A\n{src}"), "host `a.com:443`"),
            (format!("  - id: g\n    host: a.com\n    header: 'A B'\n{src}"), "not an HTTP header"),
            (format!("  - id: g\n    host: a.com\n    header: Host\n{src}"), "frames the request"),
            (format!("  - id: g\n    host: a.com\n    header: content-length\n{src}"), "frames"),
            ("  - id: g\n    host: a.com\n    header: A\n    source: { file: rel/t }\n".into(), "absolute"),
            ("  - id: g\n    host: a.com\n    header: A\n    source: { env: 'A-B' }\n".into(), "variable name"),
            (
                "  - id: g\n    host: a.com\n    header: A\n    source: { keychain: { service: '', account: a } }\n".into(),
                "keychain",
            ),
        ] {
            let got = problem(&yaml);
            assert!(got.contains(want), "{yaml}: {got}");
        }
        assert!(parse(&format!("{GH}    source: {{ vault: x }}\n")).is_err());
        assert!(parse(&format!("{GH}    source: {{ env: T }}\n    extra: 1\n")).is_err());
    }

    #[test]
    fn rejects_duplicates() {
        let two = format!("{GH}    source: {{ env: A }}\n{GH}    source: {{ env: B }}\n");
        assert!(matches!(parse(&two), Err(PolicyError::DuplicateId(id)) if id == "secrets.gh"));
        let same_header = format!(
            "{GH}    source: {{ env: A }}\n  - id: gh2\n    host: api.github.com\n    header: authorization\n    source: {{ env: B }}\n"
        );
        assert!(problem(&same_header).contains("already sets"));
    }
}
