//! New network endpoints: hosts the change's code and configuration name in
//! URLs that the policy's network allow list does not.
//!
//! One finding per host for the whole change, at the first added line that
//! names it. Not read: prose (a README link is for people), tests and
//! fixtures (whose URLs are mostly sample data), lockfiles and manifests
//! (their sources are `diff-package-source`), comment lines, URLs
//! with a template in their host (`https://${HOST}/`), and hosts that name no
//! endpoint: loopback, the names reserved for examples and tests (RFC 2606,
//! RFC 6761) and XML and JSON schema namespaces, which programs compare as
//! strings and never connect to. A host the change also removes is not new.

use std::collections::BTreeSet;

use super::files::{self, Kind, is_comment};
use super::{Change, Hit, Level, NEW_HOST};
use crate::host;

/// URL schemes of network connections.
const SCHEMES: &[&str] = &["http", "https", "ws", "wss", "ftp", "ftps", "sftp"];

/// Top-level names reserved for documentation and tests (RFC 2606, RFC 6761),
/// and `local` (mDNS on this network).
const RESERVED_TLDS: &[&str] = &["example", "test", "invalid", "localhost", "local"];

/// Names reserved for examples (RFC 2606), with their subdomains.
const RESERVED_DOMAINS: &[&str] = &["example.com", "example.net", "example.org"];

/// Hosts of namespace and schema identifiers: written as URLs, never fetched.
const NAMESPACE_HOSTS: &[&str] = &[
    "www.w3.org",
    "w3.org",
    "json-schema.org",
    "schema.org",
    "schemas.xmlsoap.org",
    "schemas.microsoft.com",
    "schemas.openxmlformats.org",
    "schemas.android.com",
    "purl.org",
    "xmlns.com",
    "ns.adobe.com",
];

/// Each host `changes` add that `allowed` (the policy's network decision)
/// does not allow: the index of the change it is first named in, and its finding.
pub fn new_hosts(changes: &[Change<'_>], allowed: impl Fn(&str) -> bool) -> Vec<(usize, Hit)> {
    let removed: BTreeSet<String> = changes
        .iter()
        .flat_map(|c| c.blocks.iter().flat_map(|b| &b.removed))
        .flat_map(|t| hosts_in(t))
        .collect();
    let mut seen = BTreeSet::new();
    let mut found = Vec::new();
    for (index, change) in changes.iter().enumerate() {
        let file = files::classify(change.path);
        if file.is(Kind::Doc) || file.test || file.lock.is_some() || file.manifest.is_some() {
            continue;
        }
        for (line, text) in change.added {
            if is_comment(text) {
                continue;
            }
            for host in hosts_in(text) {
                if removed.contains(&host) || !seen.insert(host.clone()) || allowed(&host) {
                    continue;
                }
                let reason = format!(
                    "adds a connection to {host}, which the policy's network allow list does not \
                     name: check what the code sends there"
                );
                found.push((index, Hit::new(NEW_HOST, Level::Review, *line, reason)));
            }
        }
    }
    found
}

/// The endpoint hosts of the URLs in `text`, lowercase, in order.
fn hosts_in(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut hosts = Vec::new();
    for (at, _) in lower.match_indices("://") {
        let scheme_start = lower[..at]
            .char_indices()
            .rev()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |(i, c)| i + c.len_utf8());
        let scheme = lower[scheme_start..at]
            .rsplit('+')
            .next()
            .unwrap_or_default();
        if !SCHEMES.contains(&scheme) {
            continue;
        }
        let rest = &lower[at + 3..];
        let authority = rest
            // a non-ASCII letter ends it too (`«https://x»`): hosts are read in their ASCII form
            .split(|c: char| {
                !c.is_ascii()
                    || c.is_whitespace()
                    || matches!(
                        c,
                        '/' | '?' | '#' | '"' | '\'' | '`' | '<' | '>' | ')' | ',' | ';' | '\\'
                    )
            })
            .next()
            .unwrap_or_default();
        if authority.contains(['$', '{', '}', '%', '*', '[']) {
            continue;
        }
        let Some(host) = host::of_url(authority) else {
            continue;
        };
        let address = host.parse::<core::net::IpAddr>().is_ok();
        if (address || host::fetchable(&host)) && endpoint(&host) && !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    hosts
}

/// Whether `host` names something a program connects to.
fn endpoint(host: &str) -> bool {
    let under = |domain: &str| host == domain || host.ends_with(&format!(".{domain}"));
    let tld = host.rsplit('.').next().unwrap_or(host);
    !host::is_loopback(host)
        && !RESERVED_TLDS.contains(&tld)
        && !RESERVED_DOMAINS.iter().any(|d| under(d))
        && !NAMESPACE_HOSTS.contains(&host)
}
