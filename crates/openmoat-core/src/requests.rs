//! Method and path rules for allowed hosts: the policy's `requests:` list
//! (ADR-062, docs/POLICY.md §2.2).
//!
//! An entry names one host and lists `deny` and `allow` rules written as a
//! brokered secret's (`METHOD /path`, `crate::route`). `deny` is tried first
//! and is absolute; with an `allow` list, a request no rule of it names is
//! refused too; a host's entries only narrow what the `net` and `fetch` rules
//! allow. Two places hold them:
//!
//! - the hook (`requests/hook.rs`), which reads the method and URL a command
//!   or a fetch tool will send (`curl -X POST …`, `gh api`, `gh gist create`)
//!   and denies what a rule refuses, or holds for review what it cannot read
//!   in full; it never allows;
//! - the proxy (`openmoat-proxy`), which reads the request itself inside a
//!   tunnel it terminates. An entry with `hook_only: true` is left to the hook:
//!   it needs no certificate authority and changes nothing at the proxy.
//!
//! Deny rules match the method and the path in any letter case (a server may
//! read `post /Gists` as the route a rule names), so a deny list errs wide;
//! allow rules match as written, so an allow list errs closed. A request whose
//! path the server could read as another, or that asks the server for another
//! method, is refused, as a secret's rules refuse it (ADR-043).

use serde::{Deserialize, Serialize};

use crate::policy::PolicyError;
use crate::route::{MAX_ROUTES, METHOD_OVERRIDE_HEADERS, Partial, RequestPath, Route};

pub(crate) mod command;
pub(crate) mod hook;

/// What a `requests:` entry's id is prefixed with where it stands for a rule
/// id: lint warnings and policy errors (`requests.<id>`).
pub const REQUESTS_RULE_PREFIX: &str = "requests.";

/// One `requests:` entry: one host's request rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEntry {
    /// Stable identifier: lowercase letters, digits and `-`. Named in the
    /// reason of every refusal.
    pub id: String,
    /// The one host (a lowercase DNS name, no address, port or pattern) whose
    /// requests these rules decide.
    pub host: String,
    /// Requests that may be sent, `METHOD /path` each; empty, every request
    /// `deny` does not name. Only the person's own policy may list them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Requests that are refused, whatever `allow` or a secret's rules say.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Decided by the hook only: the proxy neither terminates the host for
    /// this entry nor refuses a session that cannot be terminated.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hook_only: bool,
}

/// What `openmoat proxy` does with a connection to a `requests:` host it
/// cannot terminate (`requests_untrusted:`): a session that did not receive
/// OpenMoat's certificate authority, or a request without a session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Untrusted {
    /// Refuse it (`request-rule`): the rules cannot be held otherwise.
    #[default]
    Refuse,
    /// Relay it unread, as before ADR-062, and say so on its row.
    Relay,
}

/// What a host's request rules say about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestCheck {
    /// No entry names the host.
    Unlisted,
    /// The rules let it pass; why, for the audit row.
    Passed(String),
    /// The rules refuse it; why, naming the method and the rule, never the
    /// path, which may carry data.
    Refused(String),
}

/// The `requests:` entries of a policy, their rules parsed, for one enforcer.
#[derive(Debug, Clone, Default)]
pub struct RequestRules {
    entries: Vec<Compiled>,
}

#[derive(Debug, Clone)]
struct Compiled {
    id: String,
    host: String,
    /// Each rule's text and the rule, its path folded to lowercase.
    deny: Vec<(String, Route)>,
    allow: Vec<(String, Route)>,
}

impl RequestRules {
    /// The rules the hook holds: every entry.
    pub fn for_hook(entries: &[RequestEntry]) -> Result<Self, PolicyError> {
        Self::compile(entries.iter())
    }

    /// The rules the proxy holds: every entry not marked `hook_only`.
    pub fn for_proxy(entries: &[RequestEntry]) -> Result<Self, PolicyError> {
        Self::compile(entries.iter().filter(|e| !e.hook_only))
    }

    fn compile<'a>(entries: impl Iterator<Item = &'a RequestEntry>) -> Result<Self, PolicyError> {
        let mut out = Vec::new();
        for entry in entries {
            let fail = |problem: String| PolicyError::Rule {
                rule: format!("{REQUESTS_RULE_PREFIX}{}", entry.id),
                problem,
            };
            check_one(entry).map_err(fail)?;
            let deny = entry
                .deny
                .iter()
                .map(|text| Ok((text.clone(), Route::parse(&fold_rule(text))?)))
                .collect::<Result<_, String>>()
                .map_err(fail)?;
            let allow = entry
                .allow
                .iter()
                .map(|text| Ok((text.clone(), Route::parse(text)?)))
                .collect::<Result<_, String>>()
                .map_err(fail)?;
            out.push(Compiled {
                id: entry.id.clone(),
                host: entry.host.clone(),
                deny,
                allow,
            });
        }
        Ok(Self { entries: out })
    }

    /// Whether no entry is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The hosts the entries name, sorted, once each: what a proxy CA must cover.
    #[must_use]
    pub fn hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self.entries.iter().map(|e| e.host.clone()).collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// Whether an entry names `host`.
    #[must_use]
    pub fn names(&self, host: &str) -> bool {
        self.of(Some(host)).next().is_some()
    }

    /// The entries for `host`, every entry for `None` (a host not known).
    fn of<'s>(&'s self, host: Option<&'s str>) -> impl Iterator<Item = &'s Compiled> + 's {
        self.entries
            .iter()
            .filter(move |e| host.is_none_or(|h| e.host.eq_ignore_ascii_case(h)))
    }

    /// What the rules say about a `method` request for `target` (the request
    /// line's target) to `host`, whose headers are named `header_names`.
    #[must_use]
    pub fn check(
        &self,
        host: &str,
        method: &str,
        target: &str,
        header_names: &[&str],
    ) -> RequestCheck {
        if !self.names(host) {
            return RequestCheck::Unlisted;
        }
        let refused =
            |why: String| RequestCheck::Refused(format!("{method} request to {host} {why}"));
        let (exact, folded) = match (
            RequestPath::parse(target),
            RequestPath::parse(&target.to_ascii_lowercase()),
        ) {
            (Ok(exact), Ok(folded)) => (exact, folded),
            (Err(why), _) | (_, Err(why)) => {
                return refused(format!(
                    "is refused: {why}, so its request rules cannot tell what the server would read"
                ));
            }
        };
        if let Some(name) = header_names.iter().find(|name| {
            METHOD_OVERRIDE_HEADERS
                .iter()
                .any(|h| name.eq_ignore_ascii_case(h))
        }) {
            return refused(format!(
                "is refused: its `{name}` header asks the server for another method"
            ));
        }
        if exact.overrides_method() {
            return refused("is refused: its query names a `_method` parameter".to_owned());
        }
        let upper = method.to_ascii_uppercase();
        // A server may read `/gists/` as `/gists`: a deny rule matches both.
        let bare = without_trailing_slash(&target.to_ascii_lowercase())
            .and_then(|t| RequestPath::parse(&t).ok());
        for entry in self.of(Some(host)) {
            if let Some((text, _)) = entry.deny.iter().find(|(_, r)| {
                r.matches(&upper, &folded) || bare.as_ref().is_some_and(|b| r.matches(&upper, b))
            }) {
                return refused(format!(
                    "is refused by `deny: {text}` of request rules `{}`",
                    entry.id
                ));
            }
        }
        let mut listing = self
            .of(Some(host))
            .filter(|e| !e.allow.is_empty())
            .peekable();
        if listing.peek().is_none() {
            return RequestCheck::Passed(format!(
                "no request rule for {host} refuses this {method} request"
            ));
        }
        let mut ids = Vec::new();
        for entry in listing {
            if let Some((text, _)) = entry.allow.iter().find(|(_, r)| r.matches(method, &exact)) {
                return RequestCheck::Passed(format!(
                    "{method} request to {host} is named by `allow: {text}` of request rules `{}`",
                    entry.id
                ));
            }
            ids.push(format!("`{}`", entry.id));
        }
        refused(format!(
            "is refused: it matches none of the `allow` rules of request rules {}",
            ids.join(", ")
        ))
    }

    /// Why a request known only in part could be refused, if it could:
    /// `host` `None` is any host an entry names, `method` `None` any method,
    /// `path` `None` any path. An entry with an `allow` list could refuse
    /// any request it does not see in full.
    #[must_use]
    pub(crate) fn could_refuse(
        &self,
        host: Option<&str>,
        method: Option<&str>,
        path: Option<&[Partial]>,
    ) -> Option<String> {
        let upper = method.map(str::to_ascii_uppercase);
        let folded: Option<Vec<Partial>> = path.map(|p| {
            let mut folded: Vec<Partial> = p
                .iter()
                .map(|s| match s {
                    Partial::Known(k) => Partial::Known(k.to_ascii_lowercase()),
                    other => other.clone(),
                })
                .collect();
            // As in `check`: `/gists/` is matched as `/gists` too.
            if folded.len() > 1 && folded.last() == Some(&Partial::Known(String::new())) {
                folded.pop();
            }
            folded
        });
        for entry in self.of(host) {
            if let Some((text, _)) = entry
                .deny
                .iter()
                .find(|(_, r)| r.could_match(upper.as_deref(), folded.as_deref()))
            {
                return Some(format!(
                    "it may be a request `deny: {text}` of request rules `{}` refuses",
                    entry.id
                ));
            }
            if !entry.allow.is_empty() {
                return Some(format!(
                    "request rules `{}` allow only the requests they list",
                    entry.id
                ));
            }
        }
        None
    }
}

/// `target` without the `/` that ends its path, when it has one past the root.
fn without_trailing_slash(target: &str) -> Option<String> {
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(p, q)| (p, Some(q)));
    let bare = path.strip_suffix('/').filter(|b| !b.is_empty())?;
    Some(query.map_or_else(|| bare.to_owned(), |q| format!("{bare}?{q}")))
}

/// `text` with its path in lowercase, as a deny rule is matched; the method
/// stays as written, which [`Route::parse`] wants in capitals.
fn fold_rule(text: &str) -> String {
    text.split_once(' ').map_or_else(
        || text.to_owned(),
        |(m, p)| format!("{m} {}", p.to_ascii_lowercase()),
    )
}

/// Validate the `requests:` list. Errors name the entry as `requests.<id>`.
pub(crate) fn check(entries: &[RequestEntry]) -> Result<(), PolicyError> {
    for (i, entry) in entries.iter().enumerate() {
        if entries[..i].iter().any(|e| e.id == entry.id) {
            return Err(PolicyError::DuplicateId(format!(
                "{REQUESTS_RULE_PREFIX}{}",
                entry.id
            )));
        }
    }
    RequestRules::for_hook(entries).map(drop)
}

fn check_one(entry: &RequestEntry) -> Result<(), String> {
    // A repository's or a pack's entries keep their `repo:` or
    // `pack:<name>:` prefix once merged.
    let id = entry.id.rsplit(':').next().unwrap_or_default();
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("id must be 1 to 64 lowercase letters, digits or `-`".into());
    }
    if !is_dns_name(&entry.host) {
        return Err(format!(
            "host `{}` must be one lowercase DNS name, without address, port or pattern: \
             the proxy's certificate authority is constrained to names",
            entry.host
        ));
    }
    if entry.allow.is_empty() && entry.deny.is_empty() {
        return Err("lists no `allow` or `deny` rule".into());
    }
    for (name, list) in [("allow", &entry.allow), ("deny", &entry.deny)] {
        if list.len() > MAX_ROUTES {
            return Err(format!("`{name}` lists more than {MAX_ROUTES} rules"));
        }
    }
    Ok(())
}

/// A lowercase DNS name that is not an IPv4 address.
fn is_dns_name(host: &str) -> bool {
    host.len() <= crate::host::MAX_DNS_NAME_LEN
        && host.parse::<core::net::Ipv4Addr>().is_err()
        && !host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= crate::host::MAX_DNS_LABEL_LEN
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

#[cfg(test)]
mod tests;
