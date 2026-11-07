//! Method and path rules for a host with no brokered secret (ADR-062, step 0:
//! the proof of concept). A host listed here is terminated in `openmoat run`
//! like the host of a `tls: terminate` secret (ADR-043), and each request read
//! inside its tunnel is refused when a `deny` rule names it, before anything
//! goes upstream; every other request passes unchanged.
//!
//! The rules are ADR-043's `METHOD /path` rules (`openmoat_core::SecretRoute`),
//! matched the same way, with two differences that make a deny list err wide:
//! the method and the path are compared in any letter case (a server may read
//! `post` or `/Gists` as the route the rule names), and a request whose path
//! the server could read as another, or that asks the server for another
//! method, is refused instead of being matched.
//!
//! There is no policy schema for these rules yet: the CLI builds them from an
//! unlisted setting of `openmoat run`, which ADR-062 step 0 measures.

use openmoat_core::{Decision, METHOD_OVERRIDE_HEADERS, RequestPath, SecretRoute, Verdict};

/// Rule id of a request a host's request rules refuse. ADR-062 proposes
/// `proxy-request`, which already names a malformed request (`RULE_REQUEST`).
pub const RULE_REQUEST_RULE: &str = "proxy-request-rule";

/// The request rules of one proxy run. [`Requests::default`] holds none.
#[derive(Debug, Default)]
pub struct Requests {
    hosts: Vec<HostRules>,
}

/// One host's `deny` rules, each with the text it was written as.
#[derive(Debug)]
struct HostRules {
    host: String,
    deny: Vec<(String, SecretRoute)>,
}

/// A request rule that cannot be used.
#[derive(Debug, thiserror::Error)]
#[error("request rules for {host}: {why}")]
pub struct RequestRuleError {
    host: String,
    why: String,
}

impl Requests {
    /// These rules, and `host` refused every request one of `deny` names
    /// (`METHOD /path`, as a secret's `allow` rules are written).
    pub fn deny(mut self, host: &str, deny: &[&str]) -> Result<Self, RequestRuleError> {
        let fail = |why: String| RequestRuleError {
            host: host.to_owned(),
            why,
        };
        if host.is_empty() || host.contains(['*', ':', '/']) {
            return Err(fail("the host must be one DNS name".to_owned()));
        }
        let mut rules = Vec::with_capacity(deny.len());
        for text in deny {
            // The method stays as written: `Route::parse` wants it in capitals.
            let folded = text.split_once(' ').map_or_else(
                || (*text).to_owned(),
                |(m, p)| format!("{m} {}", p.to_ascii_lowercase()),
            );
            rules.push((
                (*text).to_owned(),
                SecretRoute::parse(&folded).map_err(fail)?,
            ));
        }
        self.hosts.push(HostRules {
            host: host.to_ascii_lowercase(),
            deny: rules,
        });
        Ok(self)
    }

    /// The hosts these rules name, as the CA must cover them.
    #[must_use = "the hosts are only listed"]
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.hosts.iter().map(|h| h.host.as_str())
    }

    /// Whether `host` has rules, so its tunnels are terminated.
    pub(crate) fn names(&self, host: &str) -> bool {
        self.rules(host).is_some()
    }

    fn rules(&self, host: &str) -> Option<&HostRules> {
        self.hosts
            .iter()
            .find(|h| h.host.eq_ignore_ascii_case(host))
    }

    /// Check `head` (the complete request head the proxy will send) to
    /// `host`. `Ok` holds the reason for the audit row when `host` has rules;
    /// `Err` the deny to record. The reasons name the method and the rule,
    /// never the path, which may carry data.
    pub(crate) fn check(&self, host: &str, head: &[u8]) -> Result<Option<String>, Decision> {
        let Some(rules) = self.rules(host) else {
            return Ok(None);
        };
        let refuse = |why: String| Decision::single(Verdict::Deny, RULE_REQUEST_RULE, why);
        let mut headers = [httparse::EMPTY_HEADER; crate::request::MAX_HEADERS + 2];
        let mut request = httparse::Request::new(&mut headers);
        let (Ok(httparse::Status::Complete(_)), Some(method), Some(target)) =
            (request.parse(head), request.method, request.path)
        else {
            return Err(refuse(format!(
                "the request to {host} could not be read again to check its request rules"
            )));
        };
        let method = method.to_ascii_uppercase();
        let path = RequestPath::parse(&target.to_ascii_lowercase()).map_err(|why| {
            refuse(format!(
                "{method} request to {host}: {why}, so the request rules cannot tell what the \
                 server would read"
            ))
        })?;
        let overriding = request.headers.iter().find(|h| {
            METHOD_OVERRIDE_HEADERS
                .iter()
                .any(|o| h.name.eq_ignore_ascii_case(o))
        });
        if let Some(header) = overriding {
            return Err(refuse(format!(
                "{method} request to {host}: its `{}` header asks the server for another method",
                header.name
            )));
        }
        if path.overrides_method() {
            return Err(refuse(format!(
                "{method} request to {host}: its query names a `_method` parameter"
            )));
        }
        match rules
            .deny
            .iter()
            .find(|(_, rule)| rule.matches(&method, &path))
        {
            Some((text, _)) => Err(refuse(format!(
                "{method} request to {host} is refused by the request rule `deny: {text}` \
                 (ADR-062 proof of concept)"
            ))),
            None => Ok(Some(format!(
                "no request rule for {host} refuses this {method} request"
            ))),
        }
    }
}

#[cfg(test)]
mod tests;
