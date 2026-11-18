//! A host's request rules at the proxy (`requests:`, ADR-062). A host they
//! name is terminated like the host of a `tls: terminate` secret (ADR-043),
//! for a session that trusts the proxy's certificate authority, and each
//! request read inside its tunnel, or sent to it as plain HTTP, is checked
//! before anything goes upstream. The rules and their matching are the core's
//! ([`openmoat_core::RequestRules`]), the same the hook holds.
//!
//! A connection to such a host that cannot be terminated (a session that did
//! not receive the CA, a request without a session) is refused or relayed as
//! [`Untrusted`] says.

use openmoat_core::rule_id::REQUEST_RULE;
use openmoat_core::{
    Decision, RequestCheck, RequestEntry, RequestRules, RequestsUntrusted as Untrusted, Verdict,
};

/// The request rules of one proxy run. [`Requests::default`] holds none.
#[derive(Debug, Default)]
pub struct Requests {
    entries: Vec<RequestEntry>,
    rules: RequestRules,
    untrusted: Untrusted,
}

/// A request rule that cannot be used.
#[derive(Debug, thiserror::Error)]
#[error("request rules: {0}")]
pub struct RequestRuleError(String);

impl Requests {
    /// The proxy's half of `entries` (every entry not marked `hook_only`);
    /// a connection it cannot terminate is handled as `untrusted` says.
    pub fn new(entries: &[RequestEntry], untrusted: Untrusted) -> Result<Self, RequestRuleError> {
        let entries: Vec<RequestEntry> = entries.iter().filter(|e| !e.hook_only).cloned().collect();
        let rules =
            RequestRules::for_proxy(&entries).map_err(|e| RequestRuleError(e.to_string()))?;
        Ok(Self {
            entries,
            rules,
            untrusted,
        })
    }

    /// These rules, and `host` refusing every request one of `deny` names
    /// (`METHOD /path`, as a secret's `allow` rules are written).
    pub fn deny(self, host: &str, deny: &[&str]) -> Result<Self, RequestRuleError> {
        let mut entries = self.entries;
        entries.push(RequestEntry {
            id: format!("rules-{}", entries.len() + 1),
            host: host.to_owned(),
            allow: Vec::new(),
            deny: deny.iter().map(|d| (*d).to_owned()).collect(),
            hook_only: false,
        });
        Self::new(&entries, self.untrusted)
    }

    /// The hosts these rules name, sorted, once each: what the CA must cover.
    #[must_use = "the hosts are only listed"]
    pub fn hosts(&self) -> Vec<String> {
        self.rules.hosts()
    }

    /// Whether `host` has rules, so its tunnels are terminated.
    pub(crate) fn names(&self, host: &str) -> bool {
        self.rules.names(host)
    }

    /// What a connection to one of these hosts gets when it cannot be
    /// terminated: `Ok` the note its allow row carries (relayed), `Err` the
    /// refusal to record. `why` says why it cannot be terminated.
    pub(crate) fn untrusted(&self, host: &str, why: &str) -> Result<String, Decision> {
        match self.untrusted {
            Untrusted::Relay => Ok(format!(
                "{host} has request rules, but {why}, so the tunnel is relayed unread \
                 (`requests_untrusted: relay`)"
            )),
            Untrusted::Refuse => Err(Decision::single(
                Verdict::Deny,
                REQUEST_RULE,
                format!(
                    "{host} has request rules, but {why}, so they cannot be held and the \
                     connection is refused (`requests_untrusted: refuse`)"
                ),
            )),
        }
    }

    /// Check `head` (the complete request head the proxy will send) to
    /// `host`. `Ok` holds the reason for the audit row when `host` has rules;
    /// `Err` the deny to record. The reasons name the method and the rule,
    /// never the path, which may carry data.
    pub(crate) fn check(&self, host: &str, head: &[u8]) -> Result<Option<String>, Decision> {
        if !self.names(host) {
            return Ok(None);
        }
        let refuse = |why: String| Decision::single(Verdict::Deny, REQUEST_RULE, why);
        let mut headers = [httparse::EMPTY_HEADER; crate::request::MAX_HEADERS + 2];
        let mut request = httparse::Request::new(&mut headers);
        let (Ok(httparse::Status::Complete(_)), Some(method), Some(target)) =
            (request.parse(head), request.method, request.path)
        else {
            return Err(refuse(format!(
                "the request to {host} could not be read again to check its request rules"
            )));
        };
        let names: Vec<&str> = request.headers.iter().map(|h| h.name).collect();
        match self.rules.check(host, method, target, &names) {
            RequestCheck::Refused(why) => Err(refuse(why)),
            RequestCheck::Passed(why) => Ok(Some(why)),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests;
