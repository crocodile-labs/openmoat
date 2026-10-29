//! A secret's `allow` rules at the proxy (ADR-043): whether a request that
//! would get the value may have it. Checked on the head the proxy will send,
//! before anything goes upstream: a refused request never reaches the server,
//! and its audit row names the method and the reason, never the path.

use openmoat_core::{Decision, Permit, Verdict};

use super::{Broker, Channel};

/// Rule id for a request to a secret's host that the secret's `allow` rules
/// do not name: it would have received the value, so it is not sent.
pub const RULE_SECRET_ROUTE: &str = "proxy-secret-route";

impl Broker {
    /// Check `head` (a complete request head the proxy wrote) to `host` over
    /// `channel` against the `allow` rules of every secret that would go into
    /// it. `Ok` holds one reason per rule matched, for the audit row; `Err`
    /// the deny to record.
    pub(crate) fn admit(
        &self,
        host: &str,
        channel: Channel,
        head: &[u8],
    ) -> Result<Vec<String>, Decision> {
        let refuse = |why: String| Decision::single(Verdict::Deny, RULE_SECRET_ROUTE, why);
        let injecting: Vec<_> = self
            .held
            .iter()
            .filter(|h| h.injects(host, channel))
            .collect();
        if injecting.iter().all(|h| h.secret.allow.is_empty()) {
            return Ok(Vec::new());
        }
        let mut headers = [httparse::EMPTY_HEADER; crate::request::MAX_HEADERS + 2];
        let mut request = httparse::Request::new(&mut headers);
        let (Ok(httparse::Status::Complete(_)), Some(method), Some(target)) =
            (request.parse(head), request.method, request.path)
        else {
            return Err(refuse(format!(
                "the request to {host} could not be read again to check its secrets' rules"
            )));
        };
        let names: Vec<&str> = request.headers.iter().map(|h| h.name).collect();
        let mut matched = Vec::new();
        for held in injecting {
            match held.secret.permit(method, target, &names) {
                Permit::Unrestricted => {}
                Permit::Rule(rule) => matched.push(format!(
                    "secret `{}` goes in: the request matches `{rule}`",
                    held.secret.id
                )),
                Permit::Refused(why) => return Err(refuse(why)),
                // A new kind of answer is not understood here: refuse.
                _ => {
                    return Err(refuse(format!(
                        "{method} request to {host}: secret `{}` gave an answer the proxy \
                         does not know",
                        held.secret.id
                    )));
                }
            }
        }
        Ok(matched)
    }
}
