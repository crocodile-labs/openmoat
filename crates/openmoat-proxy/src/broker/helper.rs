//! Handing a secret's value to a tool's local helper (ADR-118).
//!
//! Without TLS termination the proxy cannot put a value into an HTTPS
//! request. A tool with a helper protocol (git's credential helper, AWS's
//! `credential_process`) asks its helper instead, and `openmoat credential`
//! asks the proxy. The proxy hands the value out only for a secret whose
//! `helper:` names that tool, and for git only when git asks for the
//! secret's own host: the audience the policy gave it. A value past its
//! deadline is never handed out. Every answer is recorded by the caller.

use openmoat_core::rule_id::PROXY_HELPER;
use openmoat_core::{Decision, Verdict};
use zeroize::Zeroizing;

use super::Broker;

/// What a helper may be handed: the value, the secret's own host (for the
/// audit row) and the user name git sends with it.
pub struct HandOut<'a> {
    /// The value to hand out.
    pub value: Zeroizing<String>,
    /// The secret's host.
    pub host: &'a str,
    /// The user name the helper gives with the value; `None` for AWS.
    pub username: Option<&'a str>,
    /// The allow decision to record.
    pub decision: Decision,
}

impl std::fmt::Debug for HandOut<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandOut")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl Broker {
    /// The value of secret `id` for a `tool` helper that asks for `host`
    /// (`None` for AWS, whose helper names no host); the deny to record when
    /// the secret has no such helper, belongs to another host, or expired.
    pub fn hand_out(
        &self,
        tool: &str,
        id: &str,
        host: Option<&str>,
    ) -> Result<HandOut<'_>, Decision> {
        let refuse = |why: String| Decision::single(Verdict::Deny, PROXY_HELPER, why);
        let Some(held) = self.held.iter().find(|h| h.secret.id == id) else {
            return Err(refuse(format!(
                "the {tool} helper asked for secret `{id}`, which the policy does not broker"
            )));
        };
        let Some(helper) = held.secret.helper.as_ref().filter(|h| h.tool() == tool) else {
            return Err(refuse(format!(
                "secret `{id}` has no `helper: {tool}`; the {tool} helper is not given it"
            )));
        };
        let own = held.secret.host.as_str();
        match (helper, host) {
            (openmoat_core::mint::Helper::Git { .. }, Some(asked)) if asked == own => {}
            (openmoat_core::mint::Helper::Git { .. }, asked) => {
                return Err(refuse(format!(
                    "the git helper asked for secret `{id}` for {}, but only {own} may receive it",
                    asked.unwrap_or("no host")
                )));
            }
            (_, None) => {}
            (_, Some(_)) => {
                return Err(refuse(format!(
                    "the {tool} helper names a host; secret `{id}` is handed out by id only"
                )));
            }
        }
        let Some(value) = held.live() else {
            return Err(refuse(format!(
                "secret `{id}` expired and was not renewed; the {tool} helper gets nothing"
            )));
        };
        let username = match helper {
            openmoat_core::mint::Helper::Git { username } => Some(username.as_str()),
            openmoat_core::mint::Helper::Aws => None,
        };
        Ok(HandOut {
            value,
            host: own,
            username,
            decision: Decision::single(
                Verdict::Allow,
                PROXY_HELPER,
                format!("secret `{id}` handed to the {tool} helper, for {own} only"),
            ),
        })
    }
}

#[cfg(test)]
mod tests;
