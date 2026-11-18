//! Warnings about request rules (`requests:`, ADR-062): a host no allow rule
//! reaches, and what the proxy needs to hold an entry.

use crate::kind::Kind;
use crate::policy::Policy;
use crate::requests::{REQUESTS_RULE_PREFIX, Untrusted};

use super::{Warning, listed};

pub(super) fn warn(policy: &Policy, out: &mut Vec<Warning>) {
    for entry in &policy.requests {
        let mut warn = |message: String| {
            out.push(Warning {
                rule: format!("{REQUESTS_RULE_PREFIX}{}", entry.id),
                message,
            });
        };
        if !listed(&policy.allow, &[Kind::Net, Kind::Fetch], &entry.host) {
            warn(format!(
                "no net or fetch allow rule names {}, so these rules decide nothing: request \
                 rules only narrow what an allow rule opens",
                entry.host
            ));
        }
        if !entry.hook_only {
            warn(format!(
                "the proxy terminates TLS to {} for these rules: `openmoat run` needs a proxy CA \
                 that covers it (`openmoat proxy ca init`), and `openmoat proxy` {} sessions \
                 it cannot terminate; `hook_only: true` leaves them to the hook",
                entry.host,
                match policy.requests_untrusted() {
                    Untrusted::Refuse => "refuses",
                    Untrusted::Relay => "relays, unchecked, the connections of",
                }
            ));
        }
    }
}
