//! Warnings about brokered secrets (docs/POLICY.md §2.1): a host the proxy
//! refuses, and a source the agent can read or, for a `command` source
//! (ADR-087), change.

use crate::kind::Kind;
use crate::paths;
use crate::policy::Policy;
use crate::secret::{SECRET_RULE_PREFIX, Source as SecretSource};

use super::{HOME, PROJECT, Warning, listed};

/// A secret whose host the proxy refuses is never injected, and one whose
/// source the agent may read is not kept from the agent.
pub(super) fn warn(policy: &Policy, out: &mut Vec<Warning>) {
    for secret in &policy.secrets {
        let mut warn = |message: String| {
            out.push(Warning {
                rule: format!("{SECRET_RULE_PREFIX}{}", secret.id),
                message,
            });
        };
        if !listed(&policy.allow, &[Kind::Net, Kind::Fetch], &secret.host) {
            warn(format!(
                "no net or fetch allow rule names {}, so `openmoat proxy` refuses it and the \
                 secret is never injected",
                secret.host
            ));
        }
        if let Some(message) = exposed_source(policy, secret) {
            warn(message);
        }
        if secret.plain_http && secret.is_loopback() {
            warn(format!(
                "`plain_http: true` names {}, a loopback host; `openmoat proxy` never connects to \
                 a loopback address, so the secret is never injected",
                secret.host
            ));
        } else if secret.plain_http {
            warn(format!(
                "`plain_http: true` sends the value to {} in clear text, readable by anyone \
                 on the network path",
                secret.host
            ));
        }
        if secret.terminates() && secret.is_loopback() {
            warn(format!(
                "`tls: terminate` names {}, a loopback host; `openmoat proxy` never connects to \
                 a loopback address, so the secret is never injected",
                secret.host
            ));
        }
    }
}

/// Why the agent can read `secret`'s value itself, when no deny rule covers
/// its source: a `file` no `fs.read` deny names, an `env` variable no
/// `env.read` deny names; for a `command`, why the agent may change the
/// program. `None` for a covered source and for the keychain.
#[must_use]
pub fn exposed_source(policy: &Policy, secret: &crate::Secret) -> Option<String> {
    match &secret.source {
        SecretSource::File(path) => paths::expand_pattern(path, HOME, Some(PROJECT))
            .filter(|p| !listed(&policy.deny, &[Kind::FsRead], p))
            .map(|_| format!("no deny fs.read rule covers `{path}`, so the agent can read it")),
        SecretSource::Env(name) => (!listed(&policy.deny, &[Kind::EnvRead], name))
            .then(|| format!("no deny env.read rule covers `{name}`, so the agent can read it")),
        SecretSource::Keychain { .. } => None,
        SecretSource::Command(command) => (!write_denied(policy, command.program())).then(|| {
            format!(
                "no deny fs.write rule covers `{}`, so `openmoat proxy` runs it only when the \
                 system keeps every user but an administrator from changing it (ADR-087)",
                command.program()
            )
        }),
    }
}

/// Whether a deny `fs.write` rule of `policy` covers `path` (absolute or under
/// `~/`): the agent cannot change the file there through a decision OpenMoat
/// makes. A command source's program must be such a file, or one only an
/// administrator can change (ADR-087).
#[must_use]
pub fn write_denied(policy: &Policy, path: &str) -> bool {
    paths::expand_pattern(path, HOME, Some(PROJECT))
        .is_some_and(|p| listed(&policy.deny, &[Kind::FsWrite], &p))
}
