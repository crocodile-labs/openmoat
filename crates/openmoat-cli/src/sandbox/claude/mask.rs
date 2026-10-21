//! Whether Claude Code's own broker masks each policy secret (#363), read
//! from a settings document, for `moat doctor` and `moat sandbox show`.
//!
//! Claude Code masks a credential only when its `sandbox.credentials` entry
//! has `"mode": "mask"` and `network.tlsTerminate` is set; without
//! `tlsTerminate` the sentinel reaches the server unchanged and the request
//! fails to authenticate, exposing nothing. On macOS a `files` mask entry is
//! applied as a read deny instead. Each `injectHosts` host must also be in
//! `network.allowedDomains`. (<https://code.claude.com/docs/en/sandboxing>,
//! "Mask credentials" and "Mask credential files".)

use openmoat_core::{SECRET_RULE_PREFIX, Secret, SecretSource};
use serde_json::{Value, json};

use super::Generated;
use crate::sandbox::Report;

/// What Claude Code does with one policy secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mask {
    /// The settings carry its mask entry and `tlsTerminate`: sandboxed
    /// commands see a placeholder and Claude Code's proxy sends the value.
    Active,
    /// Its `file` mask entry is written, but on macOS Claude Code denies
    /// reading the file instead, so a tool that reads it does not authenticate.
    FileDenied,
    /// OpenMoat does not write a mask entry for it; the loss says why.
    Skipped(String),
    /// The policy has a mask entry for it that the settings lack, or
    /// `tlsTerminate` is missing: not masked until `moat sandbox sync`.
    NotWritten,
}

impl Mask {
    /// The state, worded for one output line.
    pub fn describe(&self) -> String {
        match self {
            Self::Active => "Claude Code masks it".to_owned(),
            Self::FileDenied => "Claude Code denies the file instead of masking it on macOS, so \
                 the tool that reads it does not authenticate in the sandbox"
                .to_owned(),
            Self::Skipped(why) => format!("Claude Code skips it: {why}"),
            Self::NotWritten => {
                "not masked: the settings lack its mask entry; run `openmoat sandbox sync`"
                    .to_owned()
            }
        }
    }
}

/// The [`Mask`] of each secret in `secrets`, in order, from the settings
/// document `root`, with `report` the generator's (its `secrets.<id>` losses
/// name the secrets it skips) and `macos` whether Claude Code runs on macOS.
pub fn states<'a>(
    root: &Value,
    secrets: &'a [Secret],
    report: &Report,
    macos: bool,
) -> Vec<(&'a Secret, Mask)> {
    let tls = root
        .pointer("/sandbox/network/tlsTerminate")
        .is_some_and(Value::is_object);
    secrets
        .iter()
        .map(|secret| {
            let rule = format!("{SECRET_RULE_PREFIX}{}", secret.id);
            let state = if let Some(loss) = report.losses.iter().find(|l| l.rule == rule) {
                Mask::Skipped(loss.message.clone())
            } else if !tls || !has_entry(root, secret) {
                Mask::NotWritten
            } else if macos && matches!(secret.source, SecretSource::File(_)) {
                Mask::FileDenied
            } else {
                Mask::Active
            };
            (secret, state)
        })
        .collect()
}

/// Whether `root` has a mask entry for `secret`'s source that names its host.
fn has_entry(root: &Value, secret: &Secret) -> bool {
    let (list, key, value) = match &secret.source {
        SecretSource::Env(name) => ("envVars", "name", name),
        SecretSource::File(path) => ("files", "path", path),
        SecretSource::Keychain { .. } => return false,
    };
    root.pointer(&format!("/sandbox/credentials/{list}"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|entry| {
            entry.get(key) == Some(&json!(value))
                && entry.get("mode") == Some(&json!("mask"))
                && entry
                    .get("injectHosts")
                    .and_then(Value::as_array)
                    .is_some_and(|hosts| hosts.contains(&json!(secret.host)))
        })
}

/// A weakened mask setting in `root`, worded for `moat doctor`: Claude Code's
/// `credentials.allowPlaintextInject` lifts the HTTPS requirement for every
/// mask entry in the block (the settings reference,
/// `sandbox.credentials.allowPlaintextInject`), so it is a weakness when the
/// policy's masked secrets do not all set `plain_http`.
pub fn weaknesses(root: &Value, generated: &Generated) -> Vec<String> {
    let ours = generated.sandbox.contains_key("credentials");
    let lifted = generated
        .sandbox
        .get("credentials")
        .and_then(|c| c.get("allowPlaintextInject"))
        == Some(&json!(true));
    let set = root.pointer("/sandbox/credentials/allowPlaintextInject") == Some(&json!(true));
    if ours && set && !lifted {
        vec![
            "sandbox.credentials.allowPlaintextInject is true: masked secrets may go to \
             plain-HTTP hosts in clear text"
                .to_owned(),
        ]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests;
