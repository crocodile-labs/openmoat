//! `sandbox.credentials` for Claude Code's native broker (ADR-020, #363).

use openmoat_core::ir::BrokeredSecret;
use openmoat_core::{Kind, SECRET_RULE_PREFIX, SecretSource};
use serde_json::{Map, Value, json};

use crate::sandbox::Report;

/// One `mask` entry per IR [`BrokeredSecret`] whose host appears in `network`'s
/// `allowedDomains`, that goes over HTTPS only, and whose source Claude Code
/// can read (`env` or `file`; `keychain` is skipped with a loss). Returns
/// `None` when no entry is produced, so no `credentials` block is written at
/// all. When at least one entry is produced `network.tlsTerminate` is turned
/// on in `network`, which Claude Code requires for `mask`.
///
/// A `plain_http: true` secret is never one of them: it goes to plain-HTTP
/// requests on one port only (`port`, or 80), and Claude Code's broker cannot
/// bind a secret to a port. Its `allowPlaintextInject` would inject on every
/// port of the host, and, being block-scoped, lift the HTTPS requirement of
/// the other entries too. Such a secret is left to `moat proxy`, which honours
/// `plain_http` and `port` per secret (`openmoat-proxy/src/broker.rs`).
///
/// The IR's `header` field is unused here: Claude Code's proxy substitutes the
/// sentinel wherever it appears in a sandboxed command's outbound request
/// (headers and body), which `moat proxy` cannot do without TLS termination.
pub(super) fn credentials(
    secrets: &[BrokeredSecret],
    network: &mut Value,
    report: &mut Report,
) -> Option<Value> {
    let allowed: Vec<String> = network
        .pointer("/allowedDomains")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();
    let entries = entries(secrets, &allowed, report);
    if entries.is_empty() {
        return None;
    }
    network["tlsTerminate"] = json!({});
    Some(block(entries, report))
}

/// One [`Entry`] per secret whose host is in `allowed`, that goes over HTTPS
/// only, and whose source Claude Code can read; a loss for each of the others.
fn entries(secrets: &[BrokeredSecret], allowed: &[String], report: &mut Report) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    for secret in secrets {
        let rule = format!("{SECRET_RULE_PREFIX}{}", secret.id);
        if !allowed.iter().any(|h| h == &secret.host) {
            report.loss(
                Kind::Net,
                &rule,
                format!(
                    "`{}` is not in `net` allow, so Claude Code's broker cannot inject it; the \
                     secret still works through `openmoat proxy`",
                    secret.host
                ),
            );
            continue;
        }
        if secret.plain_http || secret.port.is_some() {
            // Claude Code's broker injects for a host on every port; the
            // secret's plain-HTTP requests go to one.
            let port = secret.port.unwrap_or(80);
            report.loss(
                Kind::Net,
                &rule,
                format!(
                    "the secret goes to plain-HTTP requests on port {port} only, and Claude Code's \
                     broker cannot bind a secret to a port; the secret still works through \
                     `openmoat proxy`"
                ),
            );
            continue;
        }
        let (kind, value) = match &secret.source {
            SecretSource::Env(name) => (
                EntryKind::EnvVar,
                json!({
                    "name": name,
                    "mode": "mask",
                    "injectHosts": [&secret.host],
                }),
            ),
            SecretSource::File(path) => (
                EntryKind::File,
                json!({
                    "path": path,
                    "mode": "mask",
                    "injectHosts": [&secret.host],
                }),
            ),
            SecretSource::Keychain { .. } => {
                report.loss(
                    Kind::Net,
                    &rule,
                    "Claude Code's broker reads env and file sources only, not the keychain; the \
                     secret still works through `openmoat proxy`"
                        .into(),
                );
                continue;
            }
        };
        entries.push(Entry {
            id: secret.id.clone(),
            kind,
            value,
        });
    }
    entries
}

/// The `credentials` block for `entries`, with the allowance it grants. It
/// never sets `allowPlaintextInject`: every entry goes over HTTPS only.
fn block(entries: Vec<Entry>, report: &mut Report) -> Value {
    let mut env_vars = Vec::new();
    let mut files = Vec::new();
    let mut masked = Vec::new();
    for entry in entries {
        match entry.kind {
            EntryKind::EnvVar => env_vars.push(entry.value),
            EntryKind::File => files.push(entry.value),
        }
        masked.push(entry.id);
    }
    let mut credentials = Map::new();
    if !env_vars.is_empty() {
        credentials.insert("envVars".into(), Value::Array(env_vars));
    }
    if !files.is_empty() {
        credentials.insert("files".into(), Value::Array(files));
    }
    report.allowance(
        Kind::Net,
        "claude-code.mask-credentials",
        masked,
        "Claude Code's own broker substitutes these inside HTTPS for sandboxed commands \
         (`sandbox.credentials` with `tlsTerminate`); on macOS a `file` source is denied \
         instead of masked, so the tool that reads it does not authenticate",
    );
    Value::Object(credentials)
}

/// One mask entry prepared from a brokered secret.
struct Entry {
    id: String,
    kind: EntryKind,
    value: Value,
}

enum EntryKind {
    EnvVar,
    File,
}
