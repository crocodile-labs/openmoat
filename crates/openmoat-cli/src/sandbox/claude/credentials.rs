//! `sandbox.credentials` for Claude Code's native broker (ADR-020, #363).

use openmoat_core::ir::BrokeredSecret;
use openmoat_core::{Kind, SECRET_RULE_PREFIX, SecretSource};
use serde_json::{Map, Value, json};

use crate::sandbox::Report;

/// One `mask` entry per IR [`BrokeredSecret`] whose host appears in `network`'s
/// `allowedDomains` and whose source Claude Code can read (`env` or `file`;
/// `keychain` is skipped with a loss). Returns `None` when no entry is
/// produced, so no `credentials` block is written at all. When at least one
/// entry is produced `network.tlsTerminate` is turned on in `network`, which
/// Claude Code requires for `mask`.
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
    // Claude Code's `allowPlaintextInject` is block-scoped: setting it `true`
    // lifts the HTTPS requirement for *every* `envVars`/`files` entry in the
    // `credentials` block. If the policy mixes `plain_http: true` and `false`
    // entries, lifting TLS for the plain-HTTP ones would widen the HTTPS-only
    // ones through the same flag, which ADR-019 forbids (lowering never
    // widens). Only lift TLS when every emitted entry is `plain_http: true`;
    // in a mixed block drop the `plain_http: true` entries from Claude Code's
    // mask list and route them through `moat proxy` instead, which honours
    // `plain_http` per secret (`openmoat-proxy/src/broker.rs`).
    let mut entries = entries(secrets, &allowed, report);
    if entries.is_empty() {
        return None;
    }
    let can_lift_tls = entries.iter().all(|e| e.plain_http);
    if !can_lift_tls {
        drop_plain_http(&mut entries, report);
    }
    if entries.is_empty() {
        return None;
    }
    network["tlsTerminate"] = json!({});
    Some(block(entries, can_lift_tls, report))
}

/// One [`Entry`] per secret whose host is in `allowed` and whose source Claude
/// Code can read; a loss for each of the others.
fn entries(secrets: &[BrokeredSecret], allowed: &[String], report: &mut Report) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    for secret in secrets {
        if !allowed.iter().any(|h| h == &secret.host) {
            report.loss(
                Kind::Net,
                &format!("{SECRET_RULE_PREFIX}{}", secret.id),
                format!(
                    "`{}` is not in `net` allow, so Claude Code's broker cannot inject it; the \
                     secret still works through `openmoat proxy`",
                    secret.host
                ),
            );
            continue;
        }
        if let Some(port) = secret.port {
            // Claude Code's broker injects for a host on every port; the
            // secret names one.
            report.loss(
                Kind::Net,
                &format!("{SECRET_RULE_PREFIX}{}", secret.id),
                format!(
                    "the secret names port {port}, and Claude Code's broker cannot bind a secret \
                     to a port; the secret still works through `openmoat proxy`"
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
                    &format!("{SECRET_RULE_PREFIX}{}", secret.id),
                    "Claude Code's broker reads env and file sources only, not the keychain; the \
                     secret still works through `openmoat proxy`"
                        .into(),
                );
                continue;
            }
        };
        entries.push(Entry {
            id: secret.id.clone(),
            plain_http: secret.plain_http,
            kind,
            value,
        });
    }
    entries
}

/// A mixed block: drop the `plain_http: true` entries, with a loss each, so
/// the HTTPS-only ones are not widened (see [`credentials`]).
fn drop_plain_http(entries: &mut Vec<Entry>, report: &mut Report) {
    entries.retain(|e| {
        if e.plain_http {
            report.loss(
                Kind::Net,
                &format!("{SECRET_RULE_PREFIX}{}", e.id),
                "mixing `plain_http: true` with `plain_http: false` secrets would widen the \
                 others through Claude Code's block-scoped `allowPlaintextInject`; this secret \
                 is routed through `openmoat proxy` instead"
                    .into(),
            );
            false
        } else {
            true
        }
    });
}

/// The `credentials` block for `entries`, lifting TLS only when
/// `can_lift_tls` (every entry is `plain_http: true`), with the allowances
/// it grants.
fn block(entries: Vec<Entry>, can_lift_tls: bool, report: &mut Report) -> Value {
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
    if can_lift_tls {
        credentials.insert("allowPlaintextInject".into(), json!(true));
        report.allowance(
            Kind::Net,
            "claude-code.plain-http-inject",
            masked.clone(),
            "sandboxed commands may send one of these masked secrets to a plain-HTTP destination; \
             the value then goes in clear text",
        );
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

/// One mask entry prepared from a brokered secret, pending the mixed-block
/// decision above.
struct Entry {
    id: String,
    plain_http: bool,
    kind: EntryKind,
    value: Value,
}

enum EntryKind {
    EnvVar,
    File,
}
