//! What OpenMoat reads in Hermes Agent's `config.yaml` beyond its hook: the
//! form the lock pins ([`pinned_form`]) and the settings that make Hermes
//! approve an `ask` without a person seeing it ([`approves_unseen`]).

use serde_json::Value;

/// Top-level keys Hermes rewrites itself for a person's choice, which change
/// no tool, hook, program, server or file OpenMoat decides on: the config
/// version its migrations bump, the model the `hermes model` picker writes
/// and the display settings `/skin` and the Desktop write.
const SAVED_BY_HERMES: &[&str] = &["_config_version", "model", "display"];

/// A `config.yaml` that holds OpenMoat's hook list, without `mcp_servers`
/// and [`SAVED_BY_HERMES`]; `None` for any other file. The MCP pins (ADR-026)
/// hold each server's definition, so a changed server holds back only its
/// own tools. Every other change is drift: a hook added or removed, a plugin
/// enabled, `approvals`, `terminal`, `security`, `code_execution`, providers,
/// anything Hermes adds later.
pub(super) fn pinned_form(mut value: Value) -> Option<Value> {
    value.pointer("/hooks/pre_tool_call")?.as_array()?;
    let top = value.as_object_mut()?;
    top.remove("mcp_servers");
    for key in SAVED_BY_HERMES {
        top.remove(*key);
    }
    Some(value)
}

/// The unattended modes whose `approve` lets Hermes run an approval-gated
/// call with no person there (`approvals.cron_mode`, `single_query_mode` for
/// `hermes chat -q`, `unattended_mode` for webhook and API sessions). The hook
/// cannot tell which kind of session it runs in.
const UNATTENDED_MODES: &[&str] = &["cron_mode", "single_query_mode", "unattended_mode"];

/// The setting of `config` (`config.yaml`, parsed) under which Hermes
/// approves an `ask` unseen (`_run_approval_gate` in `tools/approval.py`):
/// `approvals.mode: off`, which the Desktop's "Approvals: off" writes, or an
/// unattended mode Hermes reads as `approve` (`approve`, `off`, `allow` or
/// `yes`, `_binary_approval_mode` in `tools/approval_context.py`).
pub(super) fn approves_unseen(config: &Value) -> Option<&'static str> {
    let approvals = config.get("approvals")?;
    // PyYAML reads a bare `off` as `false`; Hermes takes that as `off`.
    match approvals.get("mode") {
        Some(Value::Bool(false)) => return Some("approvals.mode"),
        Some(Value::String(mode)) if mode.trim().eq_ignore_ascii_case("off") => {
            return Some("approvals.mode");
        }
        _ => {}
    }
    UNATTENDED_MODES.iter().copied().find(|key| {
        approvals
            .get(*key)
            .and_then(Value::as_str)
            .is_some_and(|mode| {
                ["approve", "off", "allow", "yes"]
                    .iter()
                    .any(|m| mode.trim().eq_ignore_ascii_case(m))
            })
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_pinned_form_leaves_out_servers_and_what_hermes_saves_itself() {
        let base = json!({
            "hooks": { "pre_tool_call": [{ "command": "x" }] },
            "approvals": { "mode": "manual" },
        });
        let mut changed = base.clone();
        changed["model"] = json!({ "default": "hermes-4", "provider": "nous" });
        changed["display"] = json!({ "skin": "ares" });
        changed["_config_version"] = json!(31);
        changed["mcp_servers"] = json!({ "files": { "command": "npx" } });
        assert_eq!(pinned_form(changed), pinned_form(base.clone()));
        for (key, value) in [
            ("approvals", json!({ "mode": "off" })),
            ("plugins", json!({ "enabled": ["x"] })),
            ("terminal", json!({ "backend": "ssh" })),
            ("hooks_auto_accept", json!(true)),
            ("anything_new", json!(1)),
        ] {
            let mut drifted = base.clone();
            drifted[key] = value;
            assert_ne!(pinned_form(drifted), pinned_form(base.clone()), "{key}");
        }
        assert_eq!(pinned_form(json!({ "model": "x" })), None);
    }

    #[test]
    fn asks_are_approved_unseen_when_approvals_are_off_or_unattended_approve() {
        for config in [
            json!({ "approvals": { "mode": "off" } }),
            json!({ "approvals": { "mode": " OFF " } }),
            json!({ "approvals": { "mode": false } }),
            json!({ "approvals": { "cron_mode": "approve" } }),
            json!({ "approvals": { "single_query_mode": "yes" } }),
            json!({ "approvals": { "unattended_mode": "allow" } }),
        ] {
            assert!(approves_unseen(&config).is_some(), "{config}");
        }
        for config in [
            json!({}),
            json!({ "approvals": { "mode": "manual", "cron_mode": "deny" } }),
            json!({ "approvals": { "mode": "smart", "cron_mode": true } }),
        ] {
            assert_eq!(approves_unseen(&config), None, "{config}");
        }
    }
}
