//! Hermes Agent's `shell-hooks-allowlist.json` in the profile's directory:
//! `{"approvals": [{"event", "command", "approved_at",
//! "script_mtime_at_approval"}, …]}` (`agent/shell_hooks.py`, v0.22.5).
//!
//! Hermes registers a shell hook only when its `(event, command)` pair is
//! there, the command matched exactly as `config.yaml` spells it (trimmed). A
//! foreground `hermes chat` asks the person about one that is not; the
//! gateway, cron, ACP and `mcp-serve` skip it with a warning in the log, so
//! every call there would run unchecked. Hermes reads only `event` and
//! `command`; `approved_at` is shown by `hermes hooks list`. A file whose
//! `approvals` is not a list is unreadable to Hermes, which then trusts no
//! hook, so OpenMoat refuses to edit it.

use serde_json::{Value, json};

use super::hook_file::{binary_of, command_for};
use crate::HookSpec;
use crate::contract::ConsentFile;

/// The allowlist's file name in the Hermes home.
const FILE: &str = "shell-hooks-allowlist.json";

#[derive(Debug)]
pub(crate) struct Allowlist;

pub(crate) static ALLOWLIST: Allowlist = Allowlist;

impl ConsentFile for Allowlist {
    fn name(&self) -> &'static str {
        FILE
    }

    fn without(&self) -> &'static str {
        "Hermes Agent's gateway, cron and ACP sessions skip the hook, and `hermes chat` asks \
         before it runs it"
    }

    fn upsert(
        &self,
        doc: &mut Value,
        id: &str,
        hooks: &[HookSpec],
        binary: &str,
        now: &str,
    ) -> Result<bool, String> {
        let approvals = approvals_mut(doc)?;
        let mut changed = false;
        for spec in hooks {
            let command = command_for(binary, id, cfg!(windows));
            let before = approvals.len();
            // Consent to OpenMoat's guard with another binary is stale.
            approvals.retain(|e| {
                !(event(e) == Some(spec.event)
                    && entry_command(e).is_some_and(|c| c != command && binary_of(c, id).is_some()))
            });
            changed |= approvals.len() != before;
            if !approvals
                .iter()
                .any(|e| event(e) == Some(spec.event) && entry_command(e) == Some(&command))
            {
                approvals.push(json!({
                    "event": spec.event,
                    "command": command,
                    "approved_at": now,
                    "script_mtime_at_approval": null,
                }));
                changed = true;
            }
        }
        Ok(changed)
    }

    fn holds(&self, doc: &Value, id: &str, hooks: &[HookSpec], binary: &str) -> bool {
        let Some(approvals) = doc.get("approvals").and_then(Value::as_array) else {
            return false;
        };
        hooks.iter().all(|spec| {
            let command = command_for(binary, id, cfg!(windows));
            approvals
                .iter()
                .any(|e| event(e) == Some(spec.event) && entry_command(e) == Some(&command))
        })
    }

    fn remove(&self, doc: &mut Value, id: &str) -> bool {
        let Some(approvals) = doc.get_mut("approvals").and_then(Value::as_array_mut) else {
            return false;
        };
        let before = approvals.len();
        approvals.retain(|e| entry_command(e).is_none_or(|c| binary_of(c, id).is_none()));
        approvals.len() != before
    }

    fn is_empty(&self, doc: &Value) -> bool {
        doc.as_object().is_some_and(|top| {
            top.iter().all(|(key, value)| {
                key == "approvals" && value.as_array().is_some_and(Vec::is_empty)
            })
        })
    }
}

/// The `approvals` list of `doc`, made when there is none.
fn approvals_mut(doc: &mut Value) -> Result<&mut Vec<Value>, String> {
    let Value::Object(top) = doc else {
        return Err(format!("{FILE} is not a JSON object"));
    };
    let approvals = top
        .entry("approvals")
        .or_insert_with(|| Value::Array(Vec::new()));
    match approvals {
        Value::Array(list) => Ok(list),
        _ => Err(format!(
            "`approvals` in {FILE} is not a list, so Hermes Agent trusts no hook"
        )),
    }
}

fn event(entry: &Value) -> Option<&str> {
    entry.get("event").and_then(Value::as_str)
}

fn entry_command(entry: &Value) -> Option<&str> {
    entry.get("command").and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use serde_json::Map;

    use super::*;

    const HOOKS: &[HookSpec] = &[HookSpec::new("pre_tool_call", "", 60, false)];

    fn ours(binary: &str) -> String {
        command_for(binary, "hermes", cfg!(windows))
    }

    #[test]
    fn consent_is_added_once_and_a_stale_binary_replaced() {
        let other = json!({ "event": "pre_tool_call", "command": "~/.hermes/agent-hooks/x.sh" });
        let mut doc = json!({ "approvals": [other.clone()] });
        assert!(
            ALLOWLIST
                .upsert(&mut doc, "hermes", HOOKS, "/old/openmoat", "t0")
                .unwrap()
        );
        assert!(ALLOWLIST.holds(&doc, "hermes", HOOKS, "/old/openmoat"));
        assert!(
            !ALLOWLIST
                .upsert(&mut doc, "hermes", HOOKS, "/old/openmoat", "t1")
                .unwrap(),
            "a second init changes nothing"
        );
        assert!(
            ALLOWLIST
                .upsert(&mut doc, "hermes", HOOKS, "/new/openmoat", "t2")
                .unwrap()
        );
        assert!(!ALLOWLIST.holds(&doc, "hermes", HOOKS, "/old/openmoat"));
        assert!(ALLOWLIST.holds(&doc, "hermes", HOOKS, "/new/openmoat"));
        let approvals = doc["approvals"].as_array().unwrap();
        assert_eq!(approvals.len(), 2, "{doc}");
        assert_eq!(approvals[0], other, "the person's own consent stays first");
        assert_eq!(approvals[1]["command"], json!(ours("/new/openmoat")));
        assert_eq!(approvals[1]["approved_at"], json!("t2"));
    }

    #[test]
    fn remove_takes_out_only_openmoat_and_an_empty_file_is_empty() {
        let mut doc = Value::Object(Map::new());
        ALLOWLIST
            .upsert(&mut doc, "hermes", HOOKS, "/x/openmoat", "t")
            .unwrap();
        assert!(!ALLOWLIST.is_empty(&doc));
        assert!(ALLOWLIST.remove(&mut doc, "hermes"));
        assert!(ALLOWLIST.is_empty(&doc), "{doc}");
        assert!(!ALLOWLIST.remove(&mut doc, "hermes"));
        let mut kept = json!({ "approvals": [{ "event": "post_tool_call", "command": "log.sh" }] });
        assert!(!ALLOWLIST.remove(&mut kept, "hermes"));
        assert!(!ALLOWLIST.is_empty(&kept));
    }

    #[test]
    fn a_file_hermes_cannot_read_is_refused() {
        for mut doc in [json!([]), json!({ "approvals": {} })] {
            assert!(
                ALLOWLIST
                    .upsert(&mut doc, "hermes", HOOKS, "/x/openmoat", "t")
                    .is_err(),
                "{doc}"
            );
        }
        assert!(!ALLOWLIST.holds(&json!({}), "hermes", HOOKS, "/x/openmoat"));
    }
}
