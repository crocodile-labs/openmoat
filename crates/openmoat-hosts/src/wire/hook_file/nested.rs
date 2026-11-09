//! Claude Code's exec-form layout (`settings.json`):
//! `{"hooks": {"<Event>": [{"matcher": …, "hooks": [{type, command,
//! args, timeout}]}]}}`. Our entries are recognised by their `args`
//! (`guard --host <id>`, then `--home <state directory>`).

use serde_json::{Value, json};

use super::HookFile;
use crate::HookSpec;
use crate::wire::guard_command::{GuardCommand, is_guard_list};

/// Claude Code's `settings.json` entries; also recognises legacy Codex entries.
#[derive(Debug)]
pub(crate) struct Nested;

impl HookFile for Nested {
    fn entry(&self, spec: &HookSpec, id: &str, guard: &GuardCommand, block: bool) -> Value {
        let mut hook = json!({
            "type": "command",
            "command": guard.binary,
            "args": guard.arg_list(id),
            "timeout": spec.timeout,
        });
        if block {
            // Claude Code v2.1.295+: a hook that fails to start, crashes,
            // exits other than 0 or 2, or times out blocks the call as exit 2
            // does (<https://code.claude.com/docs/en/hooks>, "Block the
            // action when a hook fails"); without it the call runs.
            hook["onFailure"] = json!("block");
        }
        json!({ "matcher": spec.matcher, "hooks": [hook] })
    }

    fn is_ours(&self, entry: &Value, id: &str) -> bool {
        entry
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|hooks| {
                hooks.iter().any(|h| {
                    h.get("args").and_then(Value::as_array).is_some_and(|args| {
                        let args: Vec<&str> = args.iter().filter_map(Value::as_str).collect();
                        is_guard_list(&args, id)
                    })
                })
            })
    }

    fn binary(&self, entry: &Value, _id: &str) -> Option<String> {
        let command = entry.pointer("/hooks/0/command").and_then(Value::as_str)?;
        Some(command.to_owned())
    }

    fn knows_on_failure(&self) -> bool {
        true
    }
}
