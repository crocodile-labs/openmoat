//! The nested layout Claude Code (`settings.json`) and Codex (`hooks.json`)
//! share: `{"hooks": {"<Event>": [{"matcher": …, "hooks": [{type, command,
//! args, timeout}]}]}}`. Our entries are recognised by their `args`
//! (`guard --host <id>`).

use serde_json::{Value, json};

use super::HookFile;
use crate::HookSpec;

/// [`crate::HookFormat::Nested`].
pub(crate) struct Nested;

impl HookFile for Nested {
    fn entry(&self, spec: &HookSpec, id: &str, binary: &str, block: bool) -> Value {
        let mut hook = json!({
            "type": "command",
            "command": binary,
            "args": ["guard", "--host", id],
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
                        args == ["guard", "--host", id]
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
