//! goose's `hooks/hooks.json` entries in OpenMoat's plugin: the Open Plugins
//! layout, one rule with no `matcher` (every tool) and one command action
//! that sets `on_failure: block`.
//!
//! goose runs `command` with `sh -c`, on Windows too (`hook_command` in
//! `crates/goose/src/hooks/mod.rs`, v1.57.0), so the binary path is quoted
//! for `sh`. It reads `timeout` in seconds. `on_failure` is read only on a
//! `PreToolUse` command action: `allow` (the default) runs a call whose hook
//! failed, `block` denies it; any other value makes goose skip the whole
//! file, so the entry writes exactly `block`.

use serde_json::{Value, json};

use crate::HookSpec;
use crate::wire::guard_command::GuardCommand;
/// `'binary' guard --host <id>`, quoted for `sh`, and the binary it runs.
pub(super) use crate::wire::guard_command::{sh_binary as binary_of, sh_command as command_for};
use crate::wire::hook_file::HookFile;

/// goose's `hooks.json` entries.
#[derive(Debug)]
pub(crate) struct Goose;

/// The value of `on_failure` that blocks a call whose hook failed.
pub(crate) const BLOCK: &str = "block";

impl HookFile for Goose {
    /// The rule has no `matcher` when the spec's is empty: goose then runs it
    /// for every tool (an empty one is skipped as "none" too).
    fn entry(&self, spec: &HookSpec, id: &str, guard: &GuardCommand, _block: bool) -> Value {
        let mut entry = json!({
            "hooks": [{
                "type": "command",
                "command": command_for(guard, id),
                "timeout": spec.timeout,
                "on_failure": BLOCK,
            }],
        });
        if !spec.matcher.is_empty() {
            entry["matcher"] = Value::from(spec.matcher);
        }
        entry
    }

    fn is_ours(&self, entry: &Value, id: &str) -> bool {
        entry
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|hooks| {
                hooks.iter().any(|h| {
                    h.get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|c| binary_of(c, id).is_some())
                })
            })
    }

    fn binary(&self, entry: &Value, id: &str) -> Option<String> {
        binary_of(entry.pointer("/hooks/0/command").and_then(Value::as_str)?, id)
    }
}
