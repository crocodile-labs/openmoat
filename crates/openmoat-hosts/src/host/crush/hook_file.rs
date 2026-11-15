//! Crush's `crush.json` entries: a flat list per event, each entry
//! `{name, matcher, command, timeout}`, not Claude Code's nested groups
//! (`HookConfig` in `internal/hooks/config.go`; the hooks page). `matcher` is
//! a regular expression on the tool name, and an entry without one runs for
//! every tool; `timeout` is in seconds.
//!
//! Crush runs `command` in its embedded POSIX shell (`mvdan.cc/sh`, since
//! v0.67.0), so the binary is quoted for `sh`.

use serde_json::{Value, json};

use crate::HookSpec;
use crate::wire::guard_command::{GuardCommand, sh_binary, sh_command};
use crate::wire::hook_file::HookFile;

/// Crush's `crush.json` entries.
#[derive(Debug)]
pub(crate) struct Crush;

/// The entry's `name`, as Crush lists its hooks.
const NAME: &str = "openmoat";

impl HookFile for Crush {
    fn entry(&self, spec: &HookSpec, id: &str, guard: &GuardCommand, _block: bool) -> Value {
        let mut entry = json!({
            "name": NAME,
            "command": sh_command(guard, id),
            "timeout": spec.timeout,
        });
        if !spec.matcher.is_empty() {
            entry["matcher"] = Value::from(spec.matcher);
        }
        entry
    }

    fn is_ours(&self, entry: &Value, id: &str) -> bool {
        self.binary(entry, id).is_some()
    }

    fn binary(&self, entry: &Value, id: &str) -> Option<String> {
        sh_binary(entry.get("command")?.as_str()?, id)
    }
}
