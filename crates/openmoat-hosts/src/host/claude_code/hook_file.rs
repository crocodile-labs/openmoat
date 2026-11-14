//! Claude Code's `settings.json`: the nested entries
//! ([`crate::wire::hook_file::nested`]) and one variable in its `env` block.
//!
//! A file the person names with `@` in a prompt is read by Claude Code itself
//! while it builds the prompt, with no tool call, so no `PreToolUse` hook sees
//! it, `Read` included. With `CLAUDE_CODE_DISABLE_FILE_MENTIONS=1` in the user
//! settings Claude gets the paths with a note to read them with its file
//! tools, whose calls the hook decides. Claude Code 2.1.299 or later reads
//! the variable, and only from the shell, the user settings or managed
//! settings, never from a project's or local settings
//! (<https://code.claude.com/docs/en/hooks>, `PreToolUse`). The settings'
//! `env` block is copied into Claude Code's own environment, so an older
//! version gains a variable it ignores.

use serde_json::Value;

use crate::wire::hook_file::nested::Nested;
use crate::{GuardCommand, HookFile, HookSpec};

/// The variable that sends `@` mentions through Claude Code's file tools.
const FILE_MENTIONS: (&str, &str) = ("CLAUDE_CODE_DISABLE_FILE_MENTIONS", "1");

/// Claude Code's `settings.json`.
#[derive(Debug)]
pub(super) struct Settings;

impl HookFile for Settings {
    fn entry(&self, spec: &HookSpec, id: &str, guard: &GuardCommand, block: bool) -> Value {
        Nested.entry(spec, id, guard, block)
    }

    fn is_ours(&self, entry: &Value, id: &str) -> bool {
        Nested.is_ours(entry, id)
    }

    fn binary(&self, entry: &Value, id: &str) -> Option<String> {
        Nested.binary(entry, id)
    }

    fn knows_on_failure(&self) -> bool {
        Nested.knows_on_failure()
    }

    fn env(&self) -> &'static [(&'static str, &'static str)] {
        &[FILE_MENTIONS]
    }
}
