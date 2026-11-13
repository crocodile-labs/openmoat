//! The row for `codex`.
//!
//! Uninstall: `uninstall.rs`; a review: `codex.rs`.

use serde_json::json;

use super::{HooksOff, PRE_TOOL_USE, Row, pre_tool_use};

pub fn row() -> Row {
    Row {
        id: "codex",
        hook: "codex",
        governed: "codex/pretooluse-shell.json",
        unknown_tool: || pre_tool_use("future_tool"),
        // `PostToolUse` is handled since ADR-063 (`codex.rs`).
        unknown_event: || {
            json!({"session_id": "s", "hook_event_name": "UserPromptSubmit",
                "prompt": "list the files"})
        },
        hooks_off: Some(HooksOff {
            file: "config.toml",
            change: |config| {
                let mut doc: toml_edit::DocumentMut = config.parse().unwrap();
                doc["features"]["hooks"] = toml_edit::value(false);
                doc.to_string()
            },
            before_init: false,
            names: "features.hooks",
        }),
        ..PRE_TOOL_USE
    }
}
