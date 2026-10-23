//! The row for `codex`.
//!
//! Uninstall: `uninstall.rs`; an ask: `codex.rs`.

use super::{HooksOff, PRE_TOOL_USE, Row, post_tool_use, pre_tool_use};

pub fn row() -> Row {
    Row {
        id: "codex",
        hook: "codex",
        governed: "codex/pretooluse-shell.json",
        unknown_tool: || pre_tool_use("future_tool"),
        unknown_event: post_tool_use,
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
