//! Anthropic's Claude Code: `PreToolUse` ([`crate::wire::pre_tool_use`]) and
//! `ConfigChange` ([`config_change`]).

use openmoat_core::Decision;
use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};
use crate::contract::{Asks, HostAdapter, HostSpec, wrong_event};
use crate::wire::pre_tool_use::{self, bench};
use crate::{HookEvent, HookRequest, Host, HostError};

pub(crate) mod config_change;

/// Claude Code asks on `PreToolUse`, except in a permission mode that puts no
/// question to a person (`bypassPermissions`, `dontAsk`).
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "claude-code",
    display_name: "Claude Code",
    speaks: None,
    asks: Asks {
        on_pre_tool_use: None,
        on_no_ask: Some("Claude Code's permission mode does not ask"),
        defer_is_ask_on_no_ask: false,
    },
    on_hook_failure: "runs the call when the hook is missing, cannot start, exits non-zero \
         other than 2, or times out (default 600 s)",
};

/// Claude Code's format, also sent by the Continue CLI.
pub(crate) struct Adapter;

pub(crate) static ADAPTER: Adapter = Adapter;

impl HostAdapter for Adapter {
    fn spec(&self) -> &'static HostSpec {
        &SPEC
    }

    /// `PreToolUse` may come without its event name.
    fn parse(
        &self,
        host: Host,
        event: Option<&str>,
        payload: &str,
    ) -> Result<HookRequest, HostError> {
        match event {
            None | Some(pre_tool_use::EVENT) => pre_tool_use::parse(host, payload),
            Some(config_change::EVENT) => config_change::parse(host, payload),
            other => Err(wrong_event(other)),
        }
    }

    fn event_of(&self, event: &str) -> HookEvent {
        if event == config_change::EVENT {
            HookEvent::ConfigChange {
                source: String::new(),
                change_type: None,
            }
        } else {
            HookEvent::PreToolUse
        }
    }

    fn render(&self, event: &HookEvent, decision: &Decision) -> String {
        match event {
            HookEvent::PreToolUse | HookEvent::PreToolUseNoAsk => pre_tool_use::render(decision),
            HookEvent::ConfigChange { .. } => config_change::render(decision),
        }
    }

    fn bench_payload(&self, call: &Call, at: &Place<'_>) -> Option<String> {
        let (tool, input) = match call {
            Call::Read(path) => ("Read".to_owned(), json!({ "file_path": at.file(path) })),
            Call::Write(path) => (
                "Write".to_owned(),
                json!({ "file_path": at.file(path), "content": CONTENT }),
            ),
            Call::Edit(path) => (
                "Edit".to_owned(),
                json!({ "file_path": at.file(path), "old_string": "old", "new_string": CONTENT }),
            ),
            Call::Fetch(url) => (
                "WebFetch".to_owned(),
                json!({ "url": url, "prompt": "summarise" }),
            ),
            other => bench::common_tool(other)?,
        };
        Some(bench::payload(&tool, &input, at))
    }

    fn read_reply(&self, _call: &Call, exit: &Exit<'_>) -> Answer {
        bench::read_reply(exit, true)
    }
}
