//! The Codex CLI: `PreToolUse` in Claude Code's format
//! ([`crate::wire::pre_tool_use`]).

use openmoat_core::Decision;

use crate::contract::{Asks, HostAdapter, HostSpec, wrong_event};
use crate::wire::pre_tool_use;
use crate::{HookEvent, HookRequest, Host, HostError};

/// Codex's `PreToolUse` rejects `permissionDecision: "ask"` as unsupported and
/// then runs the call.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "codex",
    display_name: "Codex",
    speaks: None,
    asks: Asks {
        on_pre_tool_use: Some("Codex hooks cannot ask"),
        on_no_ask: None,
        defer_is_ask_on_no_ask: false,
    },
};

/// Codex sends only `PreToolUse`.
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
            other => Err(wrong_event(other)),
        }
    }

    fn render(&self, _event: &HookEvent, decision: &Decision) -> String {
        pre_tool_use::render(decision)
    }
}
