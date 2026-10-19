//! Which [`HostSpec`] describes each supported host.

use crate::contract::{Asks, HostSpec};
use crate::{Host, host};

/// The facts about `host`, from its module under `host/`.
pub(crate) fn spec(host: Host) -> &'static HostSpec {
    match host {
        Host::ClaudeCode => &host::claude_code::SPEC,
        Host::Codex => &host::codex::SPEC,
        Host::Cursor => &host::cursor::SPEC,
        Host::Continue => &host::continue_cli::SPEC,
        Host::OpenClaw => &OPENCLAW,
    }
}

/// OpenClaw, through OpenMoat's plugin and its `before_tool_call` hook. Kept
/// here until the OpenClaw module moves under `host/`.
static OPENCLAW: HostSpec = HostSpec {
    id: "openclaw",
    display_name: "OpenClaw",
    speaks: None,
    asks: Asks {
        on_pre_tool_use: None,
        on_no_ask: None,
        defer_is_ask_on_no_ask: false,
    },
};
