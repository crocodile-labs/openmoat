//! Which [`HostSpec`] describes each supported host.

use crate::contract::HostSpec;
use crate::{Host, host};

/// The facts about `host`, from its module under `host/`.
pub(crate) fn spec(host: Host) -> &'static HostSpec {
    match host {
        Host::ClaudeCode => &host::claude_code::SPEC,
        Host::Codex => &host::codex::SPEC,
        Host::Cursor => &host::cursor::SPEC,
        Host::Continue => &host::continue_cli::SPEC,
        Host::OpenClaw => &host::openclaw::SPEC,
    }
}
