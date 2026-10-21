//! Which [`HostSpec`] describes each supported host, and which
//! [`HostAdapter`] reads its format.

use crate::contract::{HostAdapter, HostSpec};
use crate::{Host, host};

/// The facts about `host`, from its module under `host/`: its adapter's, unless
/// it sends another host's format.
pub(crate) fn spec(host: Host) -> &'static HostSpec {
    match host {
        Host::Continue => &host::continue_cli::SPEC,
        own => adapter(own).spec(),
    }
}

/// The adapter for the format `host` sends: its own, or the one its spec
/// [`speaks`](HostSpec::speaks).
pub(crate) fn adapter(host: Host) -> &'static dyn HostAdapter {
    match host {
        Host::ClaudeCode | Host::Continue => &host::claude_code::ADAPTER,
        Host::Codex => &host::codex::ADAPTER,
        Host::Cursor => &host::cursor::ADAPTER,
        Host::OpenClaw => &host::openclaw::ADAPTER,
        Host::CopilotCli => &host::copilot_cli::ADAPTER,
        Host::Pi => &host::pi::ADAPTER,
        Host::GeminiCli => &host::gemini_cli::ADAPTER,
    }
}

#[cfg(test)]
mod tests {
    use super::{adapter, spec};
    use crate::Host;

    /// A host's adapter is its own, or the one of the host it speaks.
    #[test]
    fn each_host_reads_the_format_its_spec_names() {
        for host in [
            Host::ClaudeCode,
            Host::Codex,
            Host::Cursor,
            Host::Continue,
            Host::OpenClaw,
            Host::CopilotCli,
            Host::Pi,
            Host::GeminiCli,
        ] {
            let format = spec(host).speaks.unwrap_or(host);
            assert_eq!(adapter(host).spec().id, format.id(), "{host:?}");
        }
    }
}
