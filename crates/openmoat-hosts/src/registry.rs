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

    /// A host spec takes [`HostSpec::BASE`](crate::HostSpec::BASE) only for
    /// optional fields: every host names its own required ones.
    #[test]
    fn every_host_names_its_required_spec_fields() {
        for host in Host::EVERY {
            let spec = spec(host);
            for (field, value) in [
                ("id", spec.id),
                ("display_name", spec.display_name),
                ("on_hook_failure", spec.on_hook_failure),
                ("gaps", spec.gaps),
            ] {
                assert!(!value.is_empty(), "{host:?} names no {field}");
            }
            if let Some(install) = &spec.install {
                for (field, value) in [
                    ("dir_variable", install.dir_variable),
                    ("dir_name", install.dir_name),
                    ("config_file", install.config_file),
                ] {
                    assert!(!value.is_empty(), "{host:?} install names no {field}");
                }
                assert!(!install.hooks.is_empty(), "{host:?} installs no hook");
            }
        }
    }

    /// `Host::EVERY` is `Host::ALL` and the hosts that speak another's format.
    #[test]
    fn every_is_all_and_the_hosts_that_speak_another_format() {
        for host in Host::ALL {
            assert!(Host::EVERY.contains(&host), "{host:?}");
        }
        for host in Host::EVERY {
            let installs = Host::ALL.contains(&host);
            assert_eq!(installs, spec(host).speaks.is_none(), "{host:?}");
        }
    }

    /// A host's adapter is its own, or the one of the host it speaks.
    #[test]
    fn each_host_reads_the_format_its_spec_names() {
        for host in Host::EVERY {
            let format = spec(host).speaks.unwrap_or(host);
            assert_eq!(adapter(host).spec().id, format.id(), "{host:?}");
        }
    }
}
