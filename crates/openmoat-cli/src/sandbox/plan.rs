//! The Standard tier's plan: one generated output per host with a sandbox
//! ([`openmoat_hosts::HostSpec::sandbox`]), each from its format's backend.

use std::path::PathBuf;

use anyhow::Result;
use openmoat_core::Policy;
use openmoat_hosts::Host;

use super::backend::{Input, Output, SandboxBackend};
use super::{install, lower_for_hosts, proxy_port, with_read_roots};
use crate::home::Home;

/// Whether the host sandboxes run on Linux, where Claude Code and Codex use
/// bubblewrap ([`Input::linux`]).
const LINUX: bool = cfg!(target_os = "linux");

/// Everything the Standard tier writes for one policy on this machine.
#[derive(Debug)]
pub struct Plan {
    /// The policy had no `sandbox.read_roots`, so the default policy's apply.
    pub default_read_roots: bool,
    /// The loopback port the host sandboxes send their commands' traffic to,
    /// when the policy opts in.
    pub proxy_port: Option<u16>,
    /// `sandbox.proxy_serve_without_credential` (ADR-044): `openmoat proxy`
    /// serves requests that carry no session credential.
    pub serve_without_credential: bool,
    /// Each sandboxed host's generated settings, in [`install::hosts`] order.
    outputs: Vec<(Host, Box<dyn Output>)>,
}

/// A host's backend and the file its sandbox settings go into.
type Sandbox = (Host, &'static dyn SandboxBackend, PathBuf);

impl Plan {
    /// Generate every backend for `policy` and the current user's home, for
    /// the `moat` binary the lock recorded.
    pub fn new(home: &Home, policy: &Policy) -> Result<Self> {
        let binary = crate::install::self_paths::recorded_binary(home)?;
        Self::for_binary(home, policy, &binary)
    }

    /// [`Plan::new`] for hooks that run `binary`, whose paths every backend
    /// keeps from writes (`moat init` passes the binary it is about to record).
    pub fn for_binary(state: &Home, policy: &Policy, binary: &std::path::Path) -> Result<Self> {
        let binary_paths = crate::install::self_paths::sandbox_paths(binary);
        let mut policy = policy.clone();
        crate::install::self_paths::protect(&mut policy, &binary_paths);
        let (policy, default_read_roots) = with_read_roots(&policy)?;
        let (home, real_home) = crate::context::home_spellings()?;
        let homes: Vec<String> = std::iter::once(home.clone())
            .chain(real_home.clone())
            .collect();
        let ir = lower_for_hosts(
            &policy,
            &home,
            real_home,
            crate::context::moved_dirs(state)?,
            crate::context::CASE_INSENSITIVE_PATHS,
        )?;
        let mut sandboxes = Vec::new();
        for host in install::hosts() {
            if let Some(backend) = install::backend(host) {
                sandboxes.push((host, backend, install::settings_path(state, host)?));
            }
        }
        let proxy_port = proxy_port(&policy);
        let input = Input {
            ir: &ir,
            proxy_port,
            homes: &homes,
            binary_paths: &binary_paths,
            linux: LINUX,
        };
        Ok(Self {
            default_read_roots,
            proxy_port,
            serve_without_credential: policy
                .sandbox
                .as_ref()
                .is_some_and(|s| s.proxy_serve_without_credential),
            outputs: generate(&input, sandboxes)?,
        })
    }

    /// `host`'s generated settings; `None` for a host without a sandbox.
    pub fn output(&self, host: Host) -> Option<&dyn Output> {
        self.outputs
            .iter()
            .find(|(h, _)| *h == host)
            .map(|(_, output)| output.as_ref())
    }

    /// The absolute directories the host sandboxes let commands write besides
    /// the project and the temp directory, from each backend's settings.
    pub fn writable_dirs(&self) -> Vec<String> {
        self.outputs
            .iter()
            .flat_map(|(_, output)| output.writable_dirs())
            .collect()
    }
}

/// Each of `sandboxes` generated from `input`, with its own settings file.
fn generate(
    input: &Input<'_>,
    sandboxes: impl IntoIterator<Item = Sandbox>,
) -> Result<Vec<(Host, Box<dyn Output>)>> {
    sandboxes
        .into_iter()
        .map(|(host, backend, settings)| Ok((host, backend.generate(input, &settings)?)))
        .collect()
}

#[cfg(test)]
mod tests;
