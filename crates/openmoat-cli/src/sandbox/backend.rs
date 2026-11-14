//! The sandbox backends, one per [`SandboxFormat`]: how each generates its
//! settings from the IR, merges them into its file, reports, checks and undoes
//! them. The CLI reaches a host's backend through [`super::backend_of`] and its
//! settings through [`Plan::output`], and names no host.
//!
//! The one list of backends is [`super::backend_of`] in `sandbox.rs`, beside
//! the backends' module declarations: a format's backend lives in its own
//! module there, so a new sandboxed host needs its spec's
//! [`openmoat_hosts::SandboxSpec`] and its backend, and no other edit.

use std::fmt::Debug;
use std::path::Path;

use anyhow::Result;
use openmoat_core::Secret;
use openmoat_core::ir::Enforcement;
use openmoat_hosts::Host;
use serde_json::Value;
use toml_edit::DocumentMut;

use super::install::Rendered;
use super::{Plan, Report};
use crate::home::Home;
use crate::integrity::Lock;

/// How `moat uninstall` takes a backend's settings out of its file.
#[derive(Clone, Copy)]
pub enum Undo {
    /// The settings share the hook file and go with the hooks; the function
    /// strips them, given the rules `hosts.json` records as OpenMoat's.
    WithHooks(fn(&mut Value, &[String]) -> bool),
    /// A TOML file of its own; the function strips OpenMoat's part.
    Toml(fn(&mut DocumentMut) -> bool),
    /// A JSON file of its own; the function strips OpenMoat's keys.
    Json(fn(&mut Value) -> bool),
}

/// How the policy lock pins a backend's settings file.
#[derive(Clone, Copy)]
pub enum Pin {
    /// The settings are in the hook file, which is pinned with the hooks.
    WithHooks,
    /// Pinned whole, when the function finds OpenMoat's keys in the file.
    Whole(fn(&Path) -> Result<bool>),
    /// The host edits the rest of the file itself, so only the part OpenMoat
    /// owns is pinned, when `carries` finds that part in the file.
    Part {
        carries: fn(&Path) -> Result<bool>,
        digest: fn(&Path) -> Result<String>,
    },
}

/// How [`SecretMask`] counts in `moat doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskLevel {
    /// The host's broker masks the secret.
    Masked,
    /// The settings lack what masking needs: a warning.
    NotWritten,
    /// Not masked, for a reason the row gives: a note.
    Unmasked,
}

/// What a host's own broker does with one policy secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMask<'a> {
    pub secret: &'a Secret,
    /// The state, worded for one output line.
    pub text: String,
    pub level: MaskLevel,
}

/// What every backend generates its settings from.
pub struct Input<'a> {
    /// The policy lowered for host-wide settings ([`super::lower_for_hosts`]).
    pub ir: &'a Enforcement,
    /// The loopback port of `moat proxy` the sandboxed commands' traffic goes
    /// to, when the policy opts in.
    pub proxy_port: Option<u16>,
    /// The user's home directory as written, then resolved where that differs.
    pub homes: &'a [String],
    /// The paths of the `moat` binary the hooks run, which commands must not
    /// write ([`crate::install::self_paths::sandbox_paths`]).
    pub binary_paths: &'a [String],
    /// Whether the host sandboxes run on Linux, where Claude Code and Codex
    /// confine commands with bubblewrap rather than Seatbelt.
    pub linux: bool,
}

/// One sandbox settings format's backend.
pub trait SandboxBackend: Sync {
    /// The settings for `input`'s IR, ready to merge into the host's file
    /// `settings` ([`super::install::settings_path`]), which they keep from
    /// commands wherever it was moved.
    fn generate(&self, input: &Input<'_>, settings: &Path) -> Result<Box<dyn Output>>;
    /// How `moat uninstall` removes the settings.
    fn undo(&self) -> Undo;
    /// How the lock pins the settings file.
    fn pin(&self) -> Pin;
    /// Whether the host's own broker masks the policy's secrets from these settings.
    fn masks_secrets(&self) -> bool {
        false
    }
}

/// One host's generated settings, held by the [`Plan`].
pub trait Output: Debug {
    /// `current` (the text of `host`'s sandbox settings file) with these
    /// settings merged in; `None` when it would not change.
    fn render(&self, home: &Home, host: Host, current: &str) -> Result<Option<Rendered>>;
    /// What the settings lose and widen against the policy.
    fn report(&self) -> &Report;
    /// What OpenMoat owns in the file, in the file's own format, as
    /// `moat sandbox show` prints it.
    fn shown(&self) -> Result<String>;
    /// Problems with the settings at `path` (its directory exists).
    fn problems(
        &self,
        home: &Home,
        path: &Path,
        plan: &Plan,
        lock: Option<&Lock>,
    ) -> Result<Vec<String>>;
    /// The absolute directories the settings let commands write besides the
    /// project and the temp directory.
    fn writable_dirs(&self) -> Vec<String>;
    /// What the host's own broker does with each of `secrets`, in order, given
    /// the settings document `settings`; empty for a backend that does not
    /// [`masks_secrets`](SandboxBackend::masks_secrets).
    fn secret_masks<'a>(&self, _settings: &Value, _secrets: &'a [Secret]) -> Vec<SecretMask<'a>> {
        Vec::new()
    }
}

/// The strings of the JSON array `value`, if it is one.
pub(super) fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

pub(super) const OUT_OF_DATE: &str = "differs from the policy; run `openmoat sandbox sync`";
pub(super) const NOT_PINNED: &str = "not pinned by the lock; run `openmoat sandbox sync`";
