//! The sandbox backends, one per [`SandboxFormat`]: how each merges the plan
//! into its file, reports, checks and undoes it. The CLI reaches a host's
//! backend through [`backend`] and names no host.

use std::path::Path;

use anyhow::Result;
use openmoat_core::Secret;
use openmoat_hosts::{Host, SandboxFormat};
use serde_json::Value;
use toml_edit::DocumentMut;

use super::install::Rendered;
use super::{Plan, Report, claude, codex, cursor};
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

/// One sandbox settings format's backend.
pub trait SandboxBackend: Sync {
    /// `current` (the text of `host`'s sandbox settings file) with the plan
    /// merged in; `None` when it would not change.
    fn render(
        &self,
        home: &Home,
        host: Host,
        plan: &Plan,
        current: &str,
    ) -> Result<Option<Rendered>>;
    /// What the backend loses and widens against the policy.
    fn report<'a>(&self, plan: &'a Plan) -> &'a Report;
    /// What OpenMoat owns in the file, in the file's own format, as
    /// `moat sandbox show` prints it.
    fn shown(&self, plan: &Plan) -> Result<String>;
    /// Problems with the settings at `path` (its directory exists).
    fn problems(
        &self,
        home: &Home,
        path: &Path,
        plan: &Plan,
        lock: Option<&Lock>,
    ) -> Result<Vec<String>>;
    /// How `moat uninstall` removes the settings.
    fn undo(&self) -> Undo;
    /// How the lock pins the settings file.
    fn pin(&self) -> Pin;
    /// Whether the host's own broker masks the policy's secrets from these settings.
    fn masks_secrets(&self) -> bool {
        false
    }
    /// What the host's own broker does with each of `secrets`, in order, given
    /// the settings document `settings`; empty for a backend that does not
    /// [`masks_secrets`](Self::masks_secrets).
    fn secret_masks<'a>(
        &self,
        _settings: &Value,
        _secrets: &'a [Secret],
        _plan: &Plan,
    ) -> Vec<SecretMask<'a>> {
        Vec::new()
    }
}

/// The backend that writes `format`.
pub fn backend(format: SandboxFormat) -> &'static dyn SandboxBackend {
    match format {
        SandboxFormat::ClaudeSettings => &claude::backend::ClaudeSettings,
        SandboxFormat::CodexProfile => &codex::backend::CodexProfile,
        SandboxFormat::CursorSandbox => &cursor::backend::CursorSandbox,
    }
}

pub(super) const OUT_OF_DATE: &str = "differs from the policy; run `openmoat sandbox sync`";
pub(super) const NOT_PINNED: &str = "not pinned by the lock; run `openmoat sandbox sync`";
