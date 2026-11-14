//! A host whose searches that name no directory read every directory of its
//! workspace, which the hook payload does not name ([`WorkspaceSpec`]).

use openmoat_core::Action;

/// The directories a host's settings add to its workspace, and why a search
/// that names no directory is not all checked until the guard read them
/// ([`crate::HostSpec::workspace`]).
#[derive(Debug)]
#[non_exhaustive]
pub struct WorkspaceSpec {
    /// The directories one parsed settings file adds (Gemini CLI's
    /// `context.includeDirectories`); empty when it sets none.
    pub dirs: fn(&serde_json::Value) -> Vec<String>,
    /// What the payload of such a search does not show, as the review names
    /// it while the directories are unknown.
    pub unnamed: &'static str,
}

/// What an adapter marks a call as not showing ([`Action::Unchecked`]), by
/// kind; the text a person reads comes from the host's spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unchecked {
    /// A search over every directory of the host's workspace
    /// ([`WorkspaceSpec`]): the guard replaces the mark with reads of the
    /// directories the settings add ([`crate::HookRequest::with_workspace_dirs`]).
    WorkspaceWide,
}

impl Unchecked {
    /// `action` marked as this kind under `spec`.
    pub(crate) fn mark(self, spec: &WorkspaceSpec, action: Action) -> Action {
        match self {
            Self::WorkspaceWide => Action::unchecked(action, spec.unnamed),
        }
    }

    /// Whether an [`Action::Unchecked`] whose reason is `reason` is this
    /// kind's mark under `spec`. Only the spec of the host that sent the
    /// request is asked, so another host's reason never counts.
    pub(crate) fn marks(self, spec: &WorkspaceSpec, reason: &str) -> bool {
        match self {
            Self::WorkspaceWide => reason == spec.unnamed,
        }
    }
}
