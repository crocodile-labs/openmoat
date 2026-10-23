//! How a host's hook file is laid out ([`super::InstallSpec::hook_file`]), as the
//! code that edits it: the CLI picks what to do from this, never from the host.

use crate::wire::hook_file::HookFile;
use crate::wire::owned_file::OwnedFile;

/// The layout of a host's hook file.
#[derive(Debug, Clone, Copy)]
pub enum HookLayout {
    /// OpenMoat's entries among the person's own in a `hooks` object (Claude
    /// Code, Codex, Cursor, GitHub Copilot CLI, Gemini CLI).
    Entries(&'static dyn HookFile),
    /// The hook file is OpenMoat's whole (pi's extension).
    Owned(&'static OwnedFile),
    /// A JSON5 configuration that loads a plugin OpenMoat owns whole, the
    /// host's first [`super::InstallSpec::extra_files`] (OpenClaw's
    /// `openclaw.json` and plugin).
    Plugin(&'static OwnedFile),
}

impl HookLayout {
    /// The code for the entries among the person's own; `None` for a file
    /// OpenMoat owns whole or a plugin configuration.
    #[must_use]
    pub fn entries(self) -> Option<&'static dyn HookFile> {
        match self {
            Self::Entries(layout) => Some(layout),
            Self::Owned(_) | Self::Plugin(_) => None,
        }
    }
}
