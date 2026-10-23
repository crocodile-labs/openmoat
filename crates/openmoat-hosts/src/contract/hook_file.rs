//! Each [`HookFormat`] whose entries sit among the person's own, to the
//! [`HookFile`] code that edits it. The files OpenMoat owns whole (OpenClaw's
//! plugin, pi's extension) are still edited by the CLI.

use super::{HookFormat, InstallSpec};
use crate::host::{copilot_cli, cursor, gemini_cli};
use crate::wire::hook_file::{HookFile, nested};

impl HookFormat {
    /// The layout code for this format's entries; `None` for OpenClaw and pi,
    /// whose hook files the CLI writes whole.
    #[must_use]
    pub fn hook_file(self) -> Option<&'static dyn HookFile> {
        match self {
            Self::Nested => Some(&nested::Nested),
            Self::Cursor => Some(&cursor::hook_file::Cursor),
            Self::Copilot => Some(&copilot_cli::hook_file::Copilot),
            Self::Gemini => Some(&gemini_cli::hook_file::Gemini),
            Self::OpenClaw | Self::Pi => None,
        }
    }
}

impl InstallSpec {
    /// The layout code for this host's hook file ([`HookFormat::hook_file`]).
    #[must_use]
    pub fn hook_file(&self) -> Option<&'static dyn HookFile> {
        self.hook_format.hook_file()
    }
}
