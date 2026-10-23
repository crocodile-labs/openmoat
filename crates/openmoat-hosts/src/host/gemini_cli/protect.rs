//! Gemini CLI's files the default policy and the taint list protect, and its
//! processes.

use crate::contract::{Paths, ProcessSpec, Protect};

pub(super) const PROTECT: Protect = Protect {
    self_paths: &[Paths::new(
        "Gemini CLI: its directory, the settings that hold OpenMoat's hook (a\n\
         project's are merged over them and can turn hooks off) and the folder\n\
         trust list, which decides whether settings hooks run at all",
        &[
            "~/.gemini",
            "**/.gemini",
            "~/.gemini/settings.json",
            "~/.gemini/trustedFolders.json",
            "**/.gemini/settings.json",
        ],
    )],
    taint: &[Paths::new(
        "Gemini CLI: its settings, extensions and the memory file it loads into\n\
         every session",
        &["**/GEMINI.md", "**/.gemini", "**/.gemini/**"],
    )],
};

pub(super) const PROCESS: ProcessSpec = ProcessSpec {
    names: &["gemini"],
    package_dirs: &[&["@google", "gemini-cli"]],
    helper: None,
};
