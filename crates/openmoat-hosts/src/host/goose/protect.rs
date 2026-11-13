//! goose's files the default policy and the taint list protect, and its
//! processes.

use crate::contract::{Paths, ProcessSpec, Protect};

pub(super) const PROTECT: Protect = Protect {
    self_paths: &[Paths::new(
        "goose: its configuration (`config.yaml` turns plugins and extensions on\n\
         and off), the plugin settings that can turn OpenMoat's plugin off, and\n\
         the plugin directories whose `hooks/hooks.json` it runs: the person's,\n\
         with OpenMoat's own, and a project's, which can replace it",
        &[
            "~/.config/goose",
            "~/.config/goose/config.yaml",
            "~/.config/goose/settings.json",
            "**/.config/goose/settings.json",
            "**/.config/goose/settings.local.json",
            "~/.agents/plugins",
            "~/.agents/plugins/**",
            "**/.agents/plugins",
            "**/.agents/plugins/**",
        ],
    )],
    taint: &[Paths::new(
        "goose: the hints it loads into every session, its configuration, saved\n\
         recipes and plugin settings, and the plugins whose hooks it runs",
        &[
            "**/.goosehints",
            "~/.config/goose",
            "~/.config/goose/**",
            "**/.config/goose/**",
            "**/.agents/plugins",
            "**/.agents/plugins/**",
        ],
    )],
    credentials: &[Paths::new(
        "goose: the provider keys it keeps in a file when the keyring is off\n\
         (`GOOSE_DISABLE_KEYRING`; `config/base.rs`)",
        &["~/.config/goose/secrets.yaml"],
    )],
    runs_later: &[],
};

/// The CLI is `goose`; the desktop app runs its agent as `goosed`.
pub(super) const PROCESS: ProcessSpec = ProcessSpec {
    names: &["goose", "goosed"],
    package_dirs: &[],
    helper: None,
};
