//! Crush's files the default policy and the taint list protect, and its
//! processes. Every name is from `lookupConfigs` and `GlobalConfigData` in
//! `internal/config/load.go`.

use crate::contract::{Paths, Platform, ProcessSpec, Protect, RunsLater, SystemFile};

pub(super) const PROTECT: Protect = Protect {
    self_paths: &[Paths::new(
        "Crush: its global configuration, which holds OpenMoat's hook, the `crushrc`\n\
         beside it, a Bash script it runs at start, and the data directory's\n\
         `crush.json`, merged with them",
        &[
            "~/.config/crush",
            "~/.config/crush/crush.json",
            "~/.config/crush/crushrc",
            "~/.local/share/crush/crush.json",
        ],
    )],
    taint: &[Paths::new(
        "Crush: a project's configuration files, which add hooks and MCP servers, and\n\
         its `crushrc` scripts; and its global configuration and data file, which\n\
         `kernel-self` denies writing",
        &[
            "**/.config/crush",
            "**/.config/crush/**",
            "**/.local/share/crush/crush.json",
            "**/crush.json",
            "**/.crush.json",
            "**/crushrc",
            "**/.crushrc",
            "**/.crush/**",
        ],
    )],
    temp_dirs: &[],
    // Any `crush.json` may hold a provider's `api_key` (`ProviderConfig` in
    // `internal/config/config.go`); the data directory's is the one Crush
    // writes itself.
    credentials: &[Paths::new(
        "Crush: the data directory's `crush.json`, which can hold providers' API keys",
        &["~/.local/share/crush/crush.json"],
    )],
    runs_later: &[RunsLater::agent_config(
        "Crush: a project's configuration, whose hooks and MCP servers it runs when it\n\
         starts, and its `crushrc` scripts, which it runs as Bash with no prompt",
        &[
            "**/crush.json",
            "**/.crush.json",
            "**/crushrc",
            "**/.crushrc",
            "**/.crush/**",
        ],
    )],
};

pub(super) const PROCESS: ProcessSpec = ProcessSpec {
    names: &["crush"],
    package_dirs: &[&["@charmland", "crush"]],
    helper: None,
};

/// The system configuration Crush loads first (`config_unix.go`).
pub(super) const SYSTEM_FILES: &[SystemFile] = &[SystemFile::at(
    "/etc/crush/crush.json",
    &[Platform::MacOs, Platform::Linux, Platform::Wsl],
)];
