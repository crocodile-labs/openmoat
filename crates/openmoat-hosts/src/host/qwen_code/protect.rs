//! Qwen Code's files the default policy and the taint list protect, its
//! system settings and its processes.

use crate::contract::{Paths, Platform, ProcessSpec, Protect, RunsLater, SystemFile};

pub(super) const PROTECT: Protect = Protect {
    self_paths: &[Paths::new(
        "Qwen Code: its directory, the settings that hold OpenMoat's hook and a\n\
         project's, which are merged over them and can turn hooks off",
        &[
            "~/.qwen",
            "**/.qwen",
            "~/.qwen/settings.json",
            "**/.qwen/settings.json",
        ],
    )],
    taint: &[Paths::new(
        "Qwen Code: its settings, extensions and the memory file it loads into\n\
         every session",
        &["**/QWEN.md", "**/.qwen", "**/.qwen/**"],
    )],
    temp_dirs: &[],
    // Qwen Code's OAuth sign-in, in the file Gemini CLI, which Qwen Code was
    // forked from, keeps it in (`oauth_creds.json`); not verified.
    credentials: &[Paths::new(
        "Qwen Code: its Qwen OAuth sign-in (the file name Gemini CLI uses, not\n\
         verified)",
        &["~/.qwen/oauth_creds.json"],
    )],
    runs_later: &[
        RunsLater::agent_config(
            "Qwen Code: a project's settings, whose hooks and MCP servers it runs once\n\
             approved, and its other configuration (commands, agents, skills)",
            &["**/.qwen/**"],
        ),
        RunsLater::review(
            "Qwen Code: the person's extensions, whose hooks and MCP servers it starts",
            &["~/.qwen/extensions/**"],
        ),
    ],
};

pub(super) const PROCESS: ProcessSpec = ProcessSpec {
    names: &["qwen"],
    package_dirs: &[&["@qwen-code", "qwen-code"]],
    helper: None,
};

/// System settings and system defaults (the settings reference, "Settings
/// files"), each moved by its variable.
pub(super) const SYSTEM_FILES: &[SystemFile] = &[
    SystemFile::at(
        "/Library/Application Support/QwenCode/settings.json",
        &[Platform::MacOs],
    )
    .moved_by("QWEN_CODE_SYSTEM_SETTINGS_PATH"),
    SystemFile::at(
        "/Library/Application Support/QwenCode/system-defaults.json",
        &[Platform::MacOs],
    )
    .moved_by("QWEN_CODE_SYSTEM_DEFAULTS_PATH"),
    SystemFile::at(
        "/etc/qwen-code/settings.json",
        &[Platform::Linux, Platform::Wsl],
    )
    .moved_by("QWEN_CODE_SYSTEM_SETTINGS_PATH"),
    SystemFile::at(
        "/etc/qwen-code/system-defaults.json",
        &[Platform::Linux, Platform::Wsl],
    )
    .moved_by("QWEN_CODE_SYSTEM_DEFAULTS_PATH"),
    SystemFile::at(
        "C:/ProgramData/qwen-code/settings.json",
        &[Platform::Windows],
    )
    .moved_by("QWEN_CODE_SYSTEM_SETTINGS_PATH"),
    SystemFile::at(
        "C:/ProgramData/qwen-code/system-defaults.json",
        &[Platform::Windows],
    )
    .moved_by("QWEN_CODE_SYSTEM_DEFAULTS_PATH"),
];
