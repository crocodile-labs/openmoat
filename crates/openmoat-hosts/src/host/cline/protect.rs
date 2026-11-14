//! Cline's files the default policy and the taint list protect, and its
//! processes.

use crate::contract::{Paths, ProcessSpec, Protect, RunsLater};

pub(super) const PROTECT: Protect = Protect {
    self_paths: &[Paths::new(
        "Cline: its configuration directory, the hooks directories it runs every\n\
         file of (OpenMoat's `PreToolUse` among them) and its plugins, which run in\n\
         its own process (`CLINE_DIR` moves `~/.cline`)",
        &[
            "~/.cline",
            "~/.cline/hooks",
            "~/.cline/hooks/**",
            "~/.cline/plugins",
            "~/.cline/plugins/**",
            "~/Documents/Cline/Hooks",
            "~/Documents/Cline/Hooks/**",
        ],
    )],
    taint: &[Paths::new(
        "Cline: its directory (settings, MCP servers, hooks, plugins), the\n\
         rules, workflows and hooks in `Documents/Cline`, and a project's `.cline`\n\
         and `.clinerules` (hooks, plugins, rules)",
        &[
            "**/.cline",
            "**/.cline/**",
            "**/Documents/Cline/**",
            "**/.clinerules",
            "**/.clinerules/**",
        ],
    )],
    temp_dirs: &[],
    credentials: &[Paths::new(
        "Cline: the provider keys the CLI stores and its connectors' credentials\n\
         (`resolveProviderSettingsPath`, `resolveConnectorsDbPath` in\n\
         `sdk/packages/shared/src/storage/paths.ts`)",
        &[
            "~/.cline/data/settings/providers.json",
            "~/.cline/data/db/connectors.db",
        ],
    )],
    runs_later: &[
        RunsLater::agent_config(
            "Cline: a workspace's hooks, every file of which it runs on each tool call",
            &["**/.clinerules/hooks/**", "**/.cline/hooks/**"],
        ),
        RunsLater::review(
            "Cline: the folders above them (a rename away and back edits them); its rules\n\
             files in `.clinerules/` stay ordinary project writes",
            &[
                "**/.clinerules",
                "**/.clinerules/hooks",
                "**/.cline",
                "**/.cline/hooks",
            ],
        ),
    ],
};

/// The CLI is the `cline` bin of the npm package `cline`, a Node wrapper that
/// waits on the compiled binary it starts: the copy `postinstall` caches as
/// `bin/.cline`, or `bin/cline` of the `@cline/cli-<platform>` package.
pub(super) const PROCESS: ProcessSpec = ProcessSpec {
    names: &["cline"],
    package_dirs: &[&["node_modules", "cline", "bin"]],
    helper: None,
};
