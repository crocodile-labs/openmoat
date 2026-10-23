//! GitHub Copilot CLI's files the default policy and the taint list protect,
//! and its processes.

use crate::contract::{Paths, ProcessSpec, Protect};

pub(super) const PROTECT: Protect = Protect {
    self_paths: &[Paths::new(
        "GitHub Copilot CLI: its configuration directory, the hooks directory whose\n\
         every file it loads (OpenMoat's included), and the user and repository\n\
         settings whose `disableAllHooks` turns them all off; its session folders\n\
         stay writable",
        &[
            "~/.copilot",
            "~/.copilot/hooks",
            "~/.copilot/hooks/**",
            "~/.copilot/settings.json",
            "~/.copilot/config.json",
            "**/.copilot",
            "**/.copilot/hooks",
            "**/.copilot/hooks/**",
            "**/.copilot/settings.json",
            "**/.copilot/config.json",
            "**/.github/copilot/settings.json",
            "**/.github/copilot/settings.local.json",
        ],
    )],
    taint: &[Paths::new(
        "GitHub Copilot CLI: its hooks, settings, MCP servers, plugins and custom\n\
         agents, not its session folders; a repository's hooks, settings and\n\
         instructions",
        &[
            "**/.copilot",
            "**/.copilot/hooks",
            "**/.copilot/hooks/**",
            "**/.copilot/settings.json",
            "**/.copilot/config.json",
            "**/.copilot/mcp-config.json",
            "**/.copilot/installed-plugins/**",
            "**/.copilot/agents/**",
            "**/.github/hooks/**",
            "**/.github/mcp.json",
            "**/.github/agents/**",
            "**/.github/copilot/**",
            "**/.github/copilot-instructions.md",
        ],
    )],
};

pub(super) const PROCESS: ProcessSpec = ProcessSpec {
    names: &["copilot"],
    package_dirs: &[&["@github", "copilot"]],
    helper: None,
};
