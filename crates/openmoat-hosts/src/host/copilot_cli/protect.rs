//! GitHub Copilot CLI's files the default policy and the taint list protect,
//! and its processes.

use crate::contract::{Paths, ProcessSpec, Protect, RunsLater};

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
    credentials: &[Paths::new(
        "GitHub Copilot CLI: `config.json`, where its login goes when there is no\n\
         keychain, and the fallback stores of MCP sign-ins and MCP secrets\n\
         (docs: Authenticate Copilot CLI, config-dir reference)",
        &[
            "~/.copilot/config.json",
            "~/.copilot/mcp-oauth-config/**",
            "~/.copilot/mcp-secrets/**",
        ],
    )],
    runs_later: &[
        RunsLater::agent_config(
            "GitHub Copilot CLI: a repository's hook files, MCP servers and custom agents\n\
             (whose frontmatter may carry hooks)",
            &[
                "**/.github/hooks/**",
                "**/.github/mcp.json",
                "**/.github/agents/**",
            ],
        ),
        RunsLater::review(
            "GitHub Copilot CLI: the person's MCP servers, plugins and custom agents, and\n\
             the folder above a repository's hooks (a rename away and back edits them)",
            &[
                "~/.copilot/mcp-config.json",
                "~/.copilot/installed-plugins/**",
                "~/.copilot/agents/**",
                "**/.github/hooks",
            ],
        ),
    ],
};

pub(super) const PROCESS: ProcessSpec = ProcessSpec {
    names: &["copilot"],
    package_dirs: &[&["@github", "copilot"]],
    helper: None,
};
