//! Antigravity CLI's files the default policy and the taint list protect, and
//! its processes.

use crate::contract::{Paths, ProcessSpec, Protect};

pub(super) const PROTECT: Protect = Protect {
    self_paths: &[Paths::new(
        "Antigravity CLI: the hook file that holds OpenMoat's hook (shared with the\n\
         Antigravity app and IDE), its settings (`permissions`, `toolPermission`,\n\
         `trustedWorkspaces`, `enableTerminalSandbox`), a project's hook and MCP\n\
         files, which load from the repository, and the plugins that can add hooks",
        &[
            "~/.gemini/config",
            "~/.gemini/config/hooks.json",
            "~/.gemini/config/mcp_config.json",
            "~/.gemini/config/plugins",
            "~/.gemini/config/plugins/**",
            "~/.gemini/antigravity-cli",
            "~/.gemini/antigravity-cli/settings.json",
            "**/.agents/hooks.json",
            "**/.agents/mcp_config.json",
        ],
    )],
    taint: &[Paths::new(
        "Antigravity CLI: its hook and MCP files, and the plugins it loads",
        &[
            "~/.gemini/config",
            "~/.gemini/config/**",
            "**/.agents/hooks.json",
            "**/.agents/mcp_config.json",
        ],
    )],
    temp_dirs: &[],
    credentials: &[Paths::new(
        "Antigravity CLI: the MCP OAuth tokens (`/docs/mcp`). The account's\n\
         sign-in is in the OS keyring (`/docs/install`), not a file",
        &["~/.gemini/antigravity/mcp_oauth_tokens.json"],
    )],
    runs_later: &[],
};

pub(super) const PROCESS: ProcessSpec = ProcessSpec {
    names: &["agy"],
    package_dirs: &[],
    helper: None,
};
