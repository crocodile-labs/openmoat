//! pi's files the default policy and the taint list protect, and its
//! processes.

use crate::contract::{Paths, ProcessSpec, Protect, RunsLater};

pub(super) const PROTECT: Protect = Protect {
    self_paths: &[Paths::new(
        "pi: the agent directory, OpenMoat's extension in it, the settings that\n\
         can turn the extension off and the trust decisions that load a project's\n\
         own extensions; other extensions need review (`runs-later`)",
        &[
            "~/.pi",
            "~/.pi/agent",
            "~/.pi/agent/extensions",
            "~/.pi/agent/extensions/openmoat.js",
            "~/.pi/agent/settings.json",
            "~/.pi/agent/trust.json",
        ],
    )],
    taint: &[Paths::new(
        "pi: its agent directory (extensions, settings, trust decisions) and a\n\
         project's `.pi` (extensions, settings, MCP servers, system prompt)",
        &["**/.pi", "**/.pi/**"],
    )],
    credentials: &[Paths::new(
        "pi: its provider keys and OAuth tokens, the API keys `models.json` may\n\
         hold and its MCP sign-ins (`packages/coding-agent/src/config.ts`,\n\
         `docs/models.md`, `src/extensions/mcp/oauth.ts`)",
        &[
            "~/.pi/agent/auth.json",
            "~/.pi/agent/models.json",
            "~/.pi/agent/mcp-auth.json",
        ],
    )],
    runs_later: &[
        RunsLater::agent_config(
            "pi: a project's extensions, which pi loads and runs with the agent's rights,\n\
             its MCP servers, and its settings, which can add packages and turn extensions\n\
             off (a write that removes OpenMoat's extension is denied, `project-settings`)",
            &[
                "**/.pi/extensions/**",
                "**/.pi/mcp.json",
                "**/.pi/settings.json",
            ],
        ),
        RunsLater::review(
            "pi: the person's extensions and MCP servers, and the folders above a\n\
             project's (a rename away and back edits them)",
            &[
                "~/.pi/agent/extensions/**",
                "~/.pi/agent/mcp.json",
                "**/.pi",
                "**/.pi/extensions",
            ],
        ),
    ],
};

/// pi runs as `node <…>/pi-coding-agent/dist/bundle/cli.js` (its package
/// `bin`).
pub(super) const PROCESS: ProcessSpec = ProcessSpec {
    names: &["pi"],
    package_dirs: &[&["pi-coding-agent"]],
    helper: None,
};
