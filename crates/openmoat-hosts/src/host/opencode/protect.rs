//! OpenCode's files the default policy and the taint list protect, and its
//! processes.

use crate::contract::{Paths, ProcessSpec, Protect, RunsLater};

pub(super) const PROTECT: Protect = Protect {
    self_paths: &[
        Paths::new(
            "OpenCode: its configuration directory, OpenMoat's plugin and the plugin\n\
             folders around it, the configuration files whose `plugin` list loads\n\
             plugins and whose `-openmoat` removes OpenMoat's (`config` is the old TOML\n\
             one OpenCode moves into `config.json`), and OpenCode 2's background service\n\
             settings, whose `env` it starts with; other plugins need review (`runs-later`)",
            &[
                "~/.config/opencode",
                "~/.config/opencode/plugins",
                "~/.config/opencode/plugins/openmoat.js",
                "~/.config/opencode/plugin",
                "~/.config/opencode/config.json",
                "~/.config/opencode/opencode.json",
                "~/.config/opencode/opencode.jsonc",
                "~/.config/opencode/config",
                // every release channel's file by name, which Claude Code's
                // Linux sandbox keeps (it drops globs); other channels' files
                // (`service-<channel>.json`) by the glob
                "~/.config/opencode/service.json",
                "~/.config/opencode/service*.json",
            ],
        ),
        Paths::new(
            "OpenCode also reads `~/.opencode` as a configuration directory, with its\n\
             own plugin folders and configuration files",
            &[
                "~/.opencode",
                "~/.opencode/plugins",
                "~/.opencode/plugin",
                "~/.opencode/opencode.json",
                "~/.opencode/opencode.jsonc",
            ],
        ),
    ],
    taint: &[Paths::new(
        "OpenCode: its configuration directory, a project's `.opencode` and\n\
         `opencode.json[c]` (plugins, custom tools, commands, MCP servers, permission\n\
         rules) and the npm plugins it caches",
        &[
            "**/.config/opencode",
            "**/.config/opencode/**",
            "**/.opencode",
            "**/.opencode/**",
            "**/opencode.json",
            "**/opencode.jsonc",
            "**/.cache/opencode/node_modules/**",
        ],
    )],
    credentials: &[Paths::new(
        "OpenCode: its provider keys and OAuth tokens, its MCP sign-ins and the\n\
         database holding its account tokens, in its data directory on every OS\n\
         (`packages/opencode/src/auth/index.ts`, `mcp/auth.ts`,\n\
         `core/src/database/database.ts`; `XDG_DATA_HOME` moving it is not followed)",
        &[
            "~/.local/share/opencode/auth.json",
            "~/.local/share/opencode/mcp-auth.json",
            "~/.local/share/opencode/opencode*.db*",
        ],
    )],
    runs_later: &[
        RunsLater::review(
            "OpenCode: the person's plugins and custom tools, which it loads into its own\n\
             process with the agent's rights; commands, whose `` !`…` `` shell runs when\n\
             the person types the command; and the package files and caches it loads\n\
             plugin code from",
            &[
                "~/.config/opencode/plugins/**",
                "~/.config/opencode/plugin/**",
                "~/.config/opencode/tools/**",
                "~/.config/opencode/tool/**",
                "~/.config/opencode/commands/**",
                "~/.config/opencode/command/**",
                "~/.config/opencode/package.json",
                "~/.config/opencode/node_modules/**",
                "~/.cache/opencode/node_modules/**",
            ],
        ),
        RunsLater::agent_config(
            "OpenCode: a project's plugins, tools and commands (loaded at start, with no\n\
             prompt), its configuration, which adds plugins, MCP servers and permission\n\
             rules (a write that removes OpenMoat's plugin is denied, `project-settings`),\n\
             and its package file",
            &[
                "**/.opencode/plugins/**",
                "**/.opencode/plugin/**",
                "**/.opencode/tools/**",
                "**/.opencode/tool/**",
                "**/.opencode/commands/**",
                "**/.opencode/command/**",
                "**/.opencode/opencode.json",
                "**/.opencode/opencode.jsonc",
                "**/.opencode/package.json",
                "**/opencode.json",
                "**/opencode.jsonc",
            ],
        ),
        RunsLater::review(
            "OpenCode: the folders above a project's plugins (a rename away and back edits\n\
             them)",
            &["**/.opencode", "**/.opencode/plugins", "**/.opencode/plugin"],
        ),
    ],
};

/// OpenCode 1 runs as `opencode`: the compiled binary, or the npm package's
/// `bin/opencode` launcher under Node (`opencode-ai`). OpenCode 2 installs
/// `opencode` and `opencode2` (`@opencode/cli`), and runs plugins in its
/// background service, also an `opencode` process.
pub(super) const PROCESS: ProcessSpec = ProcessSpec {
    names: &["opencode", "opencode2"],
    package_dirs: &[&["opencode-ai"], &["@opencode", "cli"]],
    helper: None,
};
