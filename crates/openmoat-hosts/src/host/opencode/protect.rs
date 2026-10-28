//! OpenCode's files the default policy and the taint list protect, and its
//! processes.

use crate::contract::{Paths, ProcessSpec, Protect};

pub(super) const PROTECT: Protect = Protect {
    self_paths: &[
        Paths::new(
            "OpenCode: its configuration directory, OpenMoat's plugin and the plugin\n\
             folders around it, the configuration files whose `plugin` list loads\n\
             plugins and whose `-openmoat` removes OpenMoat's (`config` is the old TOML\n\
             one OpenCode moves into `config.json`), and OpenCode 2's background service\n\
             settings, whose `env` it starts with; other plugins ask (`runs-later`)",
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
