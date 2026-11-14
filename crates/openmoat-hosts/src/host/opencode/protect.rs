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
    temp_dirs: &[],
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
            "OpenCode: a project's plugins, tools, commands, agents and skills (loaded at\n\
             start, with no prompt), and its configuration, which adds plugins, MCP\n\
             servers and permission rules (a write that removes OpenMoat's plugin is\n\
             denied, `project-settings`)",
            &[
                "**/.opencode/plugins/**",
                "**/.opencode/plugin/**",
                "**/.opencode/tools/**",
                "**/.opencode/tool/**",
                "**/.opencode/commands/**",
                "**/.opencode/command/**",
                "**/.opencode/agents/**",
                "**/.opencode/agent/**",
                // the folder its skills docs name, searched from the working
                // directory up to the project root (opencode.ai/docs/skills)
                "**/.opencode/skills/**",
                "**/.opencode/opencode.json",
                "**/.opencode/opencode.jsonc",
                "**/opencode.json",
                "**/opencode.jsonc",
            ],
        ),
        // OpenCode itself writes `package.json` in each configuration folder
        // it uses, a project's `.opencode` included, when it installs its
        // plugin dependencies at start (the file is in OpenCode's own
        // `.opencode/.gitignore`), so `openmoat run -- opencode` must leave it
        // writable: review only.
        RunsLater::review(
            "OpenCode: a project's package file, which OpenCode writes itself when it\n\
             installs plugin dependencies at start, and the folders above a project's\n\
             plugins (a rename away and back edits them)",
            &[
                "**/.opencode/package.json",
                "**/.opencode",
                "**/.opencode/plugins",
                "**/.opencode/plugin",
            ],
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
