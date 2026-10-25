//! OpenCode's files the default policy and the taint list protect, and its
//! processes.

use crate::contract::{Paths, ProcessSpec, Protect};

pub(super) const PROTECT: Protect = Protect {
    self_paths: &[
        Paths::new(
            "OpenCode: its configuration directory, OpenMoat's plugin and the plugin\n\
             folders around it, and the configuration files whose `plugin` list loads\n\
             plugins before it (`config` is the old TOML one OpenCode moves into\n\
             `config.json`); other plugins ask (`runs-later`)",
            &[
                "~/.config/opencode",
                "~/.config/opencode/plugins",
                "~/.config/opencode/plugins/openmoat.js",
                "~/.config/opencode/plugin",
                "~/.config/opencode/config.json",
                "~/.config/opencode/opencode.json",
                "~/.config/opencode/opencode.jsonc",
                "~/.config/opencode/config",
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
};

/// OpenCode 1 runs as `opencode`: the compiled binary, or the npm package's
/// `bin/opencode` launcher under Node (`opencode-ai`). OpenCode 2 installs
/// `opencode` and `opencode2` (`@opencode/cli`); OpenMoat's hook does not run
/// there, but a person-only command started from it is still refused.
pub(super) const PROCESS: ProcessSpec = ProcessSpec {
    names: &["opencode", "opencode2"],
    package_dirs: &[&["opencode-ai"], &["@opencode", "cli"]],
    helper: None,
};
