//! pi's files the default policy and the taint list protect, and its
//! processes.

use crate::contract::{Paths, ProcessSpec, Protect};

pub(super) const PROTECT: Protect = Protect {
    self_paths: &[Paths::new(
        "pi: the agent directory, OpenMoat's extension in it, the settings that\n\
         can turn the extension off and the trust decisions that load a project's\n\
         own extensions; other extensions ask (`runs-later`)",
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
};

/// pi runs as `node <…>/pi-coding-agent/dist/bundle/cli.js` (its package
/// `bin`).
pub(super) const PROCESS: ProcessSpec = ProcessSpec {
    names: &["pi"],
    package_dirs: &[&["pi-coding-agent"]],
    helper: None,
};
