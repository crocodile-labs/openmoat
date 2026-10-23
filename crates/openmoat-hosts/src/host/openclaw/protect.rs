//! OpenClaw's files the default policy and the taint list protect, and its
//! processes.

use crate::contract::{Paths, ProcessSpec, Protect};

pub(super) const PROTECT: Protect = Protect {
    self_paths: &[
        Paths::new(
            "OpenClaw: the state directory, its configuration (which loads OpenMoat's\n\
             plugin) and the plugin `moat init` writes; its workspace inside stays\n\
             writable, and its `.env` is `secrets-paths`' (`**/.env`)",
            &[
                "~/.openclaw",
                "~/.openclaw/openclaw.json",
                "~/.openclaw/openmoat",
                "~/.openclaw/openmoat/**",
            ],
        ),
        Paths::new(
            "OpenClaw's control-plane database: its exec approvals, plugin state and the\n\
             cron jobs its Gateway runs (an OpenClaw `cron` add or update is decided as a\n\
             write of it), so an agent cannot approve its own commands there",
            &["~/.openclaw/state/**"],
        ),
    ],
    taint: &[
        Paths::new(
            "OpenClaw: its configuration, OpenMoat's plugin and the plugin directories the\n\
             Gateway loads; not the whole state directory, whose workspace is ordinary work",
            &[
                "**/.openclaw",
                "**/.openclaw/openclaw.json",
                "**/.openclaw/openmoat",
                "**/.openclaw/openmoat/**",
                "**/.openclaw/extensions/**",
            ],
        ),
        Paths::new(
            "the database where the Gateway keeps cron jobs and exec approvals",
            &["**/.openclaw/state/**"],
        ),
    ],
};

/// OpenClaw's command is `openclaw.mjs` (its package `bin`); `openclaw/dist`
/// covers a Gateway started from the package's built files.
pub(super) const PROCESS: ProcessSpec = ProcessSpec {
    names: &["openclaw"],
    package_dirs: &[&["openclaw", "dist"]],
    helper: None,
};
