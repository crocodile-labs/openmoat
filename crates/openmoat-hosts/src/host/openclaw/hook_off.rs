//! OpenClaw loads OpenMoat's plugin from the Gateway's own configuration; a
//! project holds nothing that turns it off (ADR-095).

use crate::contract::{HookOff, Managed, ProjectOff};

const SOURCE: &str = "https://docs.openclaw.ai/plugins";

pub(super) const HOOK_OFF: HookOff = HookOff {
    project: ProjectOff::Nothing {
        why: "plugins load from the Gateway's `openclaw.json` and its `plugins.load.paths`, never \
              from a project the agent works in",
        source: SOURCE,
    },
    session_override: None,
    managed: Managed::None {
        why: "OpenClaw documents no administrator location for plugins",
        source: SOURCE,
    },
};
