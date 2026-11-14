//! A project's Cline hook directories add hooks beside OpenMoat's; none turns
//! it off (ADR-095).

use crate::contract::{HookOff, Managed, ProjectOff};

pub(super) const HOOK_OFF: HookOff = HookOff {
    project: ProjectOff::Nothing {
        why: "a project's `.clinerules/hooks` and `.cline/hooks` add hooks beside OpenMoat's \
              (`openmoat status` names them); none turns OpenMoat's off",
        source: "https://docs.cline.bot/getting-started/config.md",
    },
    session_override: None,
    managed: Managed::None {
        why: "Cline's enterprise controls cover MCP servers, not hooks",
        source: "https://docs.cline.bot/enterprise-solutions/configuration/infrastructure-configuration/control-other-cline-features/mcp-server-controls.md",
    },
};
