//! Claude Code in CI's weekly latest-release check
//! (`scripts/ci/latest-agents/hosts/claude-code.sh`).

use crate::contract::{
    Checked, ConfigFormat, Proves, Weekly, WeeklyInstall, WeeklyPayload, WeeklyRun, WeeklyRuns,
};

/// The npm bin is a stub that only the postinstall replaces, so the platform
/// package's own binary is run. The version is the one the differential
/// suite pins (`scripts/ci/host-binaries.sh`).
pub(super) const WEEKLY: Weekly = Weekly {
    runs: WeeklyRuns::Runs(&[WeeklyRun {
        agent: "claude-code",
        install: WeeklyInstall::Npm {
            package: "@anthropic-ai/claude-code",
            binary: "node_modules/@anthropic-ai/claude-code-{platform}/claude",
        },
        checked: Checked {
            version: Some("2.1.290"),
            source: "scripts/ci/host-binaries.sh",
            note: None,
        },
        config: &[("{CLAUDE_CONFIG_DIR}/settings.json", ConfigFormat::Json)],
        payload: Some(WeeklyPayload {
            fixture: "claude_code/fixtures/bash.json",
            command: "/tool_input/command",
            verdict: "/hookSpecificOutput/permissionDecision",
            allow_is_silent: false,
        }),
        proves: &[Proves::Hook, Proves::HookFailure, Proves::Mcp],
        ..WeeklyRun::BASE
    }]),
    env: &[],
};
