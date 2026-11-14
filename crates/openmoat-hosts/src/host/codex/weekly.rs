//! Codex in CI's weekly latest-release check
//! (`scripts/ci/latest-agents/hosts/codex.sh`).

use crate::contract::{
    Checked, ConfigFormat, Proves, Weekly, WeeklyInstall, WeeklyPayload, WeeklyRun, WeeklyRuns,
};

/// The version is the one the differential suite pins
/// (`scripts/ci/host-binaries.sh`). Codex keeps its SQLite state where
/// `CODEX_SQLITE_HOME` says, apart from its home.
pub(super) const WEEKLY: Weekly = Weekly {
    runs: WeeklyRuns::Runs(&[WeeklyRun {
        agent: "codex",
        install: WeeklyInstall::Npm {
            package: "@openai/codex",
            binary: "node_modules/.bin/codex",
        },
        checked: Checked {
            version: Some("0.160.1"),
            source: "scripts/ci/host-binaries.sh",
            note: None,
        },
        config: &[("{CODEX_HOME}/hooks.json", ConfigFormat::Json)],
        payload: Some(WeeklyPayload {
            fixture: "codex/fixtures/pretooluse-shell.json",
            command: "/tool_input/command",
            verdict: "/hookSpecificOutput/permissionDecision",
            allow_is_silent: true,
        }),
        proves: &[Proves::Hook, Proves::HookFailure],
        ..WeeklyRun::BASE
    }]),
    env: &[("CODEX_SQLITE_HOME", "{HOME}/.codex")],
};
